/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "http/ProtocolVersion.h"
#include "http/two/forward.h"
#include "http/two/Frame.h"
#include "http/two/FrameParser.h"
#include "http/two/FrameType.h"
#include "http/two/HpackHuffmanDecoder.h"
#include "parser/BinaryTokenizer.h"

void
Http::Two::FrameParser::clear()
{
    Http::Parser::clear();

    memset(fh_.data, 0, sizeof(fh_.data));
    payload_ = NULL;
}

void
Http::Two::FrameParser::resetFrame()
{
    // only do anything if parsing frames already
    if (parsingStage_ == HTTP_PARSE_FRAMES) {
        clear();
        parsingStage_ = HTTP_PARSE_FRAMES; // retain stage.
    }
}

/*
 * attempt to parse a frame (HTTP/2.0) from the buffer
 * \retval true if a full message/frame was found and parsed
 * \retval false if incomplete, invalid or no message/frame was found
 * set to stage DONE if error found (caller should abort connection on DONE)
 */
bool
Http::Two::FrameParser::parse(const SBuf &aBuf)
{
    buf_ = aBuf;

    // stage 0: detect magic prefix
    // abort (DONE) if not present at start of connection parsing.
    if (parsingStage_ == HTTP_PARSE_NONE) {
        if (!parseHttp2magicPrefix(aBuf)) { // sets HTTP_PARSE_DONE on success
            if (!incompleteHttp2magicPrefix()) // not HTTP/2.0
                parsingStage_ = HTTP_PARSE_DONE;
            // else needs more data
            return false;
        }
        // magic found
        debugs(11,2, "HTTP/2.0 client magic prefix");
        msgProtocol_ = Http::ProtocolVersion(2,0);
        parsingStage_ = HTTP_PARSE_FRAMES;
    }

    // stage 1: parse a frame from the buffer
    if (parsingStage_ == HTTP_PARSE_FRAMES) {

        // identify frame header
        if (buf_.length() < firstLineSize()) {
            debugs(33, 8, "need " << (firstLineSize() - buf_.length()) << " more byte for next frame");
            buf_.reserveSpace(firstLineSize() - buf_.length());
            return false; // need more bytes
        }

        // map the buffer octets to a FrameHeader object
        memcpy(fh_.data, buf_.rawContent(), sizeof(fh_.data));

        // check frame is all present
        const size_t frameTotalOctets = firstLineSize() + fh_.length();
        if (buf_.length() < frameTotalOctets) {
            debugs(33, 8, "need " << (frameTotalOctets - buf_.length()) << " more byte for next frame");
            buf_.reserveSpace(frameTotalOctets - buf_.length());
            return false; // need more bytes
        }

        debugs(33, 4, "HTTP/2 frame length=" << fh_.length() <<
                      ", type=" << fh_.type() <<
                      ", flags=" << fh_.flags() << // TODO display as hex
                      ", stream-id=" << fh_.streamId());

        // copy the frame payload to our parser members
        payload_ = buf_.substr(firstLineSize(), fh_.length());
        buf_.consume(frameTotalOctets);

        // trim padding from payload_ (if any)
        const uint32_t sid = fh_.streamId();
        const bool frameMayPad = (sid == Http2::HEADERS || sid == Http2::DATA || sid == Http2::PUSH_PROMISE);
        if (frameMayPad && fh_.flags() == Http2::FLAG_PADDED) {
            const uint8_t padSz = static_cast<uint8_t>(payload_[0]);
            debugs(33, 4, "HTTP/2 frame padding=" << padSz << "+1");
            payload_ = payload_.substr(1, payload_.length() - 1 - padSz);
        }

        // trim PRIORITY details from HEADERS (if flagged) or PRIORITY payload_
        const bool frameMayPriority = (sid == Http2::HEADERS && fh_.flags() == Http2::FLAG_PRIORITY) ||
                                      sid == Http2::PRIORITY;
        if (frameMayPriority) {
            debugs(33, 4, "HTTP/2 frame priority=yes");
            priorities_ = payload_.substr(0,5);
            payload_.consume(5);
        }

        // XXX: detect and handle HEADERS that are incomplete properly.

        // decompress HEADERS payload_ into mimeHeaderBlock_
        if (!decompressPayload())
            return false; // need more data

        // TODO any other post-processing to interpret frames ?

        // do not HTTP_PARSE_DONE, in HTTP/2 that means finished with connection.
        return true;
    }

    // if we got here something has broken the parser, abort.
    parsingStage_ = HTTP_PARSE_DONE;
    return false;
}

int32_t
Http::Two::FrameParser::unpackInteger(::Parser::BinaryTokenizer &tok)
{
    // multi-octet integer value
    int32_t idx = 0;
    uint8_t octet;
    int multiplier = 0;
    do {
        octet = tok.uint8("HPACK Integer octet");
        idx += (octet & 0x7F) * (2^multiplier);
        multiplier += 7;
    } while((octet & 0x80));
    return idx;
}

SBuf
Http::Two::FrameParser::unpackString(::Parser::BinaryTokenizer &tok)
{
    static Http2::HpackHuffmanDecoder huff;

    uint8_t intro = tok.uint8("HPACK string type + length octet");
    bool huffman = (intro & 0x80);
    uint32_t idx = (intro & 0x7F);
    if (idx == 0x7F)
        idx += unpackInteger(tok);
    SBuf data(tok.area(idx, "HPACK string"));

    if (huffman && huff.decode(data))
        data = huff.output;

    return data;
}

/// Decompress the payload_ data from one frame.
/// The result gets stored into mimeHeaderBlock_ and returns true on success.
/// Errors result in parsingStage_ being set to HTTP_PARSE_DONE
bool
Http::Two::FrameParser::decompressPayload()
{
    // XXX this is almost HPACK decompressor logic in its entirety.
    // arrange things a bit better so that its more readable

    ::Parser::BinaryTokenizer tok(payload_);

    while (!tok.atEnd()) {
        bool doIndexing = false;
        const uint8_t intro = tok.uint8("h2 header entry prefix");

        if ((intro & 0x80)) { // first bit set
            // RFC 7541 section 6.1 - Indexed Header Field Representation
            // remainder of this byte and maybe following is an integer literal index into the HPACK lookup tables
            int32_t idx = (intro & 0x7F);
            if (idx == 0x7F)
                idx += unpackInteger(tok);

            if (idx == 0) { // error
                parsingStage_ = HTTP_PARSE_DONE;
                return false;
            }

            SBuf data(hpackDecodeTables_.lookup(idx));
            if (data.isEmpty()) { // error
                parsingStage_ = HTTP_PARSE_DONE;
                return false;
            }
            if (!mimeHeaderBlock_.isEmpty() && !data.isEmpty())
                mimeHeaderBlock_.append("\r\n",2);
            mimeHeaderBlock_.append(data);
            continue;
        }

        if ((intro & 0xE0) == 0x20) { // third bit set
            // RFC 7541 section 6.3 - Dynamic Table Size Update
            int32_t limit = (intro & 0x1F);
            if (limit == 0x1F)
                limit += unpackInteger(tok);

            // XXX: verify limit <= SETTINGS_HEADER_TABLE_SIZE. *MUST* be true, or emit error

            hpackDecodeTables_.changeCapacity(limit);
            continue;
        }

        // the encoding for header entry when bit-2, or bit-4, or no bits is set
        // is essentially the same logic, but with various different state to append
        int32_t idx = 0;

        if ((intro & 0xC0)) { // second bit set
            // RFC 7541 section 6.2.1 - Literal Header Field with Incremental Indexing
            idx = (intro & 0x3F);
            if (idx == 0x3F)
                idx += unpackInteger(tok);
            doIndexing = true;
        } else {
            // NP: since we are not yet re-encoding things for servers
            // the distinction of fourth bit being set or not does not matter
            // TODO: when we do re-encode we will have to store the headers in HttpMsg
            //  with that bits' stateful information somehow.

            // RFC 7541 section 6.2.2 - Literal Header Field without Indexing
            // RFC 7541 section 6.2.3 - Literal Header Field Never Indexed
            idx = (intro & 0x0F);
            if (idx == 0x0F)
                idx += unpackInteger(tok);
            doIndexing = false;
        }

        SBuf name;
        if (idx)
            name = hpackDecodeTables_.lookup(idx, true);
        else
            name = unpackString(tok);
        // value is always a literal string
        SBuf value(unpackString(tok));

        // add the found header line to the MiME block
        mimeHeaderBlock_.append(name);
        mimeHeaderBlock_.append(": ", 2);
        mimeHeaderBlock_.append(value);
        mimeHeaderBlock_.append("\r\n",2);

        // TODO: append result directly to HttpMsg headers, to avoid re-parsing Mime block.

        if (doIndexing) {
            // update dynamic table with this entry
            hpackDecodeTables_.add(name, value);
        }
    }

    return false;
}
