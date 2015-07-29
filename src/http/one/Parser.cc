/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "http/one/Parser.h"
#include "http/one/Tokenizer.h"
#include "mime_header.h"
#include "SquidConfig.h"

/// RFC 7230 section 2.6 - 7 magic octets
const SBuf Http::One::Parser::Http1magic("HTTP/1.");

void
Http::One::Parser::clear()
{
    parsingStage_ = HTTP_PARSE_NONE;
    buf_ = NULL;
    msgProtocol_ = AnyP::ProtocolVersion();
    mimeHeaderBlock_.clear();
}

bool
Http::One::Parser::skipLineTerminator(Http1::Tokenizer &tok) const
{
    static const SBuf crlf("\r\n");
    if (tok.skip(crlf))
        return true;

    if (Config.onoff.relaxed_header_parser && tok.skipOne(CharacterSet::LF))
        return true;

    return false;
}

bool
Http::One::Parser::grabMimeBlock(const char *which, const size_t limit)
{
    // MIME headers block exist in (only) HTTP/1.x and ICY
    const bool expectMime = (msgProtocol_.protocol == AnyP::PROTO_HTTP && msgProtocol_.major == 1) ||
                            msgProtocol_.protocol == AnyP::PROTO_ICY ||
                            hackExpectsMime_;

    if (expectMime) {
        /* NOTE: HTTP/0.9 messages do not have a mime header block.
         *       So the rest of the code will need to deal with '0'-byte headers
         *       (ie, none, so don't try parsing em)
         */
        // XXX: c_str() reallocates. performance regression.
        if (SBuf::size_type mimeHeaderBytes = headersEnd(buf_.c_str(), buf_.length())) {

            // Squid could handle these headers, but admin does not want to
            if (firstLineSize() + mimeHeaderBytes >= limit) {
                debugs(33, 5, "Too large " << which);
                parseStatusCode = Http::scHeaderTooLarge;
                buf_.consume(mimeHeaderBytes);
                parsingStage_ = HTTP_PARSE_DONE;
                return false;
            }

            mimeHeaderBlock_ = buf_.consume(mimeHeaderBytes);
            debugs(74, 5, "mime header (0-" << mimeHeaderBytes << ") {" << mimeHeaderBlock_ << "}");

        } else { // headersEnd() == 0
            if (buf_.length()+firstLineSize() >= limit) {
                debugs(33, 5, "Too large " << which);
                parseStatusCode = Http::scHeaderTooLarge;
                parsingStage_ = HTTP_PARSE_DONE;
            } else
                debugs(33, 5, "Incomplete " << which << ", waiting for end of headers");
            return false;
        }

    } else
        debugs(33, 3, "Missing HTTP/1.x identifier");

    // NP: we do not do any further stages here yet so go straight to DONE
    parsingStage_ = HTTP_PARSE_DONE;

    return true;
}

// arbitrary maximum-length for headers which can be found by Http1Parser::getHeaderField()
#define GET_HDR_SZ  1024

// BUG: returns only the first header line with given name,
//      ignores multi-line headers and obs-fold headers
char *
Http::One::Parser::getHeaderField(const char *name)
{
    if (!headerBlockSize() || !name)
        return NULL;

    LOCAL_ARRAY(char, header, GET_HDR_SZ);
    const int namelen = strlen(name);

    debugs(25, 5, "looking for " << name);

    // while we can find more LF in the SBuf
    static CharacterSet iso8859Line = CharacterSet("non-LF",'\0','\n'-1) + CharacterSet(NULL, '\n'+1, (unsigned char)0xFF);
    Http1::Tokenizer tok(mimeHeaderBlock_);
    SBuf p;
    static const SBuf crlf("\r\n");

    while (tok.prefix(p, iso8859Line)) {
        if (!tok.skipOne(CharacterSet::LF)) // move tokenizer past the LF
            break; // error. reached invalid octet or end of buffer insted of an LF ??

        // header lines must start with the name (case insensitive)
        if (p.substr(0, namelen).caseCmp(name, namelen))
            continue;

        // then a COLON
        if (p[namelen] != ':')
            continue;

        // drop any trailing *CR sequence
        p.trim(crlf, false, true);

        debugs(25, 5, "checking " << p);
        p.consume(namelen + 1);

        // TODO: optimize SBuf::trim to take CharacterSet directly
        Http1::Tokenizer t(p);
        t.skipAll(CharacterSet::WSP);
        p = t.remaining();

        // prevent buffer overrun on char header[];
        p.chop(0, sizeof(header)-1);

        // return the header field-value
        SBufToCstring(header, p);
        debugs(25, 5, "returning " << header);
        return header;
    }

    return NULL;
}

