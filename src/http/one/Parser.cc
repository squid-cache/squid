/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "Debug.h"
#include "http/one/Parser.h"
#include "mime_header.h"
#include "parser/Tokenizer.h"
#include "SquidConfig.h"

/// RFC 7230 section 2.6 - 7 magic octets
const SBuf Http::One::Parser::Http1magic("HTTP/1.");

const SBuf &Http::One::CrLf()
{
    static const SBuf crlf("\r\n");
    return crlf;
}

void
Http::One::Parser::clear()
{
    parsingStage_ = HTTP_PARSE_NONE;
    buf_ = NULL;
    msgProtocol_ = AnyP::ProtocolVersion();
    mimeHeaderBlock_.clear();
}

/// characters HTTP permits tolerant parsers to accept as delimiters
static const CharacterSet &
RelaxedDelimiterCharacters()
{
    // RFC 7230 section 3.5
    // tolerant parser MAY accept any of SP, HTAB, VT (%x0B), FF (%x0C),
    // or bare CR as whitespace between request-line fields
    static const CharacterSet RelaxedDels =
        (CharacterSet::SP +
         CharacterSet::HTAB +
         CharacterSet("VT,FF","\x0B\x0C") +
         CharacterSet::CR).rename("relaxed-WSP");

    return RelaxedDels;
}

const CharacterSet &
Http::One::Parser::WhitespaceCharacters()
{
    return Config.onoff.relaxed_header_parser ?
           RelaxedDelimiterCharacters() : CharacterSet::WSP;
}

const CharacterSet &
Http::One::Parser::DelimiterCharacters()
{
    return Config.onoff.relaxed_header_parser ?
           RelaxedDelimiterCharacters() : CharacterSet::SP;
}

void
Http::One::Parser::skipLineTerminator(Tokenizer &tok) const
{
    if (tok.skip(Http1::CrLf()))
        return;

    if (Config.onoff.relaxed_header_parser && tok.skipOne(CharacterSet::LF))
        return;

    if (tok.atEnd() || (tok.remaining().length() == 1 && tok.remaining().at(0) == '\r'))
        throw InsufficientInput();

    throw TexcHere("garbage instead of CRLF line terminator");
}

/// all characters except the LF line terminator
static const CharacterSet &
LineCharacters()
{
    static const CharacterSet line = CharacterSet::LF.complement("non-LF");
    return line;
}

/**
 * Remove invalid lines (if any) from the mime prefix
 *
 * RFC 7230 section 3:
 * "A recipient that receives whitespace between the start-line and
 * the first header field MUST ... consume each whitespace-preceded
 * line without further processing of it."
 *
 * We need to always use the relaxed delimiters here to prevent
 * line smuggling through strict parsers.
 *
 * Note that 'whitespace' in RFC 7230 includes CR. So that means
 * sequences of CRLF will be pruned, but not sequences of bare-LF.
 */
void
Http::One::Parser::cleanMimePrefix()
{
    Tokenizer tok(mimeHeaderBlock_);
    while (tok.skipOne(RelaxedDelimiterCharacters())) {
        (void)tok.skipAll(LineCharacters()); // optional line content
        // LF terminator is required.
        // trust headersEnd() to ensure that we have at least one LF
        (void)tok.skipOne(CharacterSet::LF);
    }

    // If mimeHeaderBlock_ had just whitespace line(s) followed by CRLF,
    // then we skipped everything, including that terminating LF.
    // Restore the terminating CRLF if needed.
    if (tok.atEnd())
        mimeHeaderBlock_ = Http1::CrLf();
    else
        mimeHeaderBlock_ = tok.remaining();
    // now mimeHeaderBlock_ has 0+ fields followed by the LF terminator
}

/**
 * Replace obs-fold with a single SP,
 *
 * RFC 7230 section 3.2.4
 * "A server that receives an obs-fold in a request message that is not
 *  within a message/http container MUST ... replace
 *  each received obs-fold with one or more SP octets prior to
 *  interpreting the field value or forwarding the message downstream."
 *
 * "A proxy or gateway that receives an obs-fold in a response message
 *  that is not within a message/http container MUST ... replace each
 *  received obs-fold with one or more SP octets prior to interpreting
 *  the field value or forwarding the message downstream."
 */
void
Http::One::Parser::unfoldMime()
{
    Tokenizer tok(mimeHeaderBlock_);
    const auto szLimit = mimeHeaderBlock_.length();
    mimeHeaderBlock_.clear();
    // prevent the mime sender being able to make append() realloc/grow multiple times.
    mimeHeaderBlock_.reserveSpace(szLimit);

    static const CharacterSet nonCRLF = (CharacterSet::CR + CharacterSet::LF).complement().rename("non-CRLF");

    while (!tok.atEnd()) {
        const SBuf all(tok.remaining());
        const auto blobLen = tok.skipAll(nonCRLF); // may not be there
        const auto crLen = tok.skipAll(CharacterSet::CR); // may not be there
        const auto lfLen = tok.skipOne(CharacterSet::LF); // may not be there

        if (lfLen && tok.skipAll(CharacterSet::WSP)) { // obs-fold!
            mimeHeaderBlock_.append(all.substr(0, blobLen));
            mimeHeaderBlock_.append(' '); // replace one obs-fold with one SP
        } else
            mimeHeaderBlock_.append(all.substr(0, blobLen + crLen + lfLen));
    }
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
        bool containsObsFold;
        if (SBuf::size_type mimeHeaderBytes = headersEnd(buf_, containsObsFold)) {

            // Squid could handle these headers, but admin does not want to
            if (firstLineSize() + mimeHeaderBytes >= limit) {
                debugs(33, 5, "Too large " << which);
                parseStatusCode = Http::scHeaderTooLarge;
                buf_.consume(mimeHeaderBytes);
                parsingStage_ = HTTP_PARSE_DONE;
                return false;
            }

            mimeHeaderBlock_ = buf_.consume(mimeHeaderBytes);
            cleanMimePrefix();
            if (containsObsFold)
                unfoldMime();

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

// arbitrary maximum-length for headers which can be found by Http1Parser::getHostHeaderField()
#define GET_HDR_SZ  1024

// BUG: returns only the first header line with given name,
//      ignores multi-line headers and obs-fold headers
char *
Http::One::Parser::getHostHeaderField()
{
    if (!headerBlockSize())
        return NULL;

    LOCAL_ARRAY(char, header, GET_HDR_SZ);
    const char *name = "Host";
    const int namelen = strlen(name);

    debugs(25, 5, "looking for " << name);

    // while we can find more LF in the SBuf
    Tokenizer tok(mimeHeaderBlock_);
    SBuf p;

    while (tok.prefix(p, LineCharacters())) {
        if (!tok.skipOne(CharacterSet::LF)) // move tokenizer past the LF
            break; // error. reached invalid octet or end of buffer insted of an LF ??

        // header lines must start with the name (case insensitive)
        if (p.substr(0, namelen).caseCmp(name, namelen))
            continue;

        // then a COLON
        if (p[namelen] != ':')
            continue;

        // drop any trailing *CR sequence
        p.trim(Http1::CrLf(), false, true);

        debugs(25, 5, "checking " << p);
        p.consume(namelen + 1);

        // TODO: optimize SBuf::trim to take CharacterSet directly
        Tokenizer t(p);
        t.skipAll(CharacterSet::WSP);
        p = t.remaining();

        // prevent buffer overrun on char header[];
        p.chop(0, sizeof(header)-1);

        // currently only used for pre-parse Host header, ensure valid domain[:port] or ip[:port]
        static const auto hostChars = CharacterSet("host",":[].-_") + CharacterSet::ALPHA + CharacterSet::DIGIT;
        if (p.findFirstNotOf(hostChars) != SBuf::npos)
            break; // error. line contains character not accepted in Host header

        // return the header field-value
        SBufToCstring(header, p);
        debugs(25, 5, "returning " << header);
        return header;
    }

    return NULL;
}

int
Http::One::ErrorLevel()
{
    return Config.onoff.relaxed_header_parser < 0 ? DBG_IMPORTANT : 5;
}

// BWS = *( SP / HTAB ) ; WhitespaceCharacters() may relax this RFC 7230 rule
void
Http::One::ParseBws(Parser::Tokenizer &tok)
{
    const auto count = tok.skipAll(Parser::WhitespaceCharacters());

    if (tok.atEnd())
        throw InsufficientInput(); // even if count is positive

    if (count) {
        // Generating BWS is a MUST-level violation so warn about it as needed.
        debugs(33, ErrorLevel(), "found " << count << " BWS octets");
        // RFC 7230 says we MUST parse BWS, so we fall through even if
        // Config.onoff.relaxed_header_parser is off.
    }
    // else we successfully "parsed" an empty BWS sequence

    // success: no more BWS characters expected
}

