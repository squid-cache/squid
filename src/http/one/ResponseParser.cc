/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Raw.h"
#include "debug/Stream.h"
#include "http/one/ResponseParser.h"
#include "http/ProtocolVersion.h"
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"
#include "SquidConfig.h"

const SBuf Http::One::ResponseParser::IcyMagic("ICY ");

Http1::Parser::size_type
Http::One::ResponseParser::firstLineSize() const
{
    Http1::Parser::size_type result = 0;

    switch (msgProtocol_.protocol)
    {
    case AnyP::PROTO_HTTP:
        result += Http1magic.length();
        break;
    case AnyP::PROTO_ICY:
        result += IcyMagic.length();
        break;
    default: // no other protocols supported
        return result;
    }
    // NP: the parser does not accept >2 DIGIT for version numbers
    if (msgProtocol_.minor > 9)
        result += 2;
    else
        result += 1;

    result += 5; /* 5 octets in: SP status SP */
    result += reasonPhrase_.length();
    result += 2; /* CRLF terminator */
    return result;
}

// NP: we found the protocol version and consumed it already.
// just need the status code and reason phrase
int
Http::One::ResponseParser::parseResponseStatusAndReason(Tokenizer &tok)
{
    try {
        if (!completedStatus_) {
            debugs(74, 9, "seek status-code in: " << tok.remaining().substr(0,10) << "...");
            ParseResponseStatus(tok, statusCode_);
            buf_ = tok.remaining(); // resume checkpoint
            completedStatus_ = true;
        }
        // NOTE: any whitespace after the single SP is part of the reason phrase.

        /* RFC 7230 says we SHOULD ignore the reason phrase content
         * but it has a definite valid vs invalid character set.
         * We interpret the SHOULD as ignoring absence and syntax, but
         * producing an error if it contains an invalid octet.
         */

        debugs(74, 9, "seek reason-phrase in: " << tok.remaining().substr(0,50) << "...");
        // if we got here we are still looking for reason-phrase bytes
        static const CharacterSet phraseChars = CharacterSet::WSP + CharacterSet::VCHAR + CharacterSet::OBSTEXT;
        (void)tok.prefix(reasonPhrase_, phraseChars); // optional, no error if missing
        skipLineTerminator(tok);
        buf_ = tok.remaining(); // resume checkpoint
        debugs(74, DBG_DATA, Raw("leftovers", buf_.rawContent(), buf_.length()));
        return 1;
    } catch (const InsufficientInput &) {
        reasonPhrase_.clear();
        return 0; // need more to be sure we have it all
    } catch (const std::exception &ex) {
        debugs(74, 6, "invalid status-line: " << ex.what());
    }
    return -1;
}

void
Http::One::ResponseParser::ParseResponseStatus(Tokenizer &tok, StatusCode &code)
{
    int64_t statusValue;
    if (tok.int64(statusValue, 10, false, 3) && tok.skipOne(Parser::DelimiterCharacters())) {
        debugs(74, 6, "raw status-code=" << statusValue);
        code = static_cast<StatusCode>(statusValue); // may be invalid

        // RFC 7230 Section 3.1.2 says status-code is exactly three DIGITs
        if (code <= 99)
            throw TextException(ToSBuf("status-code too short: ", code), Here());

        // Codes with a non-standard first digit (a.k.a. response class) are
        // considered semantically invalid per the following HTTP WG discussion:
        // https://lists.w3.org/Archives/Public/ietf-http-wg/2010AprJun/0354.html
        if (code >= 600)
            throw TextException(ToSBuf("status-code from an invalid response class: ", code), Here());
    } else if (tok.atEnd()) {
        throw InsufficientInput();
    } else {
        throw TextException("syntactically invalid status-code area", Here());
    }
}

/**
 * Attempt to parse the method field out of an HTTP message status-line.
 *
 * Governed by:
 *  RFC 1945 section 6.1
 *  RFC 7230 section 2.6, 3.1 and 3.5
 *
 * Parsing state is stored between calls. The current implementation uses
 * checkpoints after each successful status-line field.
 * The return value tells you whether the parsing is completed or not.
 *
 * \retval -1  an error occurred.
 * \retval  1  successful parse. statusCode_ and maybe reasonPhrase_ are filled and buffer consumed including first delimiter.
 * \retval  0  more data is needed to complete the parse
 */
int
Http::One::ResponseParser::parseResponseFirstLine()
{
    Tokenizer tok(buf_);

    if (msgProtocol_.protocol != AnyP::PROTO_NONE) {
        debugs(74, 6, "continue incremental parse for " << msgProtocol_);
        debugs(74, DBG_DATA, "parse remaining buf={length=" << tok.remaining().length() << ", data='" << tok.remaining() << "'}");
        // we already found the magic, but not the full line. keep going.
        return parseResponseStatusAndReason(tok);

    } else if (tok.skip(Http1magic)) {
        debugs(74, 6, "found prefix magic " << Http1magic);
        // HTTP Response status-line parse

        // magic contains major version, still need to find minor DIGIT
        int64_t verMinor;
        const auto &WspDelim = DelimiterCharacters();
        if (tok.int64(verMinor, 10, false, 1) && tok.skipOne(WspDelim)) {
            msgProtocol_.protocol = AnyP::PROTO_HTTP;
            msgProtocol_.major = 1;
            msgProtocol_.minor = static_cast<unsigned int>(verMinor);

            debugs(74, 6, "found version=" << msgProtocol_);

            debugs(74, DBG_DATA, "parse remaining buf={length=" << tok.remaining().length() << ", data='" << tok.remaining() << "'}");
            buf_ = tok.remaining(); // resume checkpoint
            return parseResponseStatusAndReason(tok);

        } else if (tok.atEnd())
            return 0; // need more to be sure we have it all
        else
            return -1; // invalid version or delimiter, a single SP terminator required

    } else if (tok.skip(IcyMagic)) {
        debugs(74, 6, "found prefix magic " << IcyMagic);
        // ICY Response status-line parse (same as HTTP/1 after the magic version)
        msgProtocol_.protocol = AnyP::PROTO_ICY;
        // NP: ICY has no /major.minor details
        debugs(74, DBG_DATA, "parse remaining buf={length=" << tok.remaining().length() << ", data='" << tok.remaining() << "'}");
        buf_ = tok.remaining(); // resume checkpoint
        return parseResponseStatusAndReason(tok);
    } else if (buf_.length() < Http1magic.length() && Http1magic.startsWith(buf_)) {
        debugs(74, 7, Raw("valid HTTP/1 prefix", buf_.rawContent(), buf_.length()));
        return 0;
    } else if (buf_.length() < IcyMagic.length() && IcyMagic.startsWith(buf_)) {
        debugs(74, 7, Raw("valid ICY prefix", buf_.rawContent(), buf_.length()));
        return 0;
    } else {
        debugs(74, 2, "unknown/missing prefix magic. Interpreting as HTTP/0.9");
        // found something that looks like an HTTP/0.9 response
        // Gateway/Transform it into HTTP/1.1
        msgProtocol_ = Http::ProtocolVersion(1,1);
        // XXX: probably should use version 0.9 here and upgrade on output,
        // but the old code did 1.1 transformation now.
        statusCode_ = Http::scOkay;
        static const SBuf gatewayPhrase("Gatewaying");
        reasonPhrase_ = gatewayPhrase;
        static const SBuf fakeHttpMimeBlock("X-Transformed-From: HTTP/0.9\r\n"
                                            /* Server: visible_appname_string */
                                            "Mime-Version: 1.0\r\n"
                                            /* Date: squid_curtime */
                                            "Expires: -1\r\n\r\n");
        mimeHeaderBlock_ = fakeHttpMimeBlock;
        parsingStage_ = HTTP_PARSE_DONE;
        return 1; // no more parsing
    }

    // unreachable
    assert(false);
    return -1;
}

bool
Http::One::ResponseParser::parse(const SBuf &aBuf)
{
    buf_ = aBuf;
    debugs(74, DBG_DATA, "Parse buf={length=" << aBuf.length() << ", data='" << aBuf << "'}");

    // stage 1: locate the status-line
    if (parsingStage_ == HTTP_PARSE_NONE) {
        // RFC 7230 explicitly states whether garbage whitespace is to be handled
        // at each point of the message framing boundaries.
        // It omits mentioning garbage prior to HTTP Responses.
        // Therefore, if we receive anything at all treat it as Response message.
        if (!buf_.isEmpty())
            parsingStage_ = HTTP_PARSE_FIRST;
        else
            return false;
    }

    // stage 2: parse the status-line
    if (parsingStage_ == HTTP_PARSE_FIRST) {
        const int retcode = parseResponseFirstLine();

        // first-line (or a look-alike) found successfully.
        if (retcode > 0 && parsingStage_ == HTTP_PARSE_FIRST)
            parsingStage_ = HTTP_PARSE_MIME;
        debugs(74, 5, "status-line: retval " << retcode);
        debugs(74, 5, "status-line: proto " << msgProtocol_);
        debugs(74, 5, "status-line: status-code " << statusCode_);
        debugs(74, 5, "status-line: reason-phrase " << reasonPhrase_);
        debugs(74, 5, "Parser: bytes processed=" << (aBuf.length()-buf_.length()));

        // syntax errors already
        if (retcode < 0) {
            parsingStage_ = HTTP_PARSE_DONE;
            parseStatusCode = Http::scInvalidHeader;
            return false;
        }
    }

    // stage 3: locate the mime header block
    if (parsingStage_ == HTTP_PARSE_MIME) {
        if (!grabMimeBlock("Response", Config.maxReplyHeaderSize))
            return false;
    }

    return !needsMoreData();
}

