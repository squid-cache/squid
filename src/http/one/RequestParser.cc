/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "http/one/RequestParser.h"
#include "http/ProtocolVersion.h"
#include "mime_header.h"
#include "parser/Tokenizer.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"

Http::One::RequestParser::RequestParser() :
    Parser(),
    request_parse_status(Http::scNone),
    firstLineGarbage_(0)
{}

Http1::Parser::size_type
Http::One::RequestParser::firstLineSize() const
{
    // RFC 7230 section 2.6
    /* method SP request-target SP "HTTP/" DIGIT "." DIGIT CRLF */
    return method_.image().length() + uri_.length() + 12;
}

/**
 * Attempt to parse the first line of a new request message.
 *
 * Governed by RFC 7230 section 3.5
 *  "
 *    In the interest of robustness, a server that is expecting to receive
 *    and parse a request-line SHOULD ignore at least one empty line (CRLF)
 *    received prior to the request-line.
 *  "
 *
 * Parsing state is stored between calls to avoid repeating buffer scans.
 * If garbage is found the parsing offset is incremented.
 */
void
Http::One::RequestParser::skipGarbageLines()
{
    if (Config.onoff.relaxed_header_parser) {
        if (Config.onoff.relaxed_header_parser < 0 && (buf_[0] == '\r' || buf_[0] == '\n'))
            debugs(74, DBG_IMPORTANT, "WARNING: Invalid HTTP Request: " <<
                   "CRLF bytes received ahead of request-line. " <<
                   "Ignored due to relaxed_header_parser.");
        // Be tolerant of prefix empty lines
        // ie any series of either \n or \r\n with no other characters and no repeated \r
        while (!buf_.isEmpty() && (buf_[0] == '\n' || (buf_[0] == '\r' && buf_[1] == '\n'))) {
            buf_.consume(1);
        }
    }
}

/**
 * Attempt to parse the method field out of an HTTP message request-line.
 *
 * Governed by:
 *  RFC 1945 section 5.1
 *  RFC 7230 section 2.6, 3.1 and 3.5
 *
 * Parsing state is stored between calls. The current implementation uses
 * checkpoints after each successful request-line field.
 * The return value tells you whether the parsing is completed or not.
 *
 * \retval -1  an error occurred. request_parse_status indicates HTTP status result.
 * \retval  1  successful parse. method_ is filled and buffer consumed including first delimiter.
 * \retval  0  more data is needed to complete the parse
 */
int
Http::One::RequestParser::parseMethodField(::Parser::Tokenizer &tok, const CharacterSet &WspDelim)
{
    // scan for up to 16 valid method characters.
    static const size_t maxMethodLength = 16; // TODO: make this configurable?

    // method field is a sequence of TCHAR.
    SBuf methodFound;
    if (tok.prefix(methodFound, CharacterSet::TCHAR, maxMethodLength) && tok.skipOne(WspDelim)) {

        method_ = HttpRequestMethod(methodFound);
        buf_ = tok.remaining(); // incremental parse checkpoint
        return 1;

    } else if (tok.atEnd()) {
        debugs(74, 5, "Parser needs more data to find method");
        return 0;

    } // else error(s)

    // non-delimiter found after accepted method bytes means ...
    if (methodFound.length() == maxMethodLength) {
        // method longer than acceptible.
        // RFC 7230 section 3.1.1 mandatory (SHOULD) 501 response
        request_parse_status = Http::scNotImplemented;
        debugs(33, 5, "invalid request-line. method too long");
    } else {
        // invalid character in the URL
        // RFC 7230 section 3.1.1 required (SHOULD) 400 response
        request_parse_status = Http::scBadRequest;
        debugs(33, 5, "invalid request-line. missing method delimiter");
    }
    return -1;
}

static CharacterSet
uriValidCharacters()
{
    CharacterSet UriChars("URI-Chars","");

    /* RFC 3986 section 2:
     * "
     *   A URI is composed from a limited set of characters consisting of
     *   digits, letters, and a few graphic symbols.
     * "
     */
    // RFC 3986 section 2.1 - percent encoding "%" HEXDIG
    UriChars.add('%');
    UriChars += CharacterSet::HEXDIG;
    // RFC 3986 section 2.2 - reserved characters
    UriChars += CharacterSet("gen-delims", ":/?#[]@");
    UriChars += CharacterSet("sub-delims", "!$&'()*+,;=");
    // RFC 3986 section 2.3 - unreserved characters
    UriChars += CharacterSet::ALPHA;
    UriChars += CharacterSet::DIGIT;
    UriChars += CharacterSet("unreserved", "-._~");

    return UriChars;
}

int
Http::One::RequestParser::parseUriField(::Parser::Tokenizer &tok)
{
    // URI field is a sequence of ... what? segments all have different valid charset
    // go with non-whitespace non-binary characters for now
    static CharacterSet UriChars = uriValidCharacters();

    /* Arbitrary 64KB URI upper length limit.
     *
     * Not quite as arbitrary as it seems though. Old SquidString objects
     * cannot store strings larger than 64KB, so we must limit until they
     * have all been replaced with SBuf.
     *
     * Not that it matters but RFC 7230 section 3.1.1 requires (RECOMMENDED)
     * at least 8000 octets for the whole line, including method and version.
     */
    const size_t maxUriLength = min(static_cast<size_t>(Config.maxRequestHeaderSize) - firstLineSize(),
                                    static_cast<size_t>((64*1024)-1));

    SBuf uriFound;

    // RFC 7230 HTTP/1.x URI are followed by at least one whitespace delimiter
    if (tok.prefix(uriFound, UriChars, maxUriLength) && tok.skipOne(CharacterSet::SP)) {
        uri_ = uriFound;
        buf_ = tok.remaining(); // incremental parse checkpoint
        return 1;

        // RFC 1945 for GET the line terminator may follow URL instead of a delimiter
    } else if (method_ == Http::METHOD_GET && skipLineTerminator(tok)) {
        debugs(33, 5, "HTTP/0.9 syntax request-line detected");
        msgProtocol_ = Http::ProtocolVersion(0,9);
        uri_ = uriFound; // found by successful prefix() call earlier.
        request_parse_status = Http::scOkay;
        buf_ = tok.remaining(); // incremental parse checkpoint
        return 1;

    } else if (tok.atEnd()) {
        debugs(74, 5, "Parser needs more data to find URI");
        return 0;
    }

    // else errors...

    if (uriFound.length() == maxUriLength) {
        // RFC 7230 section 3.1.1 mandatory (MUST) 414 response
        request_parse_status = Http::scUriTooLong;
        debugs(33, 5, "invalid request-line. URI longer than " << maxUriLength << " bytes");
    } else {
        // RFC 7230 section 3.1.1 required (SHOULD) 400 response
        request_parse_status = Http::scBadRequest;
        debugs(33, 5, "invalid request-line. missing URI delimiter");
    }
    return -1;
}

int
Http::One::RequestParser::parseHttpVersionField(::Parser::Tokenizer &tok)
{
    // partial match of HTTP/1 magic prefix
    if (tok.remaining().length() < Http1magic.length() && Http1magic.startsWith(tok.remaining())) {
        debugs(74, 5, "Parser needs more data to find version");
        return 0;
    }

    if (!tok.skip(Http1magic)) {
        debugs(74, 5, "invalid request-line. not HTTP/1 protocol");
        request_parse_status = Http::scHttpVersionNotSupported;
        return -1;
    }

    if (tok.atEnd()) {
        debugs(74, 5, "Parser needs more data to find version");
        return 0;
    }

    // get the version minor DIGIT
    SBuf digit;
    if (tok.prefix(digit, CharacterSet::DIGIT, 1) && skipLineTerminator(tok)) {

        // found version fully AND terminator
        msgProtocol_ = Http::ProtocolVersion(1, (*digit.rawContent() - '0'));
        request_parse_status = Http::scOkay;
        buf_ = tok.remaining(); // incremental parse checkpoint
        return 1;

    } else if (tok.atEnd() || (tok.skip('\r') && tok.atEnd())) {
        debugs(74, 5, "Parser needs more data to find version");
        return 0;

    } // else error ...

    // non-DIGIT. invalid version number.
    request_parse_status = Http::scHttpVersionNotSupported;
    debugs(33, 5, "invalid request-line. garabge before line terminator");
    return -1;
}

/**
 * Attempt to parse the first line of a new request message.
 *
 * Governed by:
 *  RFC 1945 section 5.1
 *  RFC 7230 section 2.6, 3.1 and 3.5
 *
 * Parsing state is stored between calls. The current implementation uses
 * checkpoints after each successful request-line field.
 * The return value tells you whether the parsing is completed or not.
 *
 * \retval -1  an error occurred. request_parse_status indicates HTTP status result.
 * \retval  1  successful parse. member fields contain the request-line items
 * \retval  0  more data is needed to complete the parse
 */
int
Http::One::RequestParser::parseRequestFirstLine()
{
    ::Parser::Tokenizer tok(buf_);

    debugs(74, 5, "parsing possible request: buf.length=" << buf_.length());
    debugs(74, DBG_DATA, buf_);

    // NP: would be static, except it need to change with reconfigure
    CharacterSet WspDelim = CharacterSet::SP; // strict parse only accepts SP

    if (Config.onoff.relaxed_header_parser) {
        // RFC 7230 section 3.5
        // tolerant parser MAY accept any of SP, HTAB, VT (%x0B), FF (%x0C), or bare CR
        // as whitespace between request-line fields
        WspDelim += CharacterSet::HTAB
                    + CharacterSet("VT,FF","\x0B\x0C")
                    + CharacterSet::CR;
    }

    // only search for method if we have not yet found one
    if (method_ == Http::METHOD_NONE) {
        const int res = parseMethodField(tok, WspDelim);
        if (res < 1)
            return res;
        // else keep going...
    }

    // tolerant parser allows multiple whitespace characters between request-line fields
    if (Config.onoff.relaxed_header_parser) {
        const size_t garbage = tok.skipAll(WspDelim);
        if (garbage > 0) {
            firstLineGarbage_ += garbage;
            buf_ = tok.remaining(); // re-checkpoint after garbage
        }
    }
    if (tok.atEnd()) {
        debugs(74, 5, "Parser needs more data");
        return 0;
    }

    // from here on, we have two possible parse paths: whitespace tolerant, and strict
    if (Config.onoff.relaxed_header_parser) {
        // whitespace tolerant

        // NOTES:
        // * this would be static, except WspDelim changes with reconfigure
        // * HTTP-version charset is included by uriValidCharacters()
        // * terminal CR is included by WspDelim here in relaxed parsing
        CharacterSet LfDelim = uriValidCharacters() + WspDelim;

        // seek the LF character, then tokenize the line in reverse
        SBuf line;
        if (tok.prefix(line, LfDelim) && tok.skip('\n')) {
            ::Parser::Tokenizer rTok(line);
            SBuf nil;
            (void)rTok.suffix(nil,CharacterSet::CR); // optional CR in terminator
            SBuf digit;
            if (rTok.suffix(digit,CharacterSet::DIGIT) && rTok.skipSuffix(Http1magic) && rTok.suffix(nil,WspDelim)) {
                uri_ = rTok.remaining();
                msgProtocol_ = Http::ProtocolVersion(1, (*digit.rawContent() - '0'));
                if (uri_.isEmpty()) {
                    debugs(33, 5, "invalid request-line. missing URL");
                    request_parse_status = Http::scBadRequest;
                    return -1;
                }

                request_parse_status = Http::scOkay;
                buf_ = tok.remaining(); // incremental parse checkpoint
                return 1;

            } else if (method_ == Http::METHOD_GET) {
                // RFC 1945 - for GET the line terminator may follow URL instead of a delimiter
                debugs(33, 5, "HTTP/0.9 syntax request-line detected");
                msgProtocol_ = Http::ProtocolVersion(0,9);
                static const SBuf cr("\r",1);
                uri_ = line.trim(cr,false,true);
                request_parse_status = Http::scOkay;
                buf_ = tok.remaining(); // incremental parse checkpoint
                return 1;
            }

            debugs(33, 5, "invalid request-line. not HTTP");
            request_parse_status = Http::scBadRequest;
            return -1;
        }

        debugs(74, 5, "Parser needs more data");
        return 0;
    }
    // else strict non-whitespace tolerant parse

    // only search for request-target (URL) if we have not yet found one
    if (uri_.isEmpty()) {
        const int res = parseUriField(tok);
        if (res < 1 || msgProtocol_.protocol == AnyP::PROTO_HTTP)
            return res;
        // else keep going...
    }

    if (tok.atEnd()) {
        debugs(74, 5, "Parser needs more data");
        return 0;
    }

    // HTTP/1 version suffix (protocol magic) followed by CR*LF
    if (msgProtocol_.protocol == AnyP::PROTO_NONE) {
        return parseHttpVersionField(tok);
    }

    // If we got here this method has been called too many times
    request_parse_status = Http::scInternalServerError;
    debugs(33, 5, "ERROR: Parser already processed request-line");
    return -1;
}

bool
Http::One::RequestParser::parse(const SBuf &aBuf)
{
    buf_ = aBuf;
    debugs(74, DBG_DATA, "Parse buf={length=" << aBuf.length() << ", data='" << aBuf << "'}");

    // stage 1: locate the request-line
    if (parsingStage_ == HTTP_PARSE_NONE) {
        skipGarbageLines();

        // if we hit something before EOS treat it as a message
        if (!buf_.isEmpty())
            parsingStage_ = HTTP_PARSE_FIRST;
        else
            return false;
    }

    // stage 2: parse the request-line
    if (parsingStage_ == HTTP_PARSE_FIRST) {
        PROF_start(HttpParserParseReqLine);
        const int retcode = parseRequestFirstLine();

        // first-line (or a look-alike) found successfully.
        if (retcode > 0) {
            parsingStage_ = HTTP_PARSE_MIME;
        }

        debugs(74, 5, "request-line: retval " << retcode << ": line={" << aBuf.length() << ", data='" << aBuf << "'}");
        debugs(74, 5, "request-line: method: " << method_);
        debugs(74, 5, "request-line: url: " << uri_);
        debugs(74, 5, "request-line: proto: " << msgProtocol_);
        debugs(74, 5, "Parser: bytes processed=" << (aBuf.length()-buf_.length()));
        PROF_stop(HttpParserParseReqLine);

        // syntax errors already
        if (retcode < 0) {
            parsingStage_ = HTTP_PARSE_DONE;
            return false;
        }
    }

    // stage 3: locate the mime header block
    if (parsingStage_ == HTTP_PARSE_MIME) {
        // HTTP/1.x request-line is valid and parsing completed.
        if (msgProtocol_.major == 1) {
            /* NOTE: HTTP/0.9 requests do not have a mime header block.
             *       So the rest of the code will need to deal with '0'-byte headers
             *       (ie, none, so don't try parsing em)
             */
            int64_t mimeHeaderBytes = 0;
            // XXX: c_str() reallocates. performance regression.
            if ((mimeHeaderBytes = headersEnd(buf_.c_str(), buf_.length())) == 0) {
                if (buf_.length()+firstLineSize() >= Config.maxRequestHeaderSize) {
                    debugs(33, 5, "Too large request");
                    request_parse_status = Http::scRequestHeaderFieldsTooLarge;
                    parsingStage_ = HTTP_PARSE_DONE;
                } else
                    debugs(33, 5, "Incomplete request, waiting for end of headers");
                return false;
            }
            mimeHeaderBlock_ = buf_.consume(mimeHeaderBytes);
            debugs(74, 5, "mime header (0-" << mimeHeaderBytes << ") {" << mimeHeaderBlock_ << "}");

        } else
            debugs(33, 3, "Missing HTTP/1.x identifier");

        // NP: we do not do any further stages here yet so go straight to DONE
        parsingStage_ = HTTP_PARSE_DONE;

        // Squid could handle these headers, but admin does not want to
        if (messageHeaderSize() >= Config.maxRequestHeaderSize) {
            debugs(33, 5, "Too large request");
            request_parse_status = Http::scRequestHeaderFieldsTooLarge;
            return false;
        }
    }

    return !needsMoreData();
}

