/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "http/one/RequestParser.h"
#include "http/ProtocolVersion.h"
#include "parser/Tokenizer.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"

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
 */
bool
Http::One::RequestParser::parseMethodField(Tokenizer &tok)
{
    // method field is a sequence of TCHAR.
    // Limit to 32 characters to prevent overly long sequences of non-HTTP
    // being sucked in before mismatch is detected. 32 is itself annoyingly
    // big but there are methods registered by IANA that reach 17 bytes:
    //  http://www.iana.org/assignments/http-methods
    static const size_t maxMethodLength = 32; // TODO: make this configurable?

    SBuf methodFound;
    if (!tok.prefix(methodFound, CharacterSet::TCHAR, maxMethodLength)) {
        debugs(33, ErrorLevel(), "invalid request-line: missing or malformed method");
        parseStatusCode = Http::scBadRequest;
        return false;
    }
    method_ = HttpRequestMethod(methodFound);

    if (!skipDelimiter(tok.skipAll(DelimiterCharacters()), "after method"))
        return false;

    return true;
}

/// the characters which truly are valid within URI
static const CharacterSet &
UriValidCharacters()
{
    /* RFC 3986 section 2:
     * "
     *   A URI is composed from a limited set of characters consisting of
     *   digits, letters, and a few graphic symbols.
     * "
     */
    static const CharacterSet UriChars =
        CharacterSet("URI-Chars","") +
        // RFC 3986 section 2.2 - reserved characters
        CharacterSet("gen-delims", ":/?#[]@") +
        CharacterSet("sub-delims", "!$&'()*+,;=") +
        // RFC 3986 section 2.3 - unreserved characters
        CharacterSet::ALPHA +
        CharacterSet::DIGIT +
        CharacterSet("unreserved", "-._~") +
        // RFC 3986 section 2.1 - percent encoding "%" HEXDIG
        CharacterSet("pct-encoded", "%") +
        CharacterSet::HEXDIG;

    return UriChars;
}

/// characters which Squid will accept in the HTTP request-target (URI)
const CharacterSet &
Http::One::RequestParser::RequestTargetCharacters()
{
    if (Config.onoff.relaxed_header_parser) {
#if USE_HTTP_VIOLATIONS
        static const CharacterSet RelaxedExtended =
            UriValidCharacters() +
            // accept whitespace (extended), it will be dealt with later
            DelimiterCharacters() +
            // RFC 2396 unwise character set which must never be transmitted
            // in un-escaped form. But many web services do anyway.
            CharacterSet("RFC2396-unwise","\"\\|^<>`{}") +
            // UTF-8 because we want to be future-proof
            CharacterSet("UTF-8", 128, 255);

        return RelaxedExtended;
#else
        static const CharacterSet RelaxedCompliant =
            UriValidCharacters() +
            // accept whitespace (extended), it will be dealt with later.
            DelimiterCharacters();

        return RelaxedCompliant;
#endif
    }

    // strict parse only accepts what the RFC say we can
    return UriValidCharacters();
}

bool
Http::One::RequestParser::parseUriField(Tokenizer &tok)
{
    /* Arbitrary 64KB URI upper length limit.
     *
     * Not quite as arbitrary as it seems though. Old SquidString objects
     * cannot store strings larger than 64KB, so we must limit until they
     * have all been replaced with SBuf.
     *
     * Not that it matters but RFC 7230 section 3.1.1 requires (RECOMMENDED)
     * at least 8000 octets for the whole line, including method and version.
     */
    const size_t maxUriLength = static_cast<size_t>((64*1024)-1);

    SBuf uriFound;
    if (!tok.prefix(uriFound, RequestTargetCharacters())) {
        parseStatusCode = Http::scBadRequest;
        debugs(33, ErrorLevel(), "invalid request-line: missing or malformed URI");
        return false;
    }

    if (uriFound.length() > maxUriLength) {
        // RFC 7230 section 3.1.1 mandatory (MUST) 414 response
        parseStatusCode = Http::scUriTooLong;
        debugs(33, ErrorLevel(), "invalid request-line: " << uriFound.length() <<
               "-byte URI exceeds " << maxUriLength << "-byte limit");
        return false;
    }

    uri_ = uriFound;
    return true;
}

bool
Http::One::RequestParser::parseHttpVersionField(Tokenizer &tok)
{
    static const SBuf http1p0("HTTP/1.0");
    static const SBuf http1p1("HTTP/1.1");
    const auto savedTok = tok;

    // Optimization: Expect (and quickly parse) HTTP/1.1 or HTTP/1.0 in
    // the vast majority of cases.
    if (tok.skipSuffix(http1p1)) {
        msgProtocol_ = Http::ProtocolVersion(1, 1);
        return true;
    } else if (tok.skipSuffix(http1p0)) {
        msgProtocol_ = Http::ProtocolVersion(1, 0);
        return true;
    } else {
        // RFC 7230 section 2.6:
        // HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
        static const CharacterSet period("Decimal point", ".");
        static const SBuf proto("HTTP/");
        SBuf majorDigit;
        SBuf minorDigit;
        if (tok.suffix(minorDigit, CharacterSet::DIGIT) &&
                tok.skipOneTrailing(period) &&
                tok.suffix(majorDigit, CharacterSet::DIGIT) &&
                tok.skipSuffix(proto)) {
            const bool multiDigits = majorDigit.length() > 1 || minorDigit.length() > 1;
            // use '0.0' for unsupported multiple digit version numbers
            const unsigned int major = multiDigits ? 0 : (*majorDigit.rawContent() - '0');
            const unsigned int minor = multiDigits ? 0 : (*minorDigit.rawContent() - '0');
            msgProtocol_ = Http::ProtocolVersion(major, minor);
            return true;
        }
    }

    // A GET request might use HTTP/0.9 syntax
    if (method_ == Http::METHOD_GET) {
        // RFC 1945 - no HTTP version field at all
        tok = savedTok; // in case the URI ends with a digit
        // report this assumption as an error if configured to triage parsing
        debugs(33, ErrorLevel(), "assuming HTTP/0.9 request-line");
        msgProtocol_ = Http::ProtocolVersion(0,9);
        return true;
    }

    debugs(33, ErrorLevel(), "invalid request-line: not HTTP");
    parseStatusCode = Http::scBadRequest;
    return false;
}

/**
 * Skip characters separating request-line fields.
 * To handle bidirectional parsing, the caller does the actual skipping and
 * we just check how many character the caller has skipped.
 */
bool
Http::One::RequestParser::skipDelimiter(const size_t count, const char *where)
{
    if (count <= 0) {
        debugs(33, ErrorLevel(), "invalid request-line: missing delimiter " << where);
        parseStatusCode = Http::scBadRequest;
        return false;
    }

    // tolerant parser allows multiple whitespace characters between request-line fields
    if (count > 1 && !Config.onoff.relaxed_header_parser) {
        debugs(33, ErrorLevel(), "invalid request-line: too many delimiters " << where);
        parseStatusCode = Http::scBadRequest;
        return false;
    }

    return true;
}

/// Parse CRs at the end of request-line, just before the terminating LF.
bool
Http::One::RequestParser::skipTrailingCrs(Tokenizer &tok)
{
    if (Config.onoff.relaxed_header_parser) {
        (void)tok.skipAllTrailing(CharacterSet::CR); // optional; multiple OK
    } else {
        if (!tok.skipOneTrailing(CharacterSet::CR)) {
            debugs(33, ErrorLevel(), "invalid request-line: missing CR before LF");
            parseStatusCode = Http::scBadRequest;
            return false;
        }
    }
    return true;
}

/**
 * Attempt to parse the first line of a new request message.
 *
 * Governed by:
 *  RFC 1945 section 5.1
 *  RFC 7230 section 2.6, 3.1 and 3.5
 *
 * \retval -1  an error occurred. parseStatusCode indicates HTTP status result.
 * \retval  1  successful parse. member fields contain the request-line items
 * \retval  0  more data is needed to complete the parse
 */
int
Http::One::RequestParser::parseRequestFirstLine()
{
    debugs(74, 5, "parsing possible request: buf.length=" << buf_.length());
    debugs(74, DBG_DATA, buf_);

    SBuf line;

    // Earlier, skipGarbageLines() took care of any leading LFs (if allowed).
    // Now, the request line has to end at the first LF.
    static const CharacterSet lineChars = CharacterSet::LF.complement("notLF");
    Tokenizer lineTok(buf_);
    if (!lineTok.prefix(line, lineChars) || !lineTok.skip('\n')) {
        if (buf_.length() >= Config.maxRequestHeaderSize) {
            /* who should we blame for our failure to parse this line? */

            Tokenizer methodTok(buf_);
            if (!parseMethodField(methodTok))
                return -1; // blame a bad method (or its delimiter)

            // assume it is the URI
            debugs(74, ErrorLevel(), "invalid request-line: URI exceeds " <<
                   Config.maxRequestHeaderSize << "-byte limit");
            parseStatusCode = Http::scUriTooLong;
            return -1;
        }
        debugs(74, 5, "Parser needs more data");
        return 0;
    }

    Tokenizer tok(line);

    if (!parseMethodField(tok))
        return -1;

    /* now parse backwards, to leave just the URI */
    if (!skipTrailingCrs(tok))
        return -1;

    if (!parseHttpVersionField(tok))
        return -1;

    if (!http0() && !skipDelimiter(tok.skipAllTrailing(DelimiterCharacters()), "before protocol version"))
        return -1;

    /* parsed everything before and after the URI */

    if (!parseUriField(tok))
        return -1;

    if (!tok.atEnd()) {
        debugs(33, ErrorLevel(), "invalid request-line: garbage after URI");
        parseStatusCode = Http::scBadRequest;
        return -1;
    }

    parseStatusCode = Http::scOkay;
    buf_ = lineTok.remaining(); // incremental parse checkpoint
    return 1;
}

bool
Http::One::RequestParser::parse(const SBuf &aBuf)
{
    const bool result = doParse(aBuf);
    if (preserveParsed_) {
        assert(aBuf.length() >= remaining().length());
        parsed_.append(aBuf.substr(0, aBuf.length() - remaining().length())); // newly parsed bytes
    }

    return result;
}

// raw is not a reference because a reference might point back to our own buf_ or parsed_
bool
Http::One::RequestParser::doParse(const SBuf &aBuf)
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
        if (!grabMimeBlock("Request", Config.maxRequestHeaderSize)) {
            if (parseStatusCode == Http::scHeaderTooLarge)
                parseStatusCode = Http::scRequestHeaderFieldsTooLarge;
            return false;
        }
    }

    return !needsMoreData();
}

