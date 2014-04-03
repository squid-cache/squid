#include "squid.h"
#include "Debug.h"
#include "http/Http1Parser.h"
#include "http/RequestMethod.h"
#include "mime_header.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"

void
Http::One::Parser::clear()
{
    parsingStage_ = HTTP_PARSE_NONE;
    buf = NULL;
    bufsiz = 0;
    parseOffset_ = 0;
    msgProtocol_ = AnyP::ProtocolVersion();
    mimeHeaderBlock_.clear();
}

void
Http::One::RequestParser::clear()
{
    Http1::Parser::clear();

    request_parse_status = Http::scNone;
    req.start = req.end = -1;
    req.m_start = req.m_end = -1;
    req.u_start = req.u_end = -1;
    req.v_start = req.v_end = -1;
    method_ = HttpRequestMethod();
}

void
Http::One::Parser::reset(const char *aBuf, int len)
{
    clear(); // empty the state.
    parsingStage_ = HTTP_PARSE_NEW;
    parseOffset_ = 0;
    buf = aBuf;
    bufsiz = len;
    debugs(74, DBG_DATA, "Parse " << Raw("buf", buf, bufsiz));
}

void
Http::One::RequestParser::noteBufferShift(int64_t n)
{
    // if parsing done, ignore buffer changes.
    if (parsingStage_ == HTTP_PARSE_DONE)
        return;

    // shift the parser resume point to match buffer content change
    parseOffset_ -= n;

    // and remember where to stop before performing buffered data overreads
    bufsiz -= n;
}

/**
 * Attempt to parse the first line of a new request message.
 *
 * Governed by RFC 2616 section 4.1
 *  "
 *    In the interest of robustness, servers SHOULD ignore any empty
 *    line(s) received where a Request-Line is expected. In other words, if
 *    the server is reading the protocol stream at the beginning of a
 *    message and receives a CRLF first, it should ignore the CRLF.
 *
 *    ... To restate what is explicitly forbidden by the
 *    BNF, an HTTP/1.1 client MUST NOT preface or follow a request with an
 *    extra CRLF.
 *  "
 *
 * Parsing state is stored between calls to avoid repeating buffer scans.
 * If garbage is found the parsing offset is incremented.
 */
void
Http::One::RequestParser::skipGarbageLines()
{
#if WHEN_RFC_COMPLIANT // CRLF or bare-LF is what RFC 2616 tolerant parsers do ...
    if (Config.onoff.relaxed_header_parser) {
        if (Config.onoff.relaxed_header_parser < 0 && (buf[parseOffset_] == '\r' || buf[parseOffset_] == '\n'))
            debugs(74, DBG_IMPORTANT, "WARNING: Invalid HTTP Request: " <<
                   "CRLF bytes received ahead of request-line. " <<
                   "Ignored due to relaxed_header_parser.");
        // Be tolerant of prefix empty lines
        // ie any series of either \n or \r\n with no other characters and no repeated \r
        for (; parseOffset_ < (size_t)bufsiz && (buf[parseOffset_] == '\n' || ((buf[parseOffset_] == '\r' && (buf[parseOffset_+1] == '\n')); ++parseOffset_);
    }
#endif

    /* XXX: this is a Squid-specific tolerance
     * it appears never to have been relevant outside out unit-tests
     * because the ConnStateData parser loop starts with consumeWhitespace()
     * which absorbs any SP HTAB VTAB CR LF characters.
     * But unit-tests called the HttpParser method directly without that pruning.
     */
#if USE_HTTP_VIOLATIONS
    if (Config.onoff.relaxed_header_parser) {
        if (Config.onoff.relaxed_header_parser < 0 && buf[parseOffset_] == ' ')
            debugs(74, DBG_IMPORTANT, "WARNING: Invalid HTTP Request: " <<
                   "Whitespace bytes received ahead of method. " <<
                   "Ignored due to relaxed_header_parser.");
        // Be tolerant of prefix spaces (other bytes are valid method values)
        for (; parseOffset_ < (size_t)bufsiz && buf[parseOffset_] == ' '; ++parseOffset_);
    }
#endif
}

/**
 * Attempt to parse the first line of a new request message.
 *
 * Governed by:
 *  RFC 1945 section 5.1
 *  RFC 2616 section 5.1
 *
 * Parsing state is stored between calls. However the current implementation
 * begins parsing from scratch on every call.
 * The return value tells you whether the parsing state fields are valid or not.
 *
 * \retval -1  an error occurred. request_parse_status indicates HTTP status result.
 * \retval  1  successful parse. member fields contain the request-line items
 * \retval  0  more data is needed to complete the parse
 */
int
Http::One::RequestParser::parseRequestFirstLine()
{
    int second_word = -1; // track the suspected URI start
    int first_whitespace = -1, last_whitespace = -1; // track the first and last SP byte
    int line_end = -1; // tracks the last byte BEFORE terminal \r\n or \n sequence

    debugs(74, 5, "parsing possible request: bufsiz=" << bufsiz << ", offset=" << parseOffset_);
    debugs(74, DBG_DATA, Raw("(buf+offset)", buf+parseOffset_, bufsiz-parseOffset_));

    // Single-pass parse: (provided we have the whole line anyways)

    req.start = parseOffset_; // avoid re-parsing any portion we managed to complete
    req.end = -1;
    for (int i = 0; i < bufsiz; ++i) {
        // track first and last whitespace (SP only)
        if (buf[i] == ' ') {
            last_whitespace = i;
            if (first_whitespace < req.start)
                first_whitespace = i;
        }

        // track next non-SP/non-HT byte after first_whitespace
        if (second_word < first_whitespace && buf[i] != ' ' && buf[i] != '\t') {
            second_word = i;
        }

        // locate line terminator
        if (buf[i] == '\n') {
            req.end = i;
            line_end = i - 1;
            break;
        }
        if (i < bufsiz - 1 && buf[i] == '\r') {
            if (Config.onoff.relaxed_header_parser) {
                if (Config.onoff.relaxed_header_parser < 0 && buf[i + 1] == '\r')
                    debugs(74, DBG_IMPORTANT, "WARNING: Invalid HTTP Request: " <<
                           "Series of carriage-return bytes received prior to line terminator. " <<
                           "Ignored due to relaxed_header_parser.");

                // Be tolerant of invalid multiple \r prior to terminal \n
                if (buf[i + 1] == '\n' || buf[i + 1] == '\r')
                    line_end = i - 1;
                while (i < bufsiz - 1 && buf[i + 1] == '\r')
                    ++i;

                if (buf[i + 1] == '\n') {
                    req.end = i + 1;
                    break;
                }
            } else {
                if (buf[i + 1] == '\n') {
                    req.end = i + 1;
                    line_end = i - 1;
                    break;
                }
            }

            // RFC 2616 section 5.1
            // "No CR or LF is allowed except in the final CRLF sequence"
            request_parse_status = Http::scBadRequest;
            return -1;
        }
    }

    if (req.end == -1) {
        // DoS protection against long first-line
        if ( (size_t)bufsiz >= Config.maxRequestHeaderSize) {
            debugs(33, 5, "Too large request-line");
            // XXX: return URL-too-log status code if second_whitespace is not yet found.
            request_parse_status = Http::scHeaderTooLarge;
            return -1;
        }

        debugs(74, 5, "Parser: retval 0: from " << req.start <<
               "->" << req.end << ": needs more data to complete first line.");
        return 0;
    }

    // NP: we have now seen EOL, more-data (0) cannot occur.
    //     From here on any failure is -1, success is 1

    // Input Validation:

    // DoS protection against long first-line
    if ((size_t)(req.end-req.start) >= Config.maxRequestHeaderSize) {
        debugs(33, 5, "Too large request-line");
        request_parse_status = Http::scHeaderTooLarge;
        return -1;
    }

    // Process what we now know about the line structure into field offsets
    // generating HTTP status for any aborts as we go.

    // First non-whitespace = beginning of method
    if (req.start > line_end) {
        request_parse_status = Http::scBadRequest;
        return -1;
    }
    req.m_start = req.start;

    // First whitespace = end of method
    if (first_whitespace > line_end || first_whitespace < req.start) {
        request_parse_status = Http::scBadRequest; // no method
        return -1;
    }
    req.m_end = first_whitespace - 1;
    if (req.m_end < req.m_start) {
        request_parse_status = Http::scBadRequest; // missing URI?
        return -1;
    }

    /* Set method_ */
    method_ = HttpRequestMethod(&buf[req.m_start], &buf[req.m_end]+1);

    // First non-whitespace after first SP = beginning of URL+Version
    if (second_word > line_end || second_word < req.start) {
        request_parse_status = Http::scBadRequest; // missing URI
        return -1;
    }
    req.u_start = second_word;

    // RFC 1945: SP and version following URI are optional, marking version 0.9
    // we identify this by the last whitespace being earlier than URI start
    if (last_whitespace < second_word && last_whitespace >= req.start) {
        msgProtocol_ = Http::ProtocolVersion(0,9);
        req.u_end = line_end;
        request_parse_status = Http::scOkay; // HTTP/0.9
        return 1;
    } else {
        // otherwise last whitespace is somewhere after end of URI.
        req.u_end = last_whitespace;
        // crop any trailing whitespace in the area we think of as URI
        for (; req.u_end >= req.u_start && xisspace(buf[req.u_end]); --req.u_end);
    }
    if (req.u_end < req.u_start) {
        request_parse_status = Http::scBadRequest; // missing URI
        return -1;
    }
    uri_.assign(&buf[req.u_start], req.u_end - req.u_start + 1);

    // Last whitespace SP = before start of protocol/version
    if (last_whitespace >= line_end) {
        request_parse_status = Http::scBadRequest; // missing version
        return -1;
    }
    req.v_start = last_whitespace + 1;
    req.v_end = line_end;

    // We only accept HTTP protocol requests right now.
    // TODO: accept other protocols; RFC 2326 (RTSP protocol) etc
    if ((req.v_end - req.v_start +1) < 5 || strncasecmp(&buf[req.v_start], "HTTP/", 5) != 0) {
#if USE_HTTP_VIOLATIONS
        // being lax; old parser accepted strange versions
        // there is a LOT of cases which are ambiguous, therefore we cannot use relaxed_header_parser here.
        msgProtocol_ = Http::ProtocolVersion(0,9);
        req.u_end = line_end;
        request_parse_status = Http::scOkay; // treat as HTTP/0.9
        return 1;
#else
        // protocol not supported / implemented.
        request_parse_status = Http::scHttpVersionNotSupported;
        return -1;
#endif
    }
    msgProtocol_.protocol = AnyP::PROTO_HTTP;

    int i = req.v_start + sizeof("HTTP/") -1;

    /* next should be 1 or more digits */
    if (!isdigit(buf[i])) {
        request_parse_status = Http::scHttpVersionNotSupported;
        return -1;
    }
    int maj = 0;
    for (; i <= line_end && (isdigit(buf[i])) && maj < 65536; ++i) {
        maj = maj * 10;
        maj = maj + (buf[i]) - '0';
    }
    // catch too-big values or missing remainders
    if (maj >= 65536 || i > line_end) {
        request_parse_status = Http::scHttpVersionNotSupported;
        return -1;
    }
    msgProtocol_.major = maj;

    /* next should be .; we -have- to have this as we have a whole line.. */
    if (buf[i] != '.') {
        request_parse_status = Http::scHttpVersionNotSupported;
        return -1;
    }
    // catch missing minor part
    if (++i > line_end) {
        request_parse_status = Http::scHttpVersionNotSupported;
        return -1;
    }
    /* next should be one or more digits */
    if (!isdigit(buf[i])) {
        request_parse_status = Http::scHttpVersionNotSupported;
        return -1;
    }
    int min = 0;
    for (; i <= line_end && (isdigit(buf[i])) && min < 65536; ++i) {
        min = min * 10;
        min = min + (buf[i]) - '0';
    }
    // catch too-big values or trailing garbage
    if (min >= 65536 || i < line_end) {
        request_parse_status = Http::scHttpVersionNotSupported;
        return -1;
    }
    msgProtocol_.minor = min;

    /* RFC 2616 section 10.5.6 : handle unsupported HTTP major versions cleanly. */
    /* We currently only support 0.9, 1.0, 1.1 properly in this parser */
    if ((maj == 0 && min != 9) || (maj > 1)) {
        request_parse_status = Http::scHttpVersionNotSupported;
        return -1;
    }

    /*
     * Rightio - we have all the schtuff. Return true; we've got enough.
     */
    request_parse_status = Http::scOkay;
    return 1;
}
#include <cstdio>
bool
Http::One::RequestParser::parse()
{
    // stage 1: locate the request-line
    if (parsingStage_ == HTTP_PARSE_NEW) {
fprintf(stderr, "parse GARBAGE: '%s'\n", buf);
        skipGarbageLines();
fprintf(stderr, "parse GBG A(%d) < B(%u)\n", bufsiz, parseOffset_);

        // if we hit something before EOS treat it as a message
        if ((size_t)bufsiz > parseOffset_)
            parsingStage_ = HTTP_PARSE_FIRST;
        else
            return false;
    }

    // stage 2: parse the request-line
    if (parsingStage_ == HTTP_PARSE_FIRST) {
fprintf(stderr, "parse FIRST: '%s'\n", buf);
        PROF_start(HttpParserParseReqLine);
        const int retcode = parseRequestFirstLine();
        debugs(74, 5, "request-line: retval " << retcode << ": from " << req.start << "->" << req.end << " " << Raw("line", &buf[req.start], req.end-req.start));
        debugs(74, 5, "request-line: method " << req.m_start << "->" << req.m_end << " (" << method_ << ")");
        debugs(74, 5, "request-line: url " << req.u_start << "->" << req.u_end << " (" << uri_ << ")");
        debugs(74, 5, "request-line: proto " << req.v_start << "->" << req.v_end << " (" << msgProtocol_ << ")");
        debugs(74, 5, "Parser: parse-offset=" << parseOffset_);
        PROF_stop(HttpParserParseReqLine);

        // syntax errors already
        if (retcode < 0) {
            parsingStage_ = HTTP_PARSE_DONE;
fprintf(stderr, "parse FIRST DONE (error)\n");
            return false;
        }

        // first-line (or a look-alike) found successfully.
        if (retcode > 0) {
            parseOffset_ += firstLineSize(); // first line bytes including CRLF terminator are now done.
            parsingStage_ = HTTP_PARSE_MIME;
fprintf(stderr, "parse FIRST (next: MIME)\n");
        }
else fprintf(stderr, "parse FIRST: ret=%d\n",retcode);
    }

    // stage 3: locate the mime header block
    if (parsingStage_ == HTTP_PARSE_MIME) {
fprintf(stderr, "parse MIME: '%s'\n", buf);
        // HTTP/1.x request-line is valid and parsing completed.
        if (msgProtocol_.major == 1) {
            /* NOTE: HTTP/0.9 requests do not have a mime header block.
             *       So the rest of the code will need to deal with '0'-byte headers
             *       (ie, none, so don't try parsing em)
             */
            int64_t mimeHeaderBytes = 0;
            if ((mimeHeaderBytes = headersEnd(buf+parseOffset_, bufsiz-parseOffset_)) == 0) {
                if (bufsiz-parseOffset_ >= Config.maxRequestHeaderSize) {
                    debugs(33, 5, "Too large request");
                    request_parse_status = Http::scHeaderTooLarge;
                    parsingStage_ = HTTP_PARSE_DONE;
fprintf(stderr, "parse DONE: HTTP/1.x\n");
                } else {
                    debugs(33, 5, "Incomplete request, waiting for end of headers");
fprintf(stderr, "parse MIME incomplete\n");
}                return false;
            }
            mimeHeaderBlock_.assign(&buf[req.end+1], mimeHeaderBytes);
            parseOffset_ += mimeHeaderBytes; // done with these bytes now.

        } else {
            debugs(33, 3, "Missing HTTP/1.x identifier");
fprintf(stderr, "parse MIME: HTTP/0.9\n");
}
        // NP: we do not do any further stages here yet so go straight to DONE
        parsingStage_ = HTTP_PARSE_DONE;

        // Squid could handle these headers, but admin does not want to
        if (messageHeaderSize() >= Config.maxRequestHeaderSize) {
            debugs(33, 5, "Too large request");
            request_parse_status = Http::scHeaderTooLarge;
            return false;
        }
    }

    return isDone();
}

// arbitrary maximum-length for headers which can be found by Http1Parser::getHeaderField()
#define GET_HDR_SZ	1024

char *
Http::One::Parser::getHeaderField(const char *name)
{
    LOCAL_ARRAY(char, header, GET_HDR_SZ);
    const char *p = NULL;
    char *q = NULL;
    char got = 0;
    const int namelen = name ? strlen(name) : 0;

    if (!headerBlockSize() || !name)
        return NULL;

    debugs(25, 5, "looking for '" << name << "'");

    for (p = rawHeaderBuf(); *p; p += strcspn(p, "\n\r")) {
        if (strcmp(p, "\r\n\r\n") == 0 || strcmp(p, "\n\n") == 0)
            return NULL;

        while (xisspace(*p))
            ++p;

        if (strncasecmp(p, name, namelen))
            continue;

        if (!xisspace(p[namelen]) && p[namelen] != ':')
            continue;

        int l = strcspn(p, "\n\r") + 1;

        if (l > GET_HDR_SZ)
            l = GET_HDR_SZ;

        xstrncpy(header, p, l);

        debugs(25, 5, "checking '" << header << "'");

        q = header;

        q += namelen;

        if (*q == ':') {
            ++q;
            got = 1;
        }

        while (xisspace(*q)) {
            ++q;
            got = 1;
        }

        if (got) {
            debugs(25, 5, "returning '" << q << "'");
            return q;
        }
    }

    return NULL;
}
