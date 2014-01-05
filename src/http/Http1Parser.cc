#include "squid.h"
#include "Debug.h"
#include "http/Http1Parser.h"
#include "http/RequestMethod.h"
#include "mime_header.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"

void
Http1::Parser::clear()
{
    completedState_ = HTTP_PARSE_NONE;
    buf = NULL;
    bufsiz = 0;
    parseOffset_ = 0;
    msgProtocol_ = AnyP::ProtocolVersion();
    mimeHeaderBlock_.clear();
}

void
Http1::RequestParser::clear()
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
Http1::Parser::reset(const char *aBuf, int len)
{
    clear(); // empty the state.
    completedState_ = HTTP_PARSE_NEW;
    buf = aBuf;
    bufsiz = len;
    debugs(74, DBG_DATA, "Parse " << Raw("buf", buf, bufsiz));
}

void
Http1::RequestParser::noteBufferShift(int64_t n)
{
    bufsiz -= n;

    // if parsing done, ignore buffer changes.
    if (completedState_ == HTTP_PARSE_DONE)
        return;

    // shift the parser resume point to match buffer content
    parseOffset_ -= n;

#if WHEN_INCREMENTAL_PARSING

    // if have not yet finished request-line
    if (completedState_ == HTTP_PARSE_NEW) {
        // check for and adjust the known request-line offsets.

        /* TODO: when the first-line is parsed incrementally we
         * will need to recalculate the offsets for req.*
         * For now, they are all re-calculated based on parserOffset_
         * with each parse attempt.
         */
    }

    // if finished request-line but not mime header
    // adjust the mime header states
    if (completedState_ == HTTP_PARSE_FIRST) {
        /* TODO: when the mime-header is parsed incrementally we
         * will need to store the initial offset of mime-header block
         * instead of locatign it from req.end or parseOffset_.
         * Since req.end may no longer be valid, and parseOffset_ may
         * have moved into the mime-block interior.
         */
    }
#endif
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
 * \return true if garbage whitespace was found
 */
bool
Http1::RequestParser::skipGarbageLines()
{
    req.start = parseOffset_; // avoid re-parsing any portion we managed to complete

#if WHEN_RFC_COMPLIANT // CRLF or bare-LF is what RFC 2616 tolerant parsers do ...
    if (Config.onoff.relaxed_header_parser) {
        if (Config.onoff.relaxed_header_parser < 0 && (buf[req.start] == '\r' || buf[req.start] == '\n'))
            debugs(74, DBG_IMPORTANT, "WARNING: Invalid HTTP Request: " <<
                   "CRLF bytes received ahead of request-line. " <<
                   "Ignored due to relaxed_header_parser.");
        // Be tolerant of prefix empty lines
        for (; req.start < bufsiz && (buf[req.start] == '\n' || ((buf[req.start] == '\r' && (buf[req.start+1] == '\n')); ++req.start);
        parseOffset_ = req.start;
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
        if (Config.onoff.relaxed_header_parser < 0 && buf[req.start] == ' ')
            debugs(74, DBG_IMPORTANT, "WARNING: Invalid HTTP Request: " <<
                   "Whitespace bytes received ahead of method. " <<
                   "Ignored due to relaxed_header_parser.");
        // Be tolerant of prefix spaces (other bytes are valid method values)
        for (; req.start < bufsiz && buf[req.start] == ' '; ++req.start);
        parseOffset_ = req.start;
    }
#endif

    return (parseOffset_ > 0);
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
Http1::RequestParser::parseRequestFirstLine()
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
        completedState_ = HTTP_PARSE_FIRST;
        parseOffset_ = line_end;
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
        completedState_ = HTTP_PARSE_FIRST;
        parseOffset_ = req.end;
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
    parseOffset_ = req.end+1; // req.end is the \n byte. Next parse step needs to start *after* that byte.
    completedState_ = HTTP_PARSE_FIRST;
    return 1;
}

bool
Http1::RequestParser::parse()
{
    // stage 1: locate the request-line
    if (completedState_ == HTTP_PARSE_NEW) {
        if (skipGarbageLines() && (size_t)bufsiz < parseOffset_)
            return false;
    }

    // stage 2: parse the request-line
    if (completedState_ == HTTP_PARSE_NEW) {
        PROF_start(HttpParserParseReqLine);
        int retcode = parseRequestFirstLine();
        debugs(74, 5, "request-line: retval " << retcode << ": from " << req.start << "->" << req.end << " " << Raw("line", &buf[req.start], req.end-req.start));
        debugs(74, 5, "request-line: method " << req.m_start << "->" << req.m_end << " (" << method_ << ")");
        debugs(74, 5, "request-line: url " << req.u_start << "->" << req.u_end << " (" << uri_ << ")");
        debugs(74, 5, "request-line: proto " << req.v_start << "->" << req.v_end << " (" << msgProtocol_ << ")");
        debugs(74, 5, "Parser: parse-offset=" << parseOffset_);
        PROF_stop(HttpParserParseReqLine);
        if (retcode < 0) {
            completedState_ = HTTP_PARSE_DONE;
            return false;
        }
    }

    // stage 3: locate the mime header block
    if (completedState_ == HTTP_PARSE_FIRST) {
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
                    completedState_ = HTTP_PARSE_DONE;
                } else
                    debugs(33, 5, "Incomplete request, waiting for end of headers");
                return false;
            }
            mimeHeaderBlock_.assign(&buf[req.end+1], mimeHeaderBytes);

        } else
            debugs(33, 3, "Missing HTTP/1.x identifier");

        // NP: planned name for this stage is HTTP_PARSE_MIME
        // but we do not do any further stages here yet so go straight to DONE
        completedState_ = HTTP_PARSE_DONE;

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
Http1::Parser::getHeaderField(const char *name)
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
