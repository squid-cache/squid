/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "HttpParser.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"

void
HttpParser::clear()
{
    state = HTTP_PARSE_NONE;
    request_parse_status = Http::scNone;
    buf = NULL;
    bufsiz = 0;
    req.start = req.end = -1;
    hdr_start = hdr_end = -1;
    req.m_start = req.m_end = -1;
    req.u_start = req.u_end = -1;
    req.v_start = req.v_end = -1;
    req.v_maj = req.v_min = 0;
}

void
HttpParser::reset(const char *aBuf, int len)
{
    clear(); // empty the state.
    state = HTTP_PARSE_NEW;
    buf = aBuf;
    bufsiz = len;
    debugs(74, 5, HERE << "Request buffer is " << buf);
}

int
HttpParser::parseRequestFirstLine()
{
    int second_word = -1; // track the suspected URI start
    int first_whitespace = -1, last_whitespace = -1; // track the first and last SP byte
    int line_end = -1; // tracks the last byte BEFORE terminal \r\n or \n sequence

    debugs(74, 5, HERE << "parsing possible request: " << buf);

    // Single-pass parse: (provided we have the whole line anyways)

    req.start = 0;
    if (Config.onoff.relaxed_header_parser) {
        if (Config.onoff.relaxed_header_parser < 0 && buf[req.start] == ' ')
            debugs(74, DBG_IMPORTANT, "WARNING: Invalid HTTP Request: " <<
                   "Whitespace bytes received ahead of method. " <<
                   "Ignored due to relaxed_header_parser.");
        // Be tolerant of prefix spaces (other bytes are valid method values)
        for (; req.start < bufsiz && buf[req.start] == ' '; ++req.start);
    }
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
        debugs(74, 5, "Parser: retval 0: from " << req.start <<
               "->" << req.end << ": needs more data to complete first line.");
        return 0;
    }

    // NP: we have now seen EOL, more-data (0) cannot occur.
    //     From here on any failure is -1, success is 1

    // Input Validation:

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

    // First non-whitespace after first SP = beginning of URL+Version
    if (second_word > line_end || second_word < req.start) {
        request_parse_status = Http::scBadRequest; // missing URI
        return -1;
    }
    req.u_start = second_word;

    // RFC 1945: SP and version following URI are optional, marking version 0.9
    // we identify this by the last whitespace being earlier than URI start
    if (last_whitespace < second_word && last_whitespace >= req.start) {
        req.v_maj = 0;
        req.v_min = 9;
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
        req.v_maj = 0;
        req.v_min = 9;
        req.u_end = line_end;
        request_parse_status = Http::scOkay; // treat as HTTP/0.9
        return 1;
#else
        // protocol not supported / implemented.
        request_parse_status = Http::scHttpVersionNotSupported;
        return -1;
#endif
    }

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
    req.v_maj = maj;

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
    req.v_min = min;

    /*
     * Rightio - we have all the schtuff. Return true; we've got enough.
     */
    request_parse_status = Http::scOkay;
    return 1;
}

int
HttpParserParseReqLine(HttpParser *hmsg)
{
    PROF_start(HttpParserParseReqLine);
    int retcode = hmsg->parseRequestFirstLine();
    debugs(74, 5, "Parser: retval " << retcode << ": from " << hmsg->req.start <<
           "->" << hmsg->req.end << ": method " << hmsg->req.m_start << "->" <<
           hmsg->req.m_end << "; url " << hmsg->req.u_start << "->" << hmsg->req.u_end <<
           "; version " << hmsg->req.v_start << "->" << hmsg->req.v_end << " (" << hmsg->req.v_maj <<
           "/" << hmsg->req.v_min << ")");
    PROF_stop(HttpParserParseReqLine);
    return retcode;
}

#if MSGDODEBUG
/* XXX This should eventually turn into something inlined or #define'd */
int
HttpParserReqSz(HttpParser *hp)
{
    assert(hp->state == HTTP_PARSE_NEW);
    assert(hp->req.start != -1);
    assert(hp->req.end != -1);
    return hp->req.end - hp->req.start + 1;
}

/*
 * This +1 makes it 'right' but won't make any sense if
 * there's a 0 byte header? This won't happen normally - a valid header
 * is at -least- a blank line (\n, or \r\n.)
 */
int
HttpParserHdrSz(HttpParser *hp)
{
    assert(hp->state == HTTP_PARSE_NEW);
    assert(hp->hdr_start != -1);
    assert(hp->hdr_end != -1);
    return hp->hdr_end - hp->hdr_start + 1;
}

const char *
HttpParserHdrBuf(HttpParser *hp)
{
    assert(hp->state == HTTP_PARSE_NEW);
    assert(hp->hdr_start != -1);
    assert(hp->hdr_end != -1);
    return hp->buf + hp->hdr_start;
}

int
HttpParserRequestLen(HttpParser *hp)
{
    return hp->hdr_end - hp->req.start + 1;
}
#endif

