#include "squid.h"
#include "Debug.h"
#include "http/one/RequestParser.h"
#include "http/ProtocolVersion.h"
#include "mime_header.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"

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
        if (Config.onoff.relaxed_header_parser < 0 && (buf[0] == '\r' || buf[0] == '\n'))
            debugs(74, DBG_IMPORTANT, "WARNING: Invalid HTTP Request: " <<
                   "CRLF bytes received ahead of request-line. " <<
                   "Ignored due to relaxed_header_parser.");
        // Be tolerant of prefix empty lines
        // ie any series of either \n or \r\n with no other characters and no repeated \r
        while (!buf.isEmpty() && (buf[0] == '\n' || (buf[0] == '\r' && buf[1] == '\n'))) {
            buf.consume(1);
        }
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
        if (Config.onoff.relaxed_header_parser < 0 && buf[0] == ' ')
            debugs(74, DBG_IMPORTANT, "WARNING: Invalid HTTP Request: " <<
                   "Whitespace bytes received ahead of method. " <<
                   "Ignored due to relaxed_header_parser.");
        // Be tolerant of prefix spaces (other bytes are valid method values)
        while (!buf.isEmpty() && buf[0] == ' ') {
            buf.consume(1);
        }
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

    debugs(74, 5, "parsing possible request: buf.length=" << buf.length());
    debugs(74, DBG_DATA, buf);

    // Single-pass parse: (provided we have the whole line anyways)

    req.start = 0;
    req.end = -1;
    for (SBuf::size_type i = 0; i < buf.length(); ++i) {
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
        if (i < buf.length() - 1 && buf[i] == '\r') {
            if (Config.onoff.relaxed_header_parser) {
                if (Config.onoff.relaxed_header_parser < 0 && buf[i + 1] == '\r')
                    debugs(74, DBG_IMPORTANT, "WARNING: Invalid HTTP Request: " <<
                           "Series of carriage-return bytes received prior to line terminator. " <<
                           "Ignored due to relaxed_header_parser.");

                // Be tolerant of invalid multiple \r prior to terminal \n
                if (buf[i + 1] == '\n' || buf[i + 1] == '\r')
                    line_end = i - 1;
                while (i < buf.length() - 1 && buf[i + 1] == '\r')
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
        if ((size_t)buf.length() >= Config.maxRequestHeaderSize) {
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
    SBuf tmp = buf.substr(req.m_start, req.m_end - req.m_start + 1);
    method_ = HttpRequestMethod(tmp);

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
        uri_ = buf.substr(req.u_start, req.u_end - req.u_start + 1);
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
    uri_ = buf.substr(req.u_start, req.u_end - req.u_start + 1);

    // Last whitespace SP = before start of protocol/version
    if (last_whitespace >= line_end) {
        request_parse_status = Http::scBadRequest; // missing version
        return -1;
    }
    req.v_start = last_whitespace + 1;
    req.v_end = line_end;

    // We only accept HTTP protocol requests right now.
    // TODO: accept other protocols; RFC 2326 (RTSP protocol) etc
    if ((req.v_end - req.v_start +1) < 5 || buf.substr(req.v_start, 5).caseCmp(SBuf("HTTP/")) != 0) {
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

bool
Http::One::RequestParser::parse(const SBuf &aBuf)
{
    buf = aBuf;
    debugs(74, DBG_DATA, "Parse buf={length=" << aBuf.length() << ", data='" << aBuf << "'}");

    // stage 1: locate the request-line
    if (parsingStage_ == HTTP_PARSE_NONE) {
        skipGarbageLines();

        // if we hit something before EOS treat it as a message
        if (!buf.isEmpty())
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
            buf.consume(firstLineSize()); // first line bytes including CRLF terminator are now done.
            parsingStage_ = HTTP_PARSE_MIME;
        }

        debugs(74, 5, "request-line: retval " << retcode << ": from " << req.start << "->" << req.end <<
               " line={" << aBuf.length() << ", data='" << aBuf << "'}");
        debugs(74, 5, "request-line: method " << req.m_start << "->" << req.m_end << " (" << method_ << ")");
        debugs(74, 5, "request-line: url " << req.u_start << "->" << req.u_end << " (" << uri_ << ")");
        debugs(74, 5, "request-line: proto " << req.v_start << "->" << req.v_end << " (" << msgProtocol_ << ")");
        debugs(74, 5, "Parser: bytes processed=" << (aBuf.length()-buf.length()));
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
            if ((mimeHeaderBytes = headersEnd(buf.c_str(), buf.length())) == 0) {
                if (buf.length()+firstLineSize() >= Config.maxRequestHeaderSize) {
                    debugs(33, 5, "Too large request");
                    request_parse_status = Http::scHeaderTooLarge;
                    parsingStage_ = HTTP_PARSE_DONE;
                } else
                    debugs(33, 5, "Incomplete request, waiting for end of headers");
                return false;
            }
            mimeHeaderBlock_ = buf.substr(req.end+1, mimeHeaderBytes);
            buf.consume(mimeHeaderBytes); // done with these bytes now.

        } else
            debugs(33, 3, "Missing HTTP/1.x identifier");

        // NP: we do not do any further stages here yet so go straight to DONE
        parsingStage_ = HTTP_PARSE_DONE;

        // Squid could handle these headers, but admin does not want to
        if (messageHeaderSize() >= Config.maxRequestHeaderSize) {
            debugs(33, 5, "Too large request");
            request_parse_status = Http::scHeaderTooLarge;
            return false;
        }
    }

    return !needsMoreData();
}
