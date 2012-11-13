
/*
 * DEBUG: section 57    HTTP Status-line
 * AUTHOR: Alex Rousskov
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "Debug.h"
#include "HttpStatusLine.h"
#include "Packer.h"

/* local constants */
/* AYJ: see bug 2469 - RFC2616 confirms stating 'SP characters' plural! */
const char *HttpStatusLineFormat = "HTTP/%d.%d %3d %s\r\n";
const char *IcyStatusLineFormat = "ICY %3d %s\r\n";

void
httpStatusLineInit(HttpStatusLine * sline)
{
    HttpVersion version;
    httpStatusLineSet(sline, version, HTTP_STATUS_NONE, NULL);
}

void
httpStatusLineClean(HttpStatusLine * sline)
{
    HttpVersion version;
    httpStatusLineSet(sline, version, HTTP_INTERNAL_SERVER_ERROR, NULL);
}

/* set values */
void
httpStatusLineSet(HttpStatusLine * sline, HttpVersion version, http_status status, const char *reason)
{
    assert(sline);
    sline->protocol = AnyP::PROTO_HTTP;
    sline->version = version;
    sline->status = status;
    /* Note: no xstrdup for 'reason', assumes constant 'reasons' */
    sline->reason = reason;
}

/**
 * Write HTTP version and status structures into a Packer buffer for output as HTTP status line.
 * Special exemption made for ICY response status lines.
 */
void
httpStatusLinePackInto(const HttpStatusLine * sline, Packer * p)
{
    assert(sline && p);

    /* handle ICY protocol status line specially. Pass on the bad format. */
    if (sline->protocol == AnyP::PROTO_ICY) {
        debugs(57, 9, "packing sline " << sline << " using " << p << ":");
        debugs(57, 9, "FORMAT=" << IcyStatusLineFormat );
        debugs(57, 9, "ICY " << sline->status << " " << (sline->reason ? sline->reason : httpStatusString(sline->status)) );
        packerPrintf(p, IcyStatusLineFormat, sline->status, httpStatusLineReason(sline));
        return;
    }

    debugs(57, 9, "packing sline " << sline << " using " << p << ":");
    debugs(57, 9, "FORMAT=" << HttpStatusLineFormat );
    debugs(57, 9, "HTTP/" << sline->version.major << "." << sline->version.minor <<
           " " << sline->status << " " << (sline->reason ? sline->reason : httpStatusString(sline->status)) );
    packerPrintf(p, HttpStatusLineFormat, sline->version.major,
                 sline->version.minor, sline->status, httpStatusLineReason(sline));
}

/*
 * Parse character string into 'sline'.  Note 'end' currently unused,
 * so NULL-termination assumed.
 */
int
httpStatusLineParse(HttpStatusLine * sline, const String &protoPrefix, const char *start, const char *end)
{
    assert(sline);
    sline->status = HTTP_INVALID_HEADER;	/* Squid header parsing error */

    // XXX: HttpMsg::parse() has a similar check but is using
    // casesensitive comparison (which is required by HTTP errata?)

    if (protoPrefix.cmp("ICY", 3) == 0) {
        debugs(57, 3, "httpStatusLineParse: Invalid HTTP identifier. Detected ICY protocol istead.");
        sline->protocol = AnyP::PROTO_ICY;
        start += protoPrefix.size();
    } else if (protoPrefix.caseCmp(start, protoPrefix.size()) == 0) {

        start += protoPrefix.size();

        if (!xisdigit(*start))
            return 0;

        if (sscanf(start, "%d.%d", &sline->version.major, &sline->version.minor) != 2) {
            debugs(57, 7, "httpStatusLineParse: Invalid HTTP identifier.");
        }
    } else
        return 0;

    if (!(start = strchr(start, ' ')))
        return 0;

    sline->status = (http_status) atoi(++start);

    /* we ignore 'reason-phrase' */
    /* Should assert start < end ? */
    return 1;			/* success */
}

const char *
httpStatusLineReason(const HttpStatusLine * sline)
{
    assert(sline);
    return sline->reason ? sline->reason : httpStatusString(sline->status);
}

const char *
httpStatusString(http_status status)
{
    /* why not to return matching string instead of using "p" ? @?@ */
    const char *p = NULL;

    switch (status) {

    case 0:
        p = "Init";		/* we init .status with code 0 */
        break;

    case HTTP_CONTINUE:
        p = "Continue";
        break;

    case HTTP_SWITCHING_PROTOCOLS:
        p = "Switching Protocols";
        break;

    case HTTP_OK:
        p = "OK";
        break;

    case HTTP_CREATED:
        p = "Created";
        break;

    case HTTP_ACCEPTED:
        p = "Accepted";
        break;

    case HTTP_NON_AUTHORITATIVE_INFORMATION:
        p = "Non-Authoritative Information";
        break;

    case HTTP_NO_CONTENT:
        p = "No Content";
        break;

    case HTTP_RESET_CONTENT:
        p = "Reset Content";
        break;

    case HTTP_PARTIAL_CONTENT:
        p = "Partial Content";
        break;

    case HTTP_MULTI_STATUS:
        p = "Multi-Status";
        break;

    case HTTP_MULTIPLE_CHOICES:
        p = "Multiple Choices";
        break;

    case HTTP_MOVED_PERMANENTLY:
        p = "Moved Permanently";
        break;

    case HTTP_MOVED_TEMPORARILY:
        p = "Moved Temporarily";
        break;

    case HTTP_SEE_OTHER:
        p = "See Other";
        break;

    case HTTP_NOT_MODIFIED:
        p = "Not Modified";
        break;

    case HTTP_USE_PROXY:
        p = "Use Proxy";
        break;

    case HTTP_TEMPORARY_REDIRECT:
        p = "Temporary Redirect";
        break;

    case HTTP_PERMANENT_REDIRECT:
        p = "Permanent Redirect";
        break;

    case HTTP_BAD_REQUEST:
        p = "Bad Request";
        break;

    case HTTP_UNAUTHORIZED:
        p = "Unauthorized";
        break;

    case HTTP_PAYMENT_REQUIRED:
        p = "Payment Required";
        break;

    case HTTP_FORBIDDEN:
        p = "Forbidden";
        break;

    case HTTP_NOT_FOUND:
        p = "Not Found";
        break;

    case HTTP_METHOD_NOT_ALLOWED:
        p = "Method Not Allowed";
        break;

    case HTTP_NOT_ACCEPTABLE:
        p = "Not Acceptable";
        break;

    case HTTP_PROXY_AUTHENTICATION_REQUIRED:
        p = "Proxy Authentication Required";
        break;

    case HTTP_REQUEST_TIMEOUT:
        p = "Request Time-out";
        break;

    case HTTP_CONFLICT:
        p = "Conflict";
        break;

    case HTTP_GONE:
        p = "Gone";
        break;

    case HTTP_LENGTH_REQUIRED:
        p = "Length Required";
        break;

    case HTTP_PRECONDITION_FAILED:
        p = "Precondition Failed";
        break;

    case HTTP_REQUEST_ENTITY_TOO_LARGE:
        p = "Request Entity Too Large";
        break;

    case HTTP_REQUEST_URI_TOO_LARGE:
        p = "Request-URI Too Large";
        break;

    case HTTP_UNSUPPORTED_MEDIA_TYPE:
        p = "Unsupported Media Type";
        break;

    case HTTP_REQUESTED_RANGE_NOT_SATISFIABLE:
        p = "Requested Range Not Satisfiable";
        break;

    case HTTP_EXPECTATION_FAILED:
        p = "Expectation Failed";
        break;

    case HTTP_INTERNAL_SERVER_ERROR:
        p = "Internal Server Error";
        break;

    case HTTP_NOT_IMPLEMENTED:
        p = "Not Implemented";
        break;

    case HTTP_BAD_GATEWAY:
        p = "Bad Gateway";
        break;

    case HTTP_SERVICE_UNAVAILABLE:
        p = "Service Unavailable";
        break;

    case HTTP_GATEWAY_TIMEOUT:
        p = "Gateway Time-out";
        break;

    case HTTP_HTTP_VERSION_NOT_SUPPORTED:
        p = "HTTP Version not supported";
        break;

        // RFC 6585
    case HTTP_PRECONDITION_REQUIRED: // 428
        p = "Precondition Required";
        break;

    case HTTP_TOO_MANY_REQUESTS: // 429
        p = "Too Many Requests";
        break;

    case HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE: // 431
        p = "Request Header Fields Too Large";
        break;

    case HTTP_NETWORK_AUTHENTICATION_REQUIRED: // 511
        p = "Network Authentication Required";
        break;

    default:
        p = "Unknown";
        debugs(57, 3, "Unknown HTTP status code: " << status);
        break;
    }

    return p;
}
