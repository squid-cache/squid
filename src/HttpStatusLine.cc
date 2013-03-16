
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
    httpStatusLineSet(sline, version, Http::scNone, NULL);
}

void
httpStatusLineClean(HttpStatusLine * sline)
{
    HttpVersion version;
    httpStatusLineSet(sline, version, Http::scInternalServerError, NULL);
}

/* set values */
void
httpStatusLineSet(HttpStatusLine * sline, HttpVersion version, Http::StatusCode status, const char *reason)
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
    sline->status = Http::scInvalidHeader;	/* Squid header parsing error */

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

    sline->status = static_cast<Http::StatusCode>(atoi(++start));

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
httpStatusString(Http::StatusCode status)
{
    /* why not to return matching string instead of using "p" ? @?@ */
    const char *p = NULL;

    switch (status) {

    case 0:
        p = "Init";		/* we init .status with code 0 */
        break;

    case Http::scContinue:
        p = "Continue";
        break;

    case Http::scSwitchingProtocols:
        p = "Switching Protocols";
        break;

    case Http::scOkay:
        p = "OK";
        break;

    case Http::scCreated:
        p = "Created";
        break;

    case Http::scAccepted:
        p = "Accepted";
        break;

    case Http::scNonAuthoritativeInformation:
        p = "Non-Authoritative Information";
        break;

    case Http::scNoContent:
        p = "No Content";
        break;

    case Http::scResetContent:
        p = "Reset Content";
        break;

    case Http::scPartialContent:
        p = "Partial Content";
        break;

    case Http::scMultiStatus:
        p = "Multi-Status";
        break;

    case Http::scMultipleChoices:
        p = "Multiple Choices";
        break;

    case Http::scMovedPermanently:
        p = "Moved Permanently";
        break;

    case Http::scMovedTemporarily:
        p = "Moved Temporarily";
        break;

    case Http::scSeeOther:
        p = "See Other";
        break;

    case Http::scNotModified:
        p = "Not Modified";
        break;

    case Http::scUseProxy:
        p = "Use Proxy";
        break;

    case Http::scTemporaryRedirect:
        p = "Temporary Redirect";
        break;

    case Http::scPermanentRedirect:
        p = "Permanent Redirect";
        break;

    case Http::scBadRequest:
        p = "Bad Request";
        break;

    case Http::scUnauthorized:
        p = "Unauthorized";
        break;

    case Http::scPaymentRequired:
        p = "Payment Required";
        break;

    case Http::scForbidden:
        p = "Forbidden";
        break;

    case Http::scNotFound:
        p = "Not Found";
        break;

    case Http::scMethodNotAllowed:
        p = "Method Not Allowed";
        break;

    case Http::scNotAcceptable:
        p = "Not Acceptable";
        break;

    case Http::scProxyAuthenticationRequired:
        p = "Proxy Authentication Required";
        break;

    case Http::scRequestTimeout:
        p = "Request Time-out";
        break;

    case Http::scConflict:
        p = "Conflict";
        break;

    case Http::scGone:
        p = "Gone";
        break;

    case Http::scLengthRequired:
        p = "Length Required";
        break;

    case Http::scPreconditionFailed:
        p = "Precondition Failed";
        break;

    case Http::scRequestEntityTooLarge:
        p = "Request Entity Too Large";
        break;

    case Http::scRequestUriTooLarge:
        p = "Request-URI Too Large";
        break;

    case Http::scUnsupportedMediaType:
        p = "Unsupported Media Type";
        break;

    case Http::scRequestedRangeNotSatisfied:
        p = "Requested Range Not Satisfiable";
        break;

    case Http::scExpectationFailed:
        p = "Expectation Failed";
        break;

    case Http::scInternalServerError:
        p = "Internal Server Error";
        break;

    case Http::scNotImplemented:
        p = "Not Implemented";
        break;

    case Http::scBadGateway:
        p = "Bad Gateway";
        break;

    case Http::scServiceUnavailable:
        p = "Service Unavailable";
        break;

    case Http::scGateway_Timeout:
        p = "Gateway Time-out";
        break;

    case Http::scHttpVersionNotSupported:
        p = "HTTP Version not supported";
        break;

        // RFC 6585
    case Http::scPreconditionRequired: // 428
        p = "Precondition Required";
        break;

    case Http::scTooManyFields: // 429
        p = "Too Many Requests";
        break;

    case Http::scRequestHeaderFieldsTooLarge: // 431
        p = "Request Header Fields Too Large";
        break;

    case Http::scNetworkAuthenticationRequired: // 511
        p = "Network Authentication Required";
        break;

    default:
        p = "Unknown";
        debugs(57, 3, "Unknown HTTP status code: " << status);
        break;
    }

    return p;
}
