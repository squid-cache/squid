
/*
 * $Id: HttpStatusLine.cc,v 1.12 1998/06/03 15:52:16 rousskov Exp $
 *
 * DEBUG: section 57    HTTP Status-line
 * AUTHOR: Alex Rousskov
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"


/* local constants */
const char *HttpStatusLineFormat = "HTTP/%3.1f %3d %s\r\n";

/* local routines */
static const char *httpStatusString(http_status status);



void
httpStatusLineInit(HttpStatusLine * sline)
{
    httpStatusLineSet(sline, 0.0, 0, NULL);
}

void
httpStatusLineClean(HttpStatusLine * sline)
{
    httpStatusLineSet(sline, 0.0, 500, NULL);
}

/* set values */
void
httpStatusLineSet(HttpStatusLine * sline, double version, http_status status, const char *reason)
{
    assert(sline);
    sline->version = version;
    sline->status = status;
    /* Note: no xstrdup for 'reason', assumes constant 'reasons' */
    sline->reason = reason;
}

/* parse a 0-terminating buffer and fill internal structures; returns true on success */
void
httpStatusLinePackInto(const HttpStatusLine * sline, Packer * p)
{
    assert(sline && p);
    debug(57, 9) ("packing sline %p using %p:\n", sline, p);
    debug(57, 9) (HttpStatusLineFormat, sline->version, sline->status,
	sline->reason ? sline->reason : httpStatusString(sline->status));
    packerPrintf(p, HttpStatusLineFormat,
	sline->version, sline->status, httpStatusLineReason(sline));
}

/* pack fields using Packer */
int
httpStatusLineParse(HttpStatusLine * sline, const char *start, const char *end)
{
    assert(sline);
    sline->status = HTTP_INVALID_HEADER;	/* Squid header parsing error */
    if (strncasecmp(start, "HTTP/", 5))
	return 0;
    start += 5;
    if (!isdigit(*start))
	return 0;
    sline->version = atof(start);
    if (!(start = strchr(start, ' ')))
	return 0;
    sline->status = atoi(++start);
    /* we ignore 'reason-phrase' */
    return 1;			/* success */
}

const char *
httpStatusLineReason(const HttpStatusLine * sline)
{
    assert(sline);
    return sline->reason ? sline->reason : httpStatusString(sline->status);
}

static const char *
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
    default:
	p = "Unknown";
	debug(57, 0) ("Unknown HTTP status code: %d\n", status);
	break;
    }
    return p;
}
