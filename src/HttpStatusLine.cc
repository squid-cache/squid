/*
 * $Id: HttpStatusLine.cc,v 1.5 1998/02/26 18:00:32 wessels Exp $
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

/* parse a 0-terminating buffer and fill internal structires; returns true on success */
void
httpStatusLinePackInto(const HttpStatusLine * sline, Packer * p)
{
    assert(sline && p);
    tmp_debug(here) ("packing sline %p using %p:\n", sline, p);
    tmp_debug(here) (HttpStatusLineFormat, sline->version, sline->status,
	sline->reason ? sline->reason : httpStatusString(sline->status));
    packerPrintf(p, HttpStatusLineFormat,
	sline->version, sline->status,
	sline->reason ? sline->reason : httpStatusString(sline->status));
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

static const char *
httpStatusString(http_status status)
{
    /* why not to return matching string instead of using "p" ? @?@ */
    const char *p = NULL;
    switch (status) {
    case 0:
	p = "Init";		/* we init .status with code 0 */
	break;
    case 100:
	p = "Continue";
	break;
    case 101:
	p = "Switching Protocols";
	break;
    case 200:
	p = "OK";
	break;
    case 201:
	p = "Created";
	break;
    case 202:
	p = "Accepted";
	break;
    case 203:
	p = "Non-Authoritative Information";
	break;
    case 204:
	p = "No Content";
	break;
    case 205:
	p = "Reset Content";
	break;
    case 206:
	p = "Partial Content";
	break;
    case 300:
	p = "Multiple Choices";
	break;
    case 301:
	p = "Moved Permanently";
	break;
    case 302:
	p = "Moved Temporarily";
	break;
    case 303:
	p = "See Other";
	break;
    case 304:
	p = "Not Modified";
	break;
    case 305:
	p = "Use Proxy";
	break;
    case 400:
	p = "Bad Request";
	break;
    case 401:
	p = "Unauthorized";
	break;
    case 402:
	p = "Payment Required";
	break;
    case 403:
	p = "Forbidden";
	break;
    case 404:
	p = "Not Found";
	break;
    case 405:
	p = "Method Not Allowed";
	break;
    case 406:
	p = "Not Acceptable";
	break;
    case 407:
	p = "Proxy Authentication Required";
	break;
    case 408:
	p = "Request Time-out";
	break;
    case 409:
	p = "Conflict";
	break;
    case 410:
	p = "Gone";
	break;
    case 411:
	p = "Length Required";
	break;
    case 412:
	p = "Precondition Failed";
	break;
    case 413:
	p = "Request Entity Too Large";
	break;
    case 414:
	p = "Request-URI Too Large";
	break;
    case 415:
	p = "Unsupported Media Type";
	break;
    case 500:
	p = "Internal Server Error";
	break;
    case 501:
	p = "Not Implemented";
	break;
    case 502:
	p = "Bad Gateway";
	break;
    case 503:
	p = "Service Unavailable";
	break;
    case 504:
	p = "Gateway Time-out";
	break;
    case 505:
	p = "HTTP Version not supported";
	break;
    default:
	p = "Unknown";
	debug(11, 0) ("Unknown HTTP status code: %d\n", status);
	break;
    }
    return p;
}
