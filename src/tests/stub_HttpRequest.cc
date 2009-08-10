/*
 * $Id$
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Robert Collins
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
#include "HttpRequest.h"


HttpRequest::HttpRequest() : HttpMsg(hoRequest)
{
    fatal("Not implemented");
}

HttpRequest::HttpRequest(const HttpRequestMethod& method, protocol_t protocol, const char *aUrlpath) : HttpMsg(hoRequest)
{
    fatal("Not implemented");
}

HttpRequest::~HttpRequest()
{}

void
HttpRequest::packFirstLineInto(Packer * p, bool full_uri) const
{
    fatal("Not implemented");
}

bool
HttpRequest::sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, http_status *error)
{
    fatal("Not implemented");
    return false;
}

void
HttpRequest::hdrCacheInit()
{
    fatal("Not implemented");
}

void
HttpRequest::reset()
{
    fatal("Not implemented");
}

bool
HttpRequest::expectingBody(const HttpRequestMethod& unused, int64_t&) const
{
    fatal("Not implemented");
    return false;
}

void
HttpRequest::initHTTP(const HttpRequestMethod& aMethod, protocol_t aProtocol, const char *aUrlpath)
{
    fatal("Not implemented");
}

bool
HttpRequest::parseFirstLine(const char *start, const char *end)
{
    fatal("Not implemented");
    return false;
}

HttpRequest *
HttpRequest::clone() const
{
    fatal("Not implemented");
    return NULL;
}

bool
HttpRequest::inheritProperties(const HttpMsg *aMsg)
{
    fatal("Not implemented");
    return false;
}

/*
 * DO NOT MODIFY:
 * arch-tag: dd894aa8-63cc-4543-92d9-1079a18bee11
 */
