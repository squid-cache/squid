
/*
 * $Id: HttpStatusLine.h,v 1.2 2005/09/12 23:28:57 wessels Exp $
 *
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_HTTPSTATUSLINE_H
#define SQUID_HTTPSTATUSLINE_H

#include "HttpVersion.h"

class HttpStatusLine
{

public:
    /* public, read only */
    HttpVersion version;
    const char *reason;		/* points to a _constant_ string (default or supplied), never free()d */
    http_status status;
};

/* init/clean */
SQUIDCEXTERN void httpStatusLineInit(HttpStatusLine * sline);
SQUIDCEXTERN void httpStatusLineClean(HttpStatusLine * sline);
/* set/get values */
SQUIDCEXTERN void httpStatusLineSet(HttpStatusLine * sline, HttpVersion version,
                                    http_status status, const char *reason);
SQUIDCEXTERN const char *httpStatusLineReason(const HttpStatusLine * sline);
/* parse/pack */
/* parse a 0-terminating buffer and fill internal structires; returns true on success */
SQUIDCEXTERN int httpStatusLineParse(HttpStatusLine * sline, const String &protoPrefix,
                                     const char *start, const char *end);
/* pack fields using Packer */
SQUIDCEXTERN void httpStatusLinePackInto(const HttpStatusLine * sline, Packer * p);

#endif /* SQUID_HTTPSTATUSLINE_H */
