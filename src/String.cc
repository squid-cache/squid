
/*
 * $Id: String.cc,v 1.10 2002/02/13 17:22:36 hno Exp $
 *
 * DEBUG: section 67    String
 * AUTHOR: Duane Wessels
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

static void
stringInitBuf(String * s, size_t sz)
{
    s->buf = memAllocString(sz, &sz);
    assert(sz < 65536);
    s->size = sz;
}

void
stringInit(String * s, const char *str)
{
    assert(s);
    if (str)
	stringLimitInit(s, str, strlen(str));
    else
	*s = StringNull;
}

void
stringLimitInit(String * s, const char *str, int len)
{
    assert(s && str);
    stringInitBuf(s, len + 1);
    s->len = len;
    xmemcpy(s->buf, str, len);
    s->buf[len] = '\0';
}

String
stringDup(const String * s)
{
    String dup;
    assert(s);
    stringInit(&dup, s->buf);
    return dup;
}

void
stringClean(String * s)
{
    assert(s);
    if (s->buf)
	memFreeString(s->size, s->buf);
    *s = StringNull;
}

void
stringReset(String * s, const char *str)
{
    stringClean(s);
    stringInit(s, str);
}

void
stringAppend(String * s, const char *str, int len)
{
    assert(s);
    assert(str && len >= 0);
    if (s->len + len < s->size) {
	strncat(s->buf, str, len);
	s->len += len;
    } else {
	String snew = StringNull;
	snew.len = s->len + len;
	stringInitBuf(&snew, snew.len + 1);
	if (s->buf)
	    xmemcpy(snew.buf, s->buf, s->len);
	if (len)
	    xmemcpy(snew.buf + s->len, str, len);
	snew.buf[snew.len] = '\0';
	stringClean(s);
	*s = snew;
    }
}
