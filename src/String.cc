
/*
 * $Id: String.cc,v 1.6 1998/07/20 17:19:13 wessels Exp $
 *
 * DEBUG: section 67    String
 * AUTHOR: Duane Wessels
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *  
 */

#include "squid.h"

static void
stringInitBuf(String * s, size_t sz)
{
    s->buf = memAllocBuf(sz, &sz);
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
	memFreeBuf(s->size, s->buf);
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
