/*
 * $Id: String.cc,v 1.1 1998/03/08 07:53:13 rousskov Exp $
 *
 * DEBUG: section 61    String
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"


void
stringInit(String *s, const char *str)
{
    assert(s);
    if (str)
	stringLimitInit(s, str, strlen(str));
    else
	*s = StringNull;
}

void
stringLimitInit(String *s, const char *str, int len)
{
    size_t sz = len+1;
    assert(s && str);
    s->len = len;
    s->buf = memAllocBuf(sz, &sz);
    assert(sz < 65536);
    s->size = sz;
    xmemcpy(s->buf, str, len);
    s->buf[len] = '\0';
}

String
stringDup(const String *s)
{
    String dup;
    assert(s);
    stringInit(&dup, s->buf);
    return dup;
}

void
stringClean(String *s)
{
    assert(s);
    if (s->buf)
	memFreeBuf(s->size, s->buf);
    *s = StringNull;
}

void
stringReset(String *s, const char *str)
{
    stringClean(s);
    stringInit(s, str);
}
