/*
 * $Id: Stack.h,v 1.14 2003/01/23 00:36:47 robertc Exp $
 *
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

#ifndef SQUID_STACK_H
#define SQUID_STACK_H

#include "Array.h"

typedef Array Stack;

#define stackCreate arrayCreate
#define stackInit arrayInit
#define stackClean arrayClean
#define stackDestroy arrayDestroy
#define stackPush arrayAppend
#define stackPrePush arrayPreAppend

template <class S>
typename S::value_type
stackPop(S * s)
{
    assert(s);
    if (!s->count)
	return typename S::value_type();
    typename S::value_type result = s->items[--s->count];
    s->items[s->count] = typename S::value_type();
    return result;
}

/* todo, fatal on empty Top call */
template <class S>
typename S::value_type
stackTop(S * s)
{
    assert(s);
    return s->count ? s->items[s->count - 1] : typename S::value_type();
}
#endif /* SQUID_STACK_H */
