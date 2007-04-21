/*
 * $Id: stub_store.cc,v 1.3 2007/04/21 07:14:20 wessels Exp $
 *
 * DEBUG: section 20    Storage Manager
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
#include "Store.h"

StorePointer Store::CurrentRoot = NULL;

extern "C" void
#if STDC_HEADERS
    storeAppendPrintf(StoreEntry * e, const char *fmt,...)
#else
    storeAppendPrintf(va_alist)
    va_dcl
#endif
{
    fatal("Not implemented");
}

extern "C" void
    storeAppendVPrintf(StoreEntry * e, const char *fmt, va_list vargs)
{
    fatal("Not implemented");
}

#ifndef _USE_INLINE_
#include "Store.cci"
#endif
