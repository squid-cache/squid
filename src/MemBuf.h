
/*
 * $Id: MemBuf.h,v 1.2 2003/02/21 22:50:06 robertc Exp $
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
 */

#ifndef SQUID_MEMBUF_H
#define SQUID_MEMBUF_H

/* auto-growing memory-resident buffer with printf interface */
/* note: when updating this struct, update MemBufNULL #define */

class MemBuf
{

public:
    _SQUID_INLINE_ MemBuf();
    /* public, read-only */
    char *buf;
    mb_size_t size;		/* used space, does not count 0-terminator */

    /* private, stay away; use interface function instead */
    mb_size_t max_capacity;	/* when grows: assert(new_capacity <= max_capacity) */
    mb_size_t capacity;		/* allocated space */

unsigned stolen:
    1;		/* the buffer has been stolen for use by someone else */
};

/* to initialize static variables (see also MemBufNull) */
#define MemBufNULL MemBuf();

#ifdef _USE_INLINE_
#include "MemBuf.cci"
#endif

/* MemBuf */
/* init with specific sizes */
SQUIDCEXTERN void memBufInit(MemBuf * mb, mb_size_t szInit, mb_size_t szMax);
/* init with defaults */
SQUIDCEXTERN void memBufDefInit(MemBuf * mb);
/* cleans mb; last function to call if you do not give .buf away */
SQUIDCEXTERN void memBufClean(MemBuf * mb);
/* resets mb preserving (or initializing if needed) memory buffer */
SQUIDCEXTERN void memBufReset(MemBuf * mb);
/* unfirtunate hack to test if the buffer has been Init()ialized */
SQUIDCEXTERN int memBufIsNull(MemBuf * mb);
/* calls memcpy, appends exactly size bytes, extends buffer if needed */
SQUIDCEXTERN void memBufAppend(MemBuf * mb, const char *buf, mb_size_t size);
/* calls snprintf, extends buffer if needed */
#if STDC_HEADERS
SQUIDCEXTERN void
memBufPrintf(MemBuf * mb, const char *fmt,...) PRINTF_FORMAT_ARG2;
#else
SQUIDCEXTERN void memBufPrintf();
#endif
/* vprintf for other printf()'s to use */
SQUIDCEXTERN void memBufVPrintf(MemBuf * mb, const char *fmt, va_list ap);
/* returns free() function to be used, _freezes_ the object! */
SQUIDCEXTERN FREE *memBufFreeFunc(MemBuf * mb);
/* puts report on MemBuf _module_ usage into mb */
SQUIDCEXTERN void memBufReport(MemBuf * mb);

#define MemBufNull MemBuf();

#endif /* SQUID_MEM_H */
