
/*
 * $Id: MemBuf.cc,v 1.34 2003/02/21 22:50:05 robertc Exp $
 *
 * DEBUG: section 59    auto-growing Memory Buffer with printf
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

/*
 * To-Do: use memory pools for .buf recycling @?@ @?@
 */

/*
 * Rationale:
 * ----------
 * 
 * Here is how one would comm_write an object without MemBuffer:
 * 
 * {
 * -- allocate:
 * buf = malloc(big_enough);
 * 
 * -- "pack":
 * snprintf object(s) piece-by-piece constantly checking for overflows
 * and maintaining (buf+offset);
 * ...
 * 
 * -- write
 * comm_write(buf, free, ...);
 * }
 * 
 * The whole "packing" idea is quite messy: We are given a buffer of fixed
 * size and we have to check all the time that we still fit. Sounds logical.
 *
 * However, what happens if we have more data? If we are lucky to stop before
 * we overrun any buffers, we still may have garbage (e.g. half of ETag) in
 * the buffer.
 * 
 * MemBuffer:
 * ----------
 * 
 * MemBuffer is a memory-resident buffer with printf()-like interface. It
 * hides all offest handling and overflow checking. Moreover, it has a
 * build-in control that no partial data has been written.
 * 
 * MemBuffer is designed to handle relatively small data. It starts with a
 * small buffer of configurable size to avoid allocating huge buffers all the
 * time.  MemBuffer doubles the buffer when needed. It assert()s that it will
 * not grow larger than a configurable limit. MemBuffer has virtually no
 * overhead (and can even reduce memory consumption) compared to old
 * "packing" approach.
 * 
 * MemBuffer eliminates both "packing" mess and truncated data:
 * 
 * {
 * -- setup
 * MemBuf buf;
 * 
 * -- required init with optional size tuning (see #defines for defaults)
 * memBufInit(&buf, initial-size, absolute-maximum);
 * 
 * -- "pack" (no need to handle offsets or check for overflows)
 * memBufPrintf(&buf, ...);
 * ...
 * 
 * -- write
 * comm_write_mbuf(fd, buf, handler, data);
 *
 * -- *iff* you did not give the buffer away, free it yourself
 * -- memBufClean(&buf);
 * }
 */


#include "squid.h"

/* local constants */

/* default values for buffer sizes, used by memBufDefInit */
#define MEM_BUF_INIT_SIZE   (2*1024)
#define MEM_BUF_MAX_SIZE    (2*1000*1024*1024)


/* local routines */
static void memBufGrow(MemBuf * mb, mb_size_t min_cap);


/* init with defaults */
void
memBufDefInit(MemBuf * mb)
{
    memBufInit(mb, MEM_BUF_INIT_SIZE, MEM_BUF_MAX_SIZE);
}


/* init with specific sizes */
void
memBufInit(MemBuf * mb, mb_size_t szInit, mb_size_t szMax)
{
    assert(mb);
    assert(szInit > 0 && szMax > 0);

    mb->buf = NULL;
    mb->size = 0;
    mb->max_capacity = szMax;
    mb->capacity = 0;
    mb->stolen = 0;

    memBufGrow(mb, szInit);
}

/*
 * cleans the mb; last function to call if you do not give .buf away with
 * memBufFreeFunc
 */
void
memBufClean(MemBuf * mb)
{
    assert(mb);
    assert(mb->buf);
    assert(!mb->stolen);	/* not frozen */

    memFreeBuf(mb->capacity, mb->buf);
    mb->buf = NULL;
    mb->size = mb->capacity = 0;
}

/* cleans the buffer without changing its capacity
 * if called with a Null buffer, calls memBufDefInit() */
void
memBufReset(MemBuf * mb)
{
    assert(mb);

    if (memBufIsNull(mb)) {
        memBufDefInit(mb);
    } else {
        assert(!mb->stolen);	/* not frozen */
        /* reset */
        memset(mb->buf, 0, mb->capacity);
        mb->size = 0;
    }
}

/* unfortunate hack to test if the buffer has been Init()ialized */
int
memBufIsNull(MemBuf * mb)
{
    assert(mb);

    if (!mb->buf && !mb->max_capacity && !mb->capacity && !mb->size)
        return 1;		/* is null (not initialized) */

    assert(mb->buf && mb->max_capacity && mb->capacity);	/* paranoid */

    return 0;
}


/* calls memcpy, appends exactly size bytes, extends buffer if needed */
void
memBufAppend(MemBuf * mb, const char *buf, mb_size_t sz)
{
    assert(mb && buf && sz >= 0);
    assert(mb->buf);
    assert(!mb->stolen);	/* not frozen */

    if (sz > 0) {
        if (mb->size + sz + 1 > mb->capacity)
            memBufGrow(mb, mb->size + sz + 1);

        assert(mb->size + sz <= mb->capacity);	/* paranoid */

        xmemcpy(mb->buf + mb->size, buf, sz);

        mb->size += sz;

        mb->buf[mb->size] = '\0';	/* \0 terminate in case we are used as a string. Not counted in the size */
    }
}

/* calls memBufVPrintf */
#if STDC_HEADERS
void
memBufPrintf(MemBuf * mb, const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
#else
void
memBufPrintf(va_alist)
va_dcl
{
    va_list args;
    MemBuf *mb = NULL;
    const char *fmt = NULL;
    mb_size_t sz = 0;
    va_start(args);
    mb = va_arg(args, MemBuf *);
    fmt = va_arg(args, char *);
#endif

    memBufVPrintf(mb, fmt, args);
    va_end(args);
}


/* vprintf for other printf()'s to use; calls vsnprintf, extends buf if needed */
void
memBufVPrintf(MemBuf * mb, const char *fmt, va_list vargs) {
    int sz = 0;
    assert(mb && fmt);
    assert(mb->buf);
    assert(!mb->stolen);	/* not frozen */
    /* assert in Grow should quit first, but we do not want to have a scary infinite loop */

    while (mb->capacity <= mb->max_capacity) {
        mb_size_t free_space = mb->capacity - mb->size;
        /* put as much as we can */
        sz = vsnprintf(mb->buf + mb->size, free_space, fmt, vargs);
        /* check for possible overflow */
        /* snprintf on Linuz returns -1 on overflows */
        /* snprintf on FreeBSD returns at least free_space on overflows */

        if (sz < 0 || sz >= free_space)
            memBufGrow(mb, mb->capacity + 1);
        else
            break;
    }

    mb->size += sz;
    /* on Linux and FreeBSD, '\0' is not counted in return value */
    /* on XXX it might be counted */
    /* check that '\0' is appended and not counted */

    if (!mb->size || mb->buf[mb->size - 1]) {
        assert(!mb->buf[mb->size]);
    } else {
        mb->size--;
    }
}

/*
 * returns free() function to be used.
 * Important:
 *   calling this function "freezes" mb,
 *   do not _update_ mb after that in any way
 *   (you still can read-access .buf and .size)
 */
FREE *
memBufFreeFunc(MemBuf * mb) {
    FREE *ff;
    assert(mb);
    assert(mb->buf);
    assert(!mb->stolen);	/* not frozen */

    ff = memFreeBufFunc((size_t) mb->capacity);
    mb->stolen = 1;		/* freeze */
    return ff;
}

/* grows (doubles) internal buffer to satisfy required minimal capacity */
static void
memBufGrow(MemBuf * mb, mb_size_t min_cap) {
    size_t new_cap;
    size_t buf_cap;

    assert(mb);
    assert(!mb->stolen);
    assert(mb->capacity < min_cap);

    /* determine next capacity */

    if (min_cap > 64 * 1024) {
        new_cap = 64 * 1024;

        while (new_cap < (size_t) min_cap)
            new_cap += 64 * 1024;	/* increase in reasonable steps */
    } else {
        new_cap = (size_t) min_cap;
    }

    /* last chance to fit before we assert(!overflow) */
    if (new_cap > (size_t) mb->max_capacity)
        new_cap = (size_t) mb->max_capacity;

    assert(new_cap <= (size_t) mb->max_capacity);	/* no overflow */

    assert(new_cap > (size_t) mb->capacity);	/* progress */

    buf_cap = (size_t) mb->capacity;

    mb->buf = (char *)memReallocBuf(mb->buf, new_cap, &buf_cap);

    /* done */
    mb->capacity = (mb_size_t) buf_cap;
}


/* Reports */

/* puts report on MemBuf _module_ usage into mb */
void
memBufReport(MemBuf * mb) {
    assert(mb);
    memBufPrintf(mb, "memBufReport is not yet implemented @?@\n");
}

#ifndef _USE_INLINE_
#include "MemBuf.cci"
#endif
