
/*
 * $Id: MemBuf.cc,v 1.42 2006/09/20 08:13:38 adrian Exp $
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
 * buf.init(initial-size, absolute-maximum);
 * 
 * -- "pack" (no need to handle offsets or check for overflows)
 * buf.Printf(...);
 * ...
 * 
 * -- write
 * comm_write_mbuf(fd, buf, handler, data);
 *
 * -- *iff* you did not give the buffer away, free it yourself
 * -- buf.clean();
 * }
 */
/* if you have configure you can use this */
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#ifdef VA_COPY
#undef VA_COPY
#endif
#if defined HAVE_VA_COPY
#define VA_COPY va_copy
#elif defined HAVE___VA_COPY
#define VA_COPY __va_copy
#endif

#include "squid.h"
#include "MemBuf.h"

/* local constants */

/* default values for buffer sizes, used by memBufDefInit */
#define MEM_BUF_INIT_SIZE   (2*1024)
#define MEM_BUF_MAX_SIZE    (2*1000*1024*1024)

CBDATA_CLASS_INIT(MemBuf);

/* init with defaults */
void
MemBuf::init()
{
    init(MEM_BUF_INIT_SIZE, MEM_BUF_MAX_SIZE);
}


/* init with specific sizes */
void
MemBuf::init(mb_size_t szInit, mb_size_t szMax)
{
    assert(szInit > 0 && szMax > 0);
    buf = NULL;
    size = 0;
    max_capacity = szMax;
    capacity = 0;
    stolen = 0;
    grow(szInit);
}

/*
 * cleans the mb; last function to call if you do not give .buf away with
 * memBufFreeFunc
 */
void
MemBuf::clean()
{
    if (isNull()) {
        // nothing to do
    } else {
        assert(buf);
        assert(!stolen);	/* not frozen */

        memFreeBuf(capacity, buf);
        buf = NULL;
        size = capacity = max_capacity = 0;
    }
}

/* cleans the buffer without changing its capacity
 * if called with a Null buffer, calls memBufDefInit() */
void
MemBuf::reset()
{
    if (isNull()) {
        init();
    } else {
        assert(!stolen);	/* not frozen */
        /* reset */
        memset(buf, 0, capacity);
        size = 0;
    }
}

/* unfortunate hack to test if the buffer has been Init()ialized */
int
MemBuf::isNull()
{
    if (!buf && !max_capacity && !capacity && !size)
        return 1;		/* is null (not initialized) */

    assert(buf && max_capacity && capacity);	/* paranoid */

    return 0;
}

mb_size_t MemBuf::spaceSize() const
{
    const mb_size_t terminatedSize = size + 1;
    return (terminatedSize < capacity) ? capacity - terminatedSize : 0;
}

mb_size_t MemBuf::potentialSpaceSize() const
{
    const mb_size_t terminatedSize = size + 1;
    return (terminatedSize < max_capacity) ? max_capacity - terminatedSize : 0;
}

// removes sz bytes and "packs" by moving content left
void MemBuf::consume(mb_size_t shiftSize)
{
    const mb_size_t cSize = contentSize();
    assert(0 <= shiftSize && shiftSize <= cSize);
    assert(!stolen); /* not frozen */

    PROF_start(MemBuf_consume);
    if (shiftSize > 0) {
        if (shiftSize < cSize)
            xmemmove(buf, buf + shiftSize, cSize - shiftSize);

        size -= shiftSize;

        terminate();
    }
    PROF_stop(MemBuf_consume);
}

// calls memcpy, appends exactly size bytes, extends buffer if needed
void MemBuf::append(const char *newContent, mb_size_t sz)
{
    assert(sz >= 0);
    assert(buf);
    assert(!stolen); /* not frozen */

    PROF_start(MemBuf_append);
    if (sz > 0) {
        if (size + sz + 1 > capacity)
            grow(size + sz + 1);

        assert(size + sz <= capacity); /* paranoid */

        xmemcpy(space(), newContent, sz);

        appended(sz);
    }
    PROF_stop(MemBuf_append);
}

// updates content size after external append
void MemBuf::appended(mb_size_t sz)
{
    assert(size + sz <= capacity);
    size += sz;
    terminate();
}

// 0-terminate in case we are used as a string.
// Extra octet is not counted in the content size (or space size)
// XXX: but the extra octet is counted when growth decisions are made!
// This will cause the buffer to grow when spaceSize() == 1 on append,
// which will assert() if the buffer cannot grow any more.
void MemBuf::terminate()
{
    assert(size < capacity);
    *space() = '\0';
}

/* calls memBufVPrintf */
#if STDC_HEADERS
void
MemBuf::Printf(const char *fmt,...)
{
    va_list args;
    va_start(args, fmt);
#else
void
MemBuf::Printf(va_alist)
va_dcl
{
    va_list args;
    mb_size_t sz = 0;
    va_start(args);
    const char *fmt = va_arg(args, char *);
#endif

    vPrintf(fmt, args);
    va_end(args);
}


/* vPrintf for other printf()'s to use; calls vsnprintf, extends buf if needed */
void
MemBuf::vPrintf(const char *fmt, va_list vargs) {
#ifdef VA_COPY
    va_list ap;
#endif

    int sz = 0;
    assert(fmt);
    assert(buf);
    assert(!stolen);	/* not frozen */
    /* assert in Grow should quit first, but we do not want to have a scary infinite loop */

    while (capacity <= max_capacity) {
        mb_size_t free_space = capacity - size;
        /* put as much as we can */

#ifdef VA_COPY
        /* Fix of bug 753r. The value of vargs is undefined
         * after vsnprintf() returns. Make a copy of vargs
         * incase we loop around and call vsnprintf() again.
         */
        VA_COPY(ap,vargs);
        sz = vsnprintf(buf + size, free_space, fmt, ap);
        va_end(ap);
#else /* VA_COPY */

        sz = vsnprintf(buf + size, free_space, fmt, vargs);
#endif /*VA_COPY*/
        /* check for possible overflow */
        /* snprintf on Linuz returns -1 on overflows */
        /* snprintf on FreeBSD returns at least free_space on overflows */

        if (sz < 0 || sz >= free_space)
            grow(capacity + 1);
        else
            break;
    }

    size += sz;
    /* on Linux and FreeBSD, '\0' is not counted in return value */
    /* on XXX it might be counted */
    /* check that '\0' is appended and not counted */

    if (!size || buf[size - 1]) {
        assert(!buf[size]);
    } else {
        size--;
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
MemBuf::freeFunc() {
    FREE *ff;
    assert(buf);
    assert(!stolen);	/* not frozen */

    ff = memFreeBufFunc((size_t) capacity);
    stolen = 1;		/* freeze */
    return ff;
}

/* grows (doubles) internal buffer to satisfy required minimal capacity */
void
MemBuf::grow(mb_size_t min_cap) {
    size_t new_cap;
    size_t buf_cap;

    assert(!stolen);
    assert(capacity < min_cap);

    PROF_start(MemBuf_grow);

    /* determine next capacity */

    if (min_cap > 64 * 1024) {
        new_cap = 64 * 1024;

        while (new_cap < (size_t) min_cap)
            new_cap += 64 * 1024;	/* increase in reasonable steps */
    } else {
        new_cap = (size_t) min_cap;
    }

    /* last chance to fit before we assert(!overflow) */
    if (new_cap > (size_t) max_capacity)
        new_cap = (size_t) max_capacity;

    assert(new_cap <= (size_t) max_capacity);	/* no overflow */

    assert(new_cap > (size_t) capacity);	/* progress */

    buf_cap = (size_t) capacity;

    buf = (char *)memReallocBuf(buf, new_cap, &buf_cap);

    /* done */
    capacity = (mb_size_t) buf_cap;
    PROF_stop(MemBuf_grow);
}


/* Reports */

/* puts report on MemBuf _module_ usage into mb */
void
memBufReport(MemBuf * mb) {
    assert(mb);
    mb->Printf("memBufReport is not yet implemented @?@\n");
}

#ifndef _USE_INLINE_
#include "MemBuf.cci"
#endif
