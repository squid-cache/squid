/*
 * $Id: MemBuf.cc,v 1.6 1998/02/27 09:11:43 rousskov Exp $
 *
 * DEBUG: section 59    auto-growing Memory Buffer with printf
 * AUTHOR: Alex Rousskov
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

/*
 * To-Do: uses memory pools for .buf recycling @?@
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
 * However, what happens if we have more data? If we are lucky to be careful
 * to stop before we overrun any buffers, we still may have garbage (e.g.
 * half of ETag) in the buffer.
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
 * comm_write(buf.buf, memBufFreeFunc(&buf), ...);
 * 
 * -- *iff* you did not give the buffer away, free it yourself
 * -- memBufFree(&buf);
 * }
 */


#include "squid.h"

/* local constants */

/* default values for buffer sizes, used by memBufDefInit */
#define MEM_BUF_INIT_SIZE   (2*1024)
#define MEM_BUF_MAX_SIZE   (32*1024)


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
    mb->freefunc = NULL;

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
    assert(mb->freefunc);	/* not frozen */

    (*mb->freefunc) (mb->buf);	/* freeze */
    mb->buf = NULL;
    mb->size = mb->capacity = 0;
}

/* calls memcpy, appends exactly size bytes, extends buffer if needed */
void
memBufAppend(MemBuf * mb, const char *buf, mb_size_t sz)
{
    assert(mb && buf && sz >= 0);
    assert(mb->buf);
    assert(mb->freefunc);	/* not frozen */

    if (sz > 0) {
	if (mb->size + sz > mb->capacity)
	    memBufGrow(mb, mb->size + sz);
	assert(mb->size + sz <= mb->capacity);	/* paranoid */
	xmemcpy(mb->buf + mb->size, buf, sz);
	mb->size += sz;
    }
}

/* calls snprintf, extends buffer if needed */
#ifdef __STDC__
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


/* vprintf for other printf()'s to use */
void
memBufVPrintf(MemBuf * mb, const char *fmt, va_list vargs)
{
    mb_size_t sz = 0;
    assert(mb && fmt);
    assert(mb->buf);
    assert(mb->freefunc);	/* not frozen */
    /* @?@ we do not init buf with '\0', do we have to for vsnprintf?? @?@ */
    /* assert in Grow should quit first, but we do not want to have a scare (1) loop */
    while (mb->capacity <= mb->max_capacity) {
	mb_size_t free_space = mb->capacity - mb->size;
	/* put as much as we can */
	sz = vsnprintf(mb->buf + mb->size, free_space, fmt, vargs) + 1;
	/* check for possible overflow @?@ can vsnprintf cut more than needed off? */
	if (sz + 32 >= free_space)	/* magic constant 32, ARGH! @?@ */
	    memBufGrow(mb, mb->capacity + 1);
	else
	    break;
    }
    mb->size += sz - 1;		/* note that we cut 0-terminator as store does @?@ @?@ */
}

/*
 * returns free() function to be used.
 * Important:
 *   calling this function "freezes" mb,
 *   do not _update_ mb after that in any way
 *   (you still can read-access .buf and .size)
 */
FREE *
memBufFreeFunc(MemBuf * mb)
{
    FREE *ff;
    assert(mb);
    assert(mb->buf);
    assert(mb->freefunc);	/* not frozen */

    ff = mb->freefunc;
    mb->freefunc = NULL;	/* freeze */
    return ff;
}

/* grows (doubles) internal buffer to satisfy required minimal capacity */
static void
memBufGrow(MemBuf * mb, mb_size_t min_cap)
{
    mb_size_t new_cap;
    assert(mb);
    assert(mb->capacity < min_cap);

    /* determine next capacity */
    new_cap = mb->capacity;
    if (new_cap > 0)
	while (new_cap < min_cap)
	    new_cap *= 2;	/* double */
    else
	new_cap = min_cap;

    /* last chance to fit before we assert(!overflow) */
    if (new_cap > mb->max_capacity)
	new_cap = mb->max_capacity;

    assert(new_cap <= mb->max_capacity);	/* no overflow */
    assert(new_cap > mb->capacity);	/* progress */

    /* finally [re]allocate memory */
    if (!mb->buf) {
	mb->buf = xmalloc(new_cap);
	mb->freefunc = &xfree;
    } else {
	assert(mb->freefunc);
	mb->buf = xrealloc(mb->buf, new_cap);
    }
    memset(mb->buf + mb->size, 0, new_cap - mb->size);	/* just in case */
    mb->capacity = new_cap;
}


/* Reports */

/* puts report on MemBuf _module_ usage into mb */
void
memBufReport(MemBuf * mb)
{
    assert(mb);
    memBufPrintf(mb, "memBufReport is not yet implemented @?@\n");
}
