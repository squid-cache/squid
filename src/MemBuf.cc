/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 59    auto-growing Memory Buffer with printf */

/**
 \verbatim
 * Rationale:
 * ----------
 *
 * Here is how one would Comm::Write an object without MemBuffer:
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
 * Comm::Write(buf, free, ...);
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
 * Comm::Write(fd, buf, callback);
 *
 * -- *iff* you did not give the buffer away, free it yourself
 * -- buf.clean();
 * }
 \endverbatim
 */

#include "squid.h"
#include "mem/forward.h"
#include "MemBuf.h"
#include "profiler/Profiler.h"

/* local constants */

/* default values for buffer sizes, used by memBufDefInit */
#define MEM_BUF_INIT_SIZE   (2*1024)
#define MEM_BUF_MAX_SIZE    (2*1000*1024*1024)

CBDATA_CLASS_INIT(MemBuf);

/** init with defaults */
void
MemBuf::init()
{
    init(MEM_BUF_INIT_SIZE, MEM_BUF_MAX_SIZE);
}

/** init with specific sizes */
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
    terminate();
}

/**
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
        assert(!stolen);    /* not frozen */

        memFreeBuf(capacity, buf);
        buf = NULL;
        size = capacity = max_capacity = 0;
    }
}

/**
 * Cleans the buffer without changing its capacity
 * if called with a Null buffer, calls memBufDefInit()
 */
void
MemBuf::reset()
{
    if (isNull()) {
        init();
    } else {
        assert(!stolen);    /* not frozen */
        /* reset */
        memset(buf, 0, capacity);
        size = 0;
    }
}

/**
 * Unfortunate hack to test if the buffer has been Init()ialized
 */
int
MemBuf::isNull() const
{
    if (!buf && !max_capacity && !capacity && !size)
        return 1;       /* is null (not initialized) */

    assert(buf && max_capacity && capacity);    /* paranoid */

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

/// removes sz bytes and "packs" by moving content left
void MemBuf::consume(mb_size_t shiftSize)
{
    const mb_size_t cSize = contentSize();
    assert(0 <= shiftSize && shiftSize <= cSize);
    assert(!stolen); /* not frozen */

    PROF_start(MemBuf_consume);
    if (shiftSize > 0) {
        if (shiftSize < cSize)
            memmove(buf, buf + shiftSize, cSize - shiftSize);

        size -= shiftSize;

        terminate();
    }
    PROF_stop(MemBuf_consume);
}

/// removes all whitespace prefix bytes and "packs" by moving content left
void MemBuf::consumeWhitespacePrefix()
{
    PROF_start(MemBuf_consumeWhitespace);
    if (contentSize() > 0) {
        const char *end = buf + contentSize();
        const char *p = buf;
        for (; p<end && xisspace(*p); ++p);
        if (p-buf > 0)
            consume(p-buf);
    }
    PROF_stop(MemBuf_consumeWhitespace);
}

// removes last tailSize bytes
void MemBuf::truncate(mb_size_t tailSize)
{
    const mb_size_t cSize = contentSize();
    assert(0 <= tailSize && tailSize <= cSize);
    assert(!stolen); /* not frozen */
    size -= tailSize;
}

/**
 * calls memcpy, appends exactly size bytes,
 * extends buffer or creates buffer if needed.
 */
void MemBuf::append(const char *newContent, int sz)
{
    assert(sz >= 0);
    assert(buf || (0==capacity && 0==size));
    assert(!stolen); /* not frozen */

    PROF_start(MemBuf_append);
    if (sz > 0) {
        if (size + sz + 1 > capacity)
            grow(size + sz + 1);

        assert(size + sz <= capacity); /* paranoid */
        memcpy(space(), newContent, sz);
        appended(sz);
    }
    PROF_stop(MemBuf_append);
}

/// updates content size after external append
void MemBuf::appended(mb_size_t sz)
{
    assert(size + sz <= capacity);
    size += sz;
    terminate();
}

/**
 * Null-terminate in case we are used as a string.
 * Extra octet is not counted in the content size (or space size)
 *
 \note XXX: but the extra octet is counted when growth decisions are made!
 *     This will cause the buffer to grow when spaceSize() == 1 on append,
 *     which will assert() if the buffer cannot grow any more.
 */
void MemBuf::terminate()
{
    assert(size < capacity);
    *space() = '\0';
}

/**
 * vappendf for other printf()'s to use; calls vsnprintf, extends buf if needed
 */
void
MemBuf::vappendf(const char *fmt, va_list vargs)
{
    int sz = 0;
    assert(fmt);
    assert(buf);
    assert(!stolen);    /* not frozen */
    /* assert in Grow should quit first, but we do not want to have a scary infinite loop */

    while (capacity <= max_capacity) {
        mb_size_t free_space = capacity - size;
        /* put as much as we can */

        /* Fix of bug 753r. The value of vargs is undefined
         * after vsnprintf() returns. Make a copy of vargs
         * incase we loop around and call vsnprintf() again.
         */
        va_list ap;
        va_copy(ap,vargs);
        sz = vsnprintf(buf + size, free_space, fmt, ap);
        va_end(ap);

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
        --size;
    }
}

/**
 * Important:
 *   calling this function "freezes" mb,
 *   do not _update_ mb after that in any way
 *   (you still can read-access .buf and .size)
 *
 \retval free() function to be used.
 */
FREE *
MemBuf::freeFunc()
{
    FREE *ff;
    assert(buf);
    assert(!stolen);    /* not frozen */

    ff = memFreeBufFunc((size_t) capacity);
    stolen = 1;     /* freeze */
    return ff;
}

/**
 * Grows (doubles) internal buffer to satisfy required minimal capacity
 */
void
MemBuf::grow(mb_size_t min_cap)
{
    size_t new_cap;
    size_t buf_cap;

    assert(!stolen);
    assert(capacity < min_cap);

    PROF_start(MemBuf_grow);

    /* determine next capacity */

    if (min_cap > 64 * 1024) {
        new_cap = 64 * 1024;

        while (new_cap < (size_t) min_cap)
            new_cap += 64 * 1024;   /* increase in reasonable steps */
    } else {
        new_cap = (size_t) min_cap;
    }

    /* last chance to fit before we assert(!overflow) */
    if (new_cap > (size_t) max_capacity)
        new_cap = (size_t) max_capacity;

    assert(new_cap <= (size_t) max_capacity);   /* no overflow */

    assert(new_cap > (size_t) capacity);    /* progress */

    buf_cap = (size_t) capacity;

    buf = (char *)memReallocBuf(buf, new_cap, &buf_cap);

    /* done */
    capacity = (mb_size_t) buf_cap;
    PROF_stop(MemBuf_grow);
}

/* Reports */

/**
 * Puts report on MemBuf _module_ usage into mb
 */
void
memBufReport(MemBuf * mb)
{
    assert(mb);
    mb->appendf("memBufReport is not yet implemented @?@\n");
}

