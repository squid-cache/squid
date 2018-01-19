/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_MEMBUF_H
#define SQUID_MEMBUF_H

#include "cbdata.h"
#include "Packer.h"

/**
 * Auto-growing memory-resident buffer with printf interface
 *
 \todo XXX: convert global memBuf*() functions into methods
 */
class MemBuf
{

public:
    _SQUID_INLINE_ MemBuf();
    _SQUID_INLINE_ ~MemBuf();

    /// start of the added data
    char *content() { return buf; }

    /// start of the added data
    const char *content() const { return buf; }

    /// available data size
    mb_size_t contentSize() const { return size; }

    /**
     * Whether the buffer contains any data.
     \retval true   if data exists in the buffer
     \retval false  if data exists in the buffer
     */
    bool hasContent() const { return size > 0; }

    /// returns buffer after data; does not check space existence
    char *space() { return buf + size; } ///< space to add data

    /// Returns buffer following data, after possibly growing the buffer to
    /// accommodate addition of the required bytes PLUS a 0-terminator char.
    /// The caller is not required to terminate the buffer, but MemBuf does
    /// terminate internally, trading termination for size calculation bugs.
    char *space(mb_size_t required) { if (size + required >= capacity) grow(size + required + 1); return buf + size; }

    mb_size_t spaceSize() const;

    /**
     * Whether the buffer contains any data space available.
     \retval true   if data can be added to the buffer
     \retval false  if the buffer is full
     */
    bool hasSpace() const { return size+1 < capacity; }

    mb_size_t potentialSpaceSize() const; // accounts for possible growth
    bool hasPotentialSpace() const { return potentialSpaceSize() > 0; }

    /// \note there is currently no stretch() method to grow without appending

    void consume(mb_size_t sz);  // removes sz bytes, moving content left
    void consumeWhitespacePrefix();    ///< removes all prefix whitespace, moving content left

    void append(const char *c, mb_size_t sz); // grows if needed and possible
    void appended(mb_size_t sz); // updates content size after external append
    void truncate(mb_size_t sz);  // removes sz last bytes

    void terminate(); // zero-terminates the buffer w/o increasing contentSize

    bool wasStolen() const { return stolen; }

    /** init with specific sizes */
    void init(mb_size_t szInit, mb_size_t szMax);

    /** init with defaults */
    void init();

    /** cleans mb; last function to call if you do not give .buf away */
    void clean();

    /** resets mb preserving (or initializing if needed) memory buffer */
    void reset();

    /** unfirtunate hack to test if the buffer has been Init()ialized */
    int isNull();

    /**
     * calls snprintf, extends buffer if needed
     \note  we use Printf instead of printf so the compiler won't
     *      think we're calling the libc printf()
     */
    void Printf(const char *fmt,...) PRINTF_FORMAT_ARG2;

    /** vPrintf for other printf()'s to use */
    void vPrintf(const char *fmt, va_list ap);

    /**
     * freezes the object! and returns function to clear it up.
     *
     \retval free() function to be used.
     */
    FREE *freeFunc();

private:
    /**
     * private copy constructor and assignment operator generates
     * compiler errors if someone tries to copy/assign a MemBuf
     */
    MemBuf(const MemBuf& m) {assert(false);};

    MemBuf& operator= (const MemBuf& m) {assert(false); return *this;};

    void grow(mb_size_t min_cap);

public:
    /**
     \deprecated use space*() and content*() methods to access safely instead.
     * public, read-only.
     *
     \todo XXX: hide these members completely and remove 0-termination
     *          so that consume() does not need to memmove all the time
     */
    char *buf;          // available content
    mb_size_t size;     // used space, does not count 0-terminator

    /**
     * when grows: assert(new_capacity <= max_capacity)
     \deprecated Use interface function instead
     \todo XXX: make these private after converting memBuf*() functions to methods
     */
    mb_size_t max_capacity;

    /**
     * allocated space
     \deprecated Use interface function instead
     \todo XXX: make these private after converting memBuf*() functions to methods
     */
    mb_size_t capacity;

    unsigned stolen:1;      /* the buffer has been stolen for use by someone else */

#if 0

    unsigned valid:1;       /* to be used for debugging only! */
#endif

private:
    CBDATA_CLASS2(MemBuf);
};

#if _USE_INLINE_
#include "MemBuf.cci"
#endif

/** returns free() function to be used, _freezes_ the object! */
void memBufReport(MemBuf * mb);
/** pack content into a mem buf. */
void packerToMemInit(Packer * p, MemBuf * mb);

#endif /* SQUID_MEM_H */

