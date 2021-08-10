/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_MEMBUF_H
#define SQUID_MEMBUF_H

#include "base/Packable.h"
#include "cbdata.h"
#include "mem/forward.h"

/* in case we want to change it later */
typedef ssize_t mb_size_t;

/**
 * Auto-growing memory-resident buffer with Packable interface
 * \deprecated Use SBuf instead.
 */
class MemBuf : public Packable
{
    CBDATA_CLASS(MemBuf);

public:
    static const mb_size_t maxSize = (2*1000*1024*1024); ///< 2000 MB
    static const mb_size_t defaultSize = (2*1024); ///< 2 KB

    MemBuf() = default;
    MemBuf(const MemBuf &) = delete;
    MemBuf& operator= (const MemBuf &) = delete;
    virtual ~MemBuf() {
        if (!stolen && buf)
            clean();
    }

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

    void appended(mb_size_t sz); // updates content size after external append
    void truncate(mb_size_t sz);  // removes sz last bytes

    void terminate(); // zero-terminates the buffer w/o increasing contentSize

    bool wasStolen() const { return stolen; }

    /** init with specific sizes */
    void init(mb_size_t szInit = defaultSize, mb_size_t szMax = maxSize);

    /** cleans mb; last function to call if you do not give .buf away */
    void clean();

    /** resets mb preserving (or initializing if needed) memory buffer */
    void reset();

    /** unfirtunate hack to test if the buffer has been Init()ialized */
    int isNull() const;

    /**
     * freezes the object! and returns function to clear it up.
     *
     \retval free() function to be used.
     */
    FREE *freeFunc();

    /* Packable API */
    virtual void append(const char *c, int sz);
    virtual void vappendf(const char *fmt, va_list ap);

private:
    void grow(mb_size_t min_cap);

public:
    /**
     \deprecated use space*() and content*() methods to access safely instead.
     * public, read-only.
     *
     * TODO: hide these members completely and remove 0-termination
     *          so that consume() does not need to memmove all the time
     */
    char *buf = nullptr; ///< available content
    mb_size_t size = 0; ///< used space, does not count 0-terminator

    /**
     * when grows: assert(new_capacity <= max_capacity)
     * \deprecated Use interface function instead
     * TODO: make these private after converting memBuf*() functions to methods
     */
    mb_size_t max_capacity = maxSize;

    /**
     * allocated space
     * \deprecated Use interface function instead
     * TODO: make these private after converting memBuf*() functions to methods
     */
    mb_size_t capacity = 0;

    /// the buffer has been stolen for use by someone else
    bool stolen = false;
};

/** returns free() function to be used, _freezes_ the object! */
void memBufReport(MemBuf * mb);

#endif /* SQUID_MEMBUF_H */

