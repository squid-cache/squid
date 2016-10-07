/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_MEMBLOB_H_
#define SQUID_MEMBLOB_H_

#define MEMBLOB_DEBUGSECTION 24

#include "base/InstanceId.h"
#include "base/RefCount.h"
#include "mem/forward.h"

/// Various MemBlob class-wide statistics.
class MemBlobStats
{
public:
    MemBlobStats();

    /// dumps class-wide statistics
    std::ostream& dump(std::ostream& os) const;

    MemBlobStats& operator += (const MemBlobStats&);

public:
    uint64_t alloc;     ///< number of MemBlob instances created so far
    uint64_t live;      ///< number of MemBlob instances currently alive
    uint64_t append;    ///< number of MemBlob::append() calls
    uint64_t liveBytes; ///< the total size of currently allocated storage
};

/** Refcountable, fixed-size, content-agnostic memory buffer.
 *
 * Allocated memory block is divided into two sequential areas:
 * "used memory" and "available space". The used area can be filled during
 * construction, grows via the append() call, and can be clear()ed.
 *
 * MemBlob users can cooperate to safely share the used area. However, MemBlob
 * provides weak use accounting and no sharing protections besides refcounting.
 */
class MemBlob: public RefCountable
{
    MEMPROXY_CLASS(MemBlob);

public:
    typedef RefCount<MemBlob> Pointer;
    typedef uint32_t size_type;

    /// obtain a const view of class-wide statistics
    static const MemBlobStats& GetStats();

    /// create a new MemBlob with at least reserveSize capacity
    explicit MemBlob(const size_type reserveSize);

    /// create a MemBlob containing a copy of the buffer of a given size
    MemBlob(const char *buffer, const size_type bufferSize);

    virtual ~MemBlob();

    /// the number unused bytes at the end of the allocated blob
    size_type spaceSize() const { return capacity - size; }

    /** check whether the caller can successfully append() n bytes
     *
     * \return true  the caller may append() n bytes to this blob now
     * \param off    the end of the blob area currently used by the caller
     * \param n      the total number of bytes the caller wants to append
     */
    bool canAppend(const size_type off, const size_type n) const {
        // TODO: ignore offset (and adjust size) when the blob is not shared?
        return (isAppendOffset(off) && willFit(n)) || !n;
    }

    /** adjusts internal object state as if exactly n bytes were append()ed
     *
     * \throw TextException if there was not enough space in the blob
     * \param n the number of bytes that were appended
     */
    void appended(const size_type n);

    /** copies exactly n bytes from the source to the available space area,
     *  enlarging the used area by n bytes
     *
     * \throw TextException if there is not enough space in the blob
     * \param source raw buffer to be copied
     * \param n the number of bytes to copy from the source buffer
     */
    void append(const char *source, const size_type n);

    /// extends the available space to the entire allocated blob
    void clear() { size = 0; }

    /// dump debugging information
    std::ostream & dump(std::ostream &os) const;

public:
    /* MemBlob users should avoid these and must treat them as read-only */
    char *mem;          ///< raw allocated memory block
    size_type capacity; ///< size of the raw allocated memory block
    size_type size;     ///< maximum allocated memory in use by callers
    const InstanceId<MemBlob> id; ///< blob identifier

private:
    static MemBlobStats Stats; ///< class-wide statistics

    void memAlloc(const size_type memSize);

    /// whether the offset points to the end of the used area
    bool isAppendOffset(const size_type off) const { return off == size; }

    /// whether n more bytes can be appended
    bool willFit(const size_type n) const { return n <= spaceSize(); }

    /* copying is not implemented */
    MemBlob(const MemBlob &);
    MemBlob& operator =(const MemBlob &);
};

#endif /* SQUID_MEMBLOB_H_ */

