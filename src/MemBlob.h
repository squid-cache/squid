/*
 * MemBlob.h (C) 2009 Francesco Chemolli <kinkie@squid-cache.org>
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
 */

#ifndef SQUID_MEMBLOB_H_
#define SQUID_MEMBLOB_H_

#define MEMBLOB_DEBUGSECTION 24

#include "base/InstanceId.h"
#include "MemPool.h"
#include "RefCount.h"

/// Various MemBlob class-wide statistics.
class MemBlobStats
{
public:
    MemBlobStats();

    /// dumps class-wide statistics
    std::ostream& dump(std::ostream& os) const;

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
public:
    typedef RefCount<MemBlob> Pointer;
    typedef int32_t size_type;

    MEMPROXY_CLASS(MemBlob);

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
        return isAppendOffset(off) && willFit(n);
    }

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

MEMPROXY_CLASS_INLINE(MemBlob);

#endif /* SQUID_MEMBLOB_H_ */
