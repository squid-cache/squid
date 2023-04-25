/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREIOBUFFER_H
#define SQUID_STOREIOBUFFER_H

#include "base/Range.h"
#include "MemBuf.h"

class StoreIOBuffer
{

public:
    StoreIOBuffer():length(0), offset (0), data (nullptr) {flags.error = 0;}

    StoreIOBuffer(size_t aLength, int64_t anOffset, char *someData) :
        length (aLength), offset (anOffset), data (someData) {
        flags.error = 0;
    }

    /* Create a StoreIOBuffer from a MemBuf and offset */
    /* NOTE that MemBuf still "owns" the pointers, StoreIOBuffer is just borrowing them */
    StoreIOBuffer(MemBuf *aMemBuf, int64_t anOffset) :
        length(aMemBuf->contentSize()),
        offset (anOffset),
        data(aMemBuf->content()) {
        flags.error = 0;
    }

    StoreIOBuffer(MemBuf *aMemBuf, int64_t anOffset, size_t anLength) :
        length(anLength),
        offset (anOffset),
        data(aMemBuf->content()) {
        flags.error = 0;
    }

    Range<int64_t> range() const {
        return Range<int64_t>(offset, offset + length);
    }

    /// convenience method for changing the offset of a being-configured buffer
    StoreIOBuffer &positionAt(const int64_t newOffset) { offset = newOffset; return *this; }

    void dump() const {
        if (fwrite(data, length, 1, stderr)) {}
        if (fwrite("\n", 1, 1, stderr)) {}
    }

    struct {
        unsigned error:1;
    } flags;
    size_t length;
    int64_t offset;
    char *data;
};

inline
std::ostream &
operator <<(std::ostream &os, const StoreIOBuffer &b)
{
    return os << "ioBuf(@" << b.offset << ", len=" << b.length << ", " <<
           (void*)b.data << (b.flags.error ? ", ERR" : "") << ')';
}

#include "sbuf/SBuf.h" // XXX: misplaced
#include <optional> // XXX: misplaced

namespace Store
{

/// A continuous buffer for efficient accumulation and NUL-termination of
/// Store-read bytes. The buffer accumulates two kinds of Store readers:
///
/// * Readers that do not have any external buffer to worry about but need to
///   accumulate, terminate, and/or consume buffered content read by Store.
///   These readers use the default constructor and then allocate the initial
///   buffer space for their first read (if any).
///
/// * Readers that supply their StoreIOBuffer at construction time. That buffer
///   is enough to handle the majority of use cases. However, the supplied
///   StoreIOBuffer capacity may be exceeded when parsing requires accumulating
///   multiple Store read results and/or NUL-termination of a full buffer.
///
/// This buffer seamlessly grows as needed, reducing memory over-allocation and,
/// in case of StoreIOBuffer-seeded construction, memory copies.
class ParsingBuffer
{
public:
    /// creates buffer without any space or content
    ParsingBuffer();

    /// seeds this buffer with the caller-supplied buffer space
    explicit ParsingBuffer(StoreIOBuffer &space);

    /// a NUL-terminated version of content(); same lifetime as content()
    const char *c_str() { terminate(); return memory(); }

    /// the total number of append()ed bytes that were not consume()d
    size_t contentSize() const { return size_; }

    /// the number of bytes in the space() buffer
    size_t spaceSize() const;

    /// the maximum number of bytes we can store without allocating more space
    size_t capacity() const;

    /// Stored append()ed bytes that have not been consume()d. The returned
    /// buffer offset is set to zero; the caller is responsible for adjusting
    /// the offset if needed (TODO: Add/return a no-offset Mem::View instead).
    /// The returned buffer is invalidated by calling a non-constant method or
    /// by changing the StoreIOBuffer contents given to our constructor.
    StoreIOBuffer content() const;

    /// A (possibly empty) buffer for reading the next byte(s). The returned
    /// buffer offset is set to zero; the caller is responsible for adjusting
    /// the offset if needed (TODO: Add/return a no-offset Mem::Area instead).
    /// The returned buffer is invalidated by calling a non-constant method or
    /// by changing the StoreIOBuffer contents given to our constructor.
    StoreIOBuffer space();

    /// A buffer for reading the exact number of next byte(s). The method may
    /// allocate new memory and copy previously appended() bytes as needed.
    /// \param pageSize the exact number of bytes the caller wants to read
    /// \returns space() after any necessary allocations
    StoreIOBuffer makeSpace(size_t pageSize);

    /// A buffer suitable for the first storeClientCopy() call. The method may
    /// allocate new memory and copy previously appended() bytes as needed.
    /// \returns space() after any necessary allocations
    /// \deprecated New clients should call makeSpace() with client-specific
    /// pageSize instead of this one-size-fits-all legacy method.
    StoreIOBuffer makeInitialSpace() { return makeSpace(4096); }

    /// remember the new bytes received into the previously provided space()
    void appended(const char *, size_t);

    /// get rid of previously appended() prefix of a given size
    void consume(size_t);

    /// Returns stored content, reusing the StoreIOBuffer given at the
    /// construction time. Copying is avoided if we did not allocate extra
    /// memory since construction. Not meant for default-constructed buffers.
    StoreIOBuffer packBack();

    /// summarizes object state (for debugging)
    void print(std::ostream &) const;

private:
    char *memory() const;
    void terminate();
    void growSpace(size_t);

private:
    /// externally allocated buffer we were seeded with (or a zero-size one)
    StoreIOBuffer readerSuppliedMemory_;

    /// our internal buffer that takes over readerSuppliedMemory_ when the
    /// latter becomes full and more memory is needed
    std::optional<SBuf> extraMemory_;

    /// \copydoc contentSize()
    size_t size_ = 0;
};

inline std::ostream &
operator <<(std::ostream &os, const ParsingBuffer &b)
{
    b.print(os);
    return os;
}


} // namespace Store

#endif /* SQUID_STOREIOBUFFER_H */

