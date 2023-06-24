/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_STORE_PARSINGBUFFER_H
#define SQUID_SRC_STORE_PARSINGBUFFER_H

#include "sbuf/SBuf.h"
#include "StoreIOBuffer.h"

#include <optional>

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
    ParsingBuffer() = default;

    /// seeds this buffer with the caller-supplied buffer space
    explicit ParsingBuffer(StoreIOBuffer &);

    /// a NUL-terminated version of content(); same lifetime as content()
    const char *c_str() { terminate(); return memory(); }

    /// export content() into SBuf, avoiding content copying when possible
    SBuf toSBuf() const;

    /// the total number of append()ed bytes that were not consume()d
    size_t contentSize() const;

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
    /// \prec positive contentSize() (\sa store_client::finishCallback())
    StoreIOBuffer packBack();

    /// summarizes object state (for debugging)
    void print(std::ostream &) const;

private:
    const char *memory() const;
    void terminate();
    void growSpace(size_t);

private:
    /// externally allocated buffer we were seeded with (or a zero-size one)
    StoreIOBuffer readerSuppliedMemory_;

    /// append()ed to readerSuppliedMemory_ bytes that were not consume()d
    size_t readerSuppliedMemoryContentSize_ = 0;

    /// our internal buffer that takes over readerSuppliedMemory_ when the
    /// latter becomes full and more memory is needed
    std::optional<SBuf> extraMemory_;
};

inline std::ostream &
operator <<(std::ostream &os, const ParsingBuffer &b)
{
    b.print(os);
    return os;
}

} // namespace Store

#endif /* SQUID_SRC_STORE_PARSINGBUFFER_H */

