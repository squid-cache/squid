/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "sbuf/Stream.h"
#include "SquidMath.h"
#include "store/ParsingBuffer.h"

#include <iostream>

// Several Store::ParsingBuffer() methods use assert() because the corresponding
// failure means there is a good chance that somebody have already read from (or
// written to) the wrong memory location. Since this buffer is used for storing
// HTTP response bytes, such failures may corrupt traffic. No Assure() handling
// code can safely recover from such failures.

Store::ParsingBuffer::ParsingBuffer(StoreIOBuffer &initialSpace):
    readerSuppliedMemory_(initialSpace)
{
}

/// a read-only content start (or nil for some zero-size buffers)
const char *
Store::ParsingBuffer::memory() const
{
    return extraMemory_ ? extraMemory_->rawContent() : readerSuppliedMemory_.data;
}

size_t
Store::ParsingBuffer::capacity() const
{
    return extraMemory_ ? (extraMemory_->length() + extraMemory_->spaceSize()) : readerSuppliedMemory_.length;
}

size_t
Store::ParsingBuffer::contentSize() const
{
    return extraMemory_ ? extraMemory_->length() : readerSuppliedMemoryContentSize_;
}

void
Store::ParsingBuffer::appended(const char * const newBytes, const size_t newByteCount)
{
    // a positive newByteCount guarantees that, after the first assertion below
    // succeeds, the second assertion will not increment a nil memory() pointer
    if (!newByteCount)
        return;

    // these checks order guarantees that memory() is not nil in the second assertion
    assert(newByteCount <= spaceSize()); // the new bytes end in our space
    assert(memory() + contentSize() == newBytes); // the new bytes start in our space
    // and now we know that newBytes is not nil either

    if (extraMemory_)
        extraMemory_->rawAppendFinish(newBytes, newByteCount);
    else
        readerSuppliedMemoryContentSize_ = *IncreaseSum(readerSuppliedMemoryContentSize_, newByteCount);

    assert(contentSize() <= capacity()); // paranoid
}

void
Store::ParsingBuffer::consume(const size_t parsedBytes)
{
    Assure(contentSize() >= parsedBytes); // more conservative than extraMemory_->consume()
    if (extraMemory_) {
        extraMemory_->consume(parsedBytes);
    } else {
        readerSuppliedMemoryContentSize_ -= parsedBytes;
        if (parsedBytes && readerSuppliedMemoryContentSize_)
            memmove(readerSuppliedMemory_.data, memory() + parsedBytes, readerSuppliedMemoryContentSize_);
    }
}

StoreIOBuffer
Store::ParsingBuffer::space()
{
    const auto size = spaceSize();
    const auto start = extraMemory_ ?
                       extraMemory_->rawAppendStart(size) :
                       (readerSuppliedMemory_.data + readerSuppliedMemoryContentSize_);
    return StoreIOBuffer(spaceSize(), 0, start);
}

StoreIOBuffer
Store::ParsingBuffer::makeSpace(const size_t pageSize)
{
    growSpace(pageSize);
    auto result = space();
    Assure(result.length >= pageSize);
    result.length = pageSize;
    return result;
}

StoreIOBuffer
Store::ParsingBuffer::content() const
{
    // This const_cast is a StoreIOBuffer API limitation: That class does not
    // support a "constant content view", even though it is used as such a view.
    return StoreIOBuffer(contentSize(), 0, const_cast<char*>(memory()));
}

/// makes sure we have the requested number of bytes, allocates enough memory if needed
void
Store::ParsingBuffer::growSpace(const size_t minimumSpaceSize)
{
    const auto capacityIncreaseAttempt = IncreaseSum(contentSize(), minimumSpaceSize);
    if (!capacityIncreaseAttempt)
        throw TextException(ToSBuf("no support for a single memory block of ", contentSize(), '+', minimumSpaceSize, " bytes"), Here());
    const auto newCapacity = *capacityIncreaseAttempt;

    if (newCapacity <= capacity())
        return; // already have enough space; no reallocation is needed

    debugs(90, 7, "growing to provide " << minimumSpaceSize << " in " << *this);

    if (extraMemory_) {
        extraMemory_->reserveCapacity(newCapacity);
    } else {
        SBuf newStorage;
        newStorage.reserveCapacity(newCapacity);
        newStorage.append(readerSuppliedMemory_.data, readerSuppliedMemoryContentSize_);
        extraMemory_ = std::move(newStorage);
    }
    Assure(spaceSize() >= minimumSpaceSize);
}

SBuf
Store::ParsingBuffer::toSBuf() const
{
    return extraMemory_ ? *extraMemory_ : SBuf(content().data, content().length);
}

size_t
Store::ParsingBuffer::spaceSize() const
{
    if (extraMemory_)
        return extraMemory_->spaceSize();

    assert(readerSuppliedMemoryContentSize_ <= readerSuppliedMemory_.length);
    return readerSuppliedMemory_.length - readerSuppliedMemoryContentSize_;
}

/// 0-terminates stored byte sequence, allocating more memory if needed, but
/// without increasing the number of stored content bytes
void
Store::ParsingBuffer::terminate()
{
    *makeSpace(1).data = 0;
}

StoreIOBuffer
Store::ParsingBuffer::packBack()
{
    const auto bytesToPack = contentSize();
    // until our callers do not have to work around legacy code expectations
    Assure(bytesToPack);

    // if we accumulated more bytes at some point, any extra metadata should
    // have been consume()d by now, allowing readerSuppliedMemory_.data reuse
    Assure(bytesToPack <= readerSuppliedMemory_.length);

    auto result = readerSuppliedMemory_;
    result.length = bytesToPack;
    Assure(result.data);

    if (!extraMemory_) {
        // no accumulated bytes copying because they are in readerSuppliedMemory_
        debugs(90, 7, "quickly exporting " << result.length << " bytes via " << readerSuppliedMemory_);
    } else {
        debugs(90, 7, "slowly exporting " << result.length << " bytes from " << extraMemory_->id << " back into " << readerSuppliedMemory_);
        memmove(result.data, extraMemory_->rawContent(), result.length);
    }

    return result;
}

void
Store::ParsingBuffer::print(std::ostream &os) const
{
    os << "size=" << contentSize();

    if (extraMemory_) {
        os << " capacity=" << capacity();
        os << " extra=" << extraMemory_->id;
    }

    // report readerSuppliedMemory_ (if any) even if we are no longer using it
    // for content storage; it affects packBack() and related parsing logic
    if (readerSuppliedMemory_.length)
        os << ' ' << readerSuppliedMemory_;
}

