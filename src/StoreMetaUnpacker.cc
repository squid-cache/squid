/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Swapfile Unpacker */

#include "squid.h"
#include "base/TextException.h"
#include "defines.h"
#include "StoreMeta.h"
#include "StoreMetaUnpacker.h"

/* Store::SwapMetaIterator */

Store::SwapMetaIterator::SwapMetaIterator(const void * const start, const void * const end):
    fieldStart_(static_cast<const char*>(start)),
    bufEnd_(end)
{
    sync();
}

Store::SwapMetaIterator &
Store::SwapMetaIterator::operator++()
{
    Assure(fieldStart_ != bufEnd_);
    fieldStart_ += sizeof(RawSwapMetaType); // swap meta type
    fieldStart_ += sizeof(int); // swap meta value length
    fieldStart_ += meta_.rawLength; // swap meta value

    sync();
    return *this;
}

/// (re)set meta_
void
Store::SwapMetaIterator::sync()
{
    if (fieldStart_ == bufEnd_)
        return; // nothing to do when we reach the end of iteration

    // We cannot start beyond the end of the header: We start with valid
    // begin/end buffer pointers, and each field checks for overreach.
    Assure(fieldStart_ < bufEnd_);

    meta_ = SwapMetaView(fieldStart_, bufEnd_);
}

/* StoreMetaUnpacker */

StoreMetaUnpacker::StoreMetaUnpacker(const char * const buf, const ssize_t size, int * const swap_hdr_len)
{
    Assure(buf);
    Assure(size >= 0);

    // buffer = <metadata> [HTTP response byte]...
    // metadata = <prefix> [metadata field]...
    // prefix = <magic> <metadata size a.k.a. swap_hdr_len>
    // We parse the prefix and then skip it, ready to iterate metadata fields.

    const auto requiredPrefixSize = sizeof(Store::RawSwapMetaType) + sizeof(int);
    Assure2(uint64_t(size) >= requiredPrefixSize, "parsing buffer accommodates metadata prefix");

    if (buf[0] != Store::SwapMetaMagic)
        throw TextException("store entry metadata prefix is corrupted", Here());

    int rawMetaSize = 0; // metadata size, including the required prefix
    memcpy(&rawMetaSize, &buf[1], sizeof(rawMetaSize));

    if (rawMetaSize < 0)
        throw TextException("store entry metadata length is corrupted", Here());

    if (rawMetaSize > size)
        throw TextException("store entry metadata is too big", Here());

    if (size_t(rawMetaSize) < requiredPrefixSize)
        throw TextException("store entry metadata is too small", Here());

    metas = buf + requiredPrefixSize;
    metasSize = size_t(rawMetaSize) - requiredPrefixSize;
    Assure(metas + metasSize <= buf + size); // paranoid

    Assure(swap_hdr_len);
    *swap_hdr_len = rawMetaSize;
}

