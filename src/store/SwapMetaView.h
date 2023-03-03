/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_STORE_SWAPMETAVIEW_H
#define SQUID_SRC_STORE_SWAPMETAVIEW_H

#include "store/SwapMeta.h"

#include <iosfwd>

namespace Store {

/// a swap metadata field inside the buffer given to SwapMetaUnpacker
class SwapMetaView
{
public:
    /// ensures that our fixed-size field value has the given expected length
    void checkExpectedLength(size_t) const;

public:
    /// A serialized rawLength-byte value (i.e. V in swap meta TLV field).
    /// The value contents may be completely malformed/bogus.
    /// Not meaningful when type is STORE_META_VOID.
    const void *rawValue = nullptr;

    /// The number of bytes in rawValue (i.e. L in swap meta TLV field).
    /// This length may not match the length of valid fields of this type.
    /// Not meaningful when type is STORE_META_VOID.
    size_t rawLength = 0;

    /// The serialized type (i.e. T in swap meta TLV field).
    /// This type value may not match any named by SwapMetaType.
    RawSwapMetaType rawType = RawSwapMetaTypeBottom;

    /// The sanitized TLV type that always matches one named by SwapMetaType:
    /// rawType (if matches a value named by SwapMetaType) or STORE_META_VOID.
    SwapMetaType type = STORE_META_VOID;

private:
    /*
     * SwapMetaView objects should always be accessed through SwapMetaIterator
     * or SwapMetaUnpacker for read-only access to the current view of metadata.
     */
    friend class SwapMetaIterator;

    SwapMetaView() = default;
    SwapMetaView(const SwapMetaView &) = default;
    SwapMetaView(SwapMetaView &&) = default;
    SwapMetaView &operator =(const SwapMetaView &) = default;
    SwapMetaView &operator =(SwapMetaView &&) = default;

    /// positions the view at the first swap meta field in the given buffer
    /// \param begin is where the buffer and the field starts
    /// \param end is where the buffer (but not necessarily the field) finishes
    explicit SwapMetaView(const void *begin, const void * const end);
};

/// a helper function to safely copy raw end-bounded serialized input into the
/// given item and advance that input to the next item
template <typename Item>
void
SwapMetaExtract(Item &item, const char * &input, const void *end)
{
    if (input + sizeof(item) > end)
        throw TextException("truncated swap meta part", Here());
    memcpy(&item, input, sizeof(item));
    input += sizeof(item);
}

/// writes a short human-readable summary of the given SwapMetaView object
std::ostream &operator <<(std::ostream &, const SwapMetaView &);

} // namespace Store

#endif /* SQUID_SRC_STORE_SWAPMETAVIEW_H */

