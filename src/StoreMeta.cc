/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Swapfile Metadata */

#include "squid.h"
#include "sbuf/Stream.h"
#include "StoreMeta.h"

namespace Store {

/// Whether the given raw swap meta field type represents a type that we should
/// inform the admin about (if found in a store) but can otherwise ignore.
inline bool
DeprecatedSwapMetaType(const RawSwapMetaType type)
{
    enum class DeprecatedMetas {
        /// \deprecated Using URL as the cache key, as in Squid-1.1.
        STORE_META_KEY_URL = 1,
        /// \deprecated Using SHA (secure hash algorithm) as a cache key
        STORE_META_KEY_SHA = 2,
        /// \deprecated hit-metering (RFC 2227)
        STORE_META_HITMETERING = 6,
        STORE_META_VALID = 7
    };
    return
        // TODO: simplify with std::underlying_type_t when switching to C++14
        type == static_cast<RawSwapMetaType>(DeprecatedMetas::STORE_META_HITMETERING) ||
        type == static_cast<RawSwapMetaType>(DeprecatedMetas::STORE_META_KEY_SHA) ||
        type == static_cast<RawSwapMetaType>(DeprecatedMetas::STORE_META_HITMETERING) ||
        type == static_cast<RawSwapMetaType>(DeprecatedMetas::STORE_META_VALID);
}

/// Whether the given raw swap meta field type represents a type that we should
/// ignore without informing the admin.
inline bool
ReservedSwapMetaType(const RawSwapMetaType type)
{
    enum class ReservedMetas {
        /// the Store-ID url, if different to the normal URL
        STORE_META_STOREURL = 11,
        /// unique ID linking variants
        STORE_META_VARY_ID = 12
    };
    return
        type == static_cast<RawSwapMetaType>(ReservedMetas::STORE_META_STOREURL) ||
        type == static_cast<RawSwapMetaType>(ReservedMetas::STORE_META_VARY_ID);
}

/// Whether the given raw swap meta field type can be safely ignored.
/// \sa HonoredSwapMetaType()
inline bool
IgnoredSwapMetaType(const RawSwapMetaType type)
{
    return DeprecatedSwapMetaType(type) || ReservedSwapMetaType(type);
}

/// Whether we store the given swap meta field type (and also interpret the
/// corresponding swap meta field when the Store loads it). Matches all
/// SwapMetaType enum values except for the never-stored/loaded STORE_META_VOID.
inline bool
HonoredSwapMetaType(const RawSwapMetaType type)
{
    return STORE_META_VOID < type && type <= SwapMetaTypeMax && !IgnoredSwapMetaType(type);
}

/// properly reports or rejects a problematic raw swap meta field type
static void
HandleBadRawType(const RawSwapMetaType type)
{
    if (ReservedSwapMetaType(type)) {
        debugs(20, 3, "ignoring swap meta field with a reserved type: " << int(type));
        return;
    }

    if (DeprecatedSwapMetaType(type)) {
        debugs(20, DBG_CRITICAL, "ERROR: Ignoring swap meta field with a deprecated type: " << int(type));
        return;
    }

    // TODO: Instead of assuming that all future swap meta types can be ignored
    // (and some should be reported at level-0/1), future-proof this code by
    // using a type bit to define whether to silently ignore a swap meta field
    // with that type (or even the whole Store entry with that field).

    if (type > 10 && type - 10 > SwapMetaTypeMax) {
        debugs(20, DBG_CRITICAL, "ERROR: Malformed cache storage; ignoring swap meta field with an unexpected type: " << int(type));
        return;
    }

    if (type > SwapMetaTypeMax) {
        debugs(20, 3, "ignoring swap meta field with a presumed future type: " << int(type));
        return;
    }

    Assure(type <= STORE_META_VOID);
    debugs(20, DBG_CRITICAL, "ERROR: Malformed cache storage; ignoring swap meta field with an invalid type: " << int(type));
}

/// a helper function to safely extract one item from raw bounded input
/// and advance input to the next item
template <typename T>
static void
Deserialize(T &item, const char * &input, const void *end)
{
    if (input + sizeof(item) > end)
        throw TextException("truncated swap meta field", Here());
    memcpy(&item, input, sizeof(item));
    input += sizeof(item);
}

} // namespace Store

Store::SwapMetaView::SwapMetaView(const void * const begin, const void * const end)
{
    auto input = static_cast<const char *>(begin);

    Deserialize(rawType, input, end);
    if (HonoredSwapMetaType(rawType))
        type = static_cast<SwapMetaType>(rawType);
    else
        HandleBadRawType(rawType); // and leave type as STORE_META_VOID

    int lengthOrGarbage = 0;
    Deserialize(lengthOrGarbage, input, end);
    if (lengthOrGarbage < 0)
        throw TextException("negative swap meta field length value", Here());
    if (uint64_t(lengthOrGarbage) > SwapMetaFieldValueLengthMax)
        throw TextException("huge swap meta field length value", Here());
    if (input + lengthOrGarbage > end)
        throw TextException("truncated swap meta field value", Here());
    rawLength = static_cast<size_t>(lengthOrGarbage);

    Assure(input >= begin);
    Assure(input <= end);
    rawValue = input;
}

void
Store::SwapMetaView::checkExpectedLength(const size_t expectedLength) const
{
    if (rawLength != expectedLength)
        throw TextException(ToSBuf("Bad value length in a Store entry meta field expecting a ",
                            expectedLength, "-byte value: ", *this), Here());
}

std::ostream &
operator <<(std::ostream &os, const Store::SwapMetaView &meta)
{
    os << "type=" << int(meta.rawType) << " length=" << meta.rawLength;
    return os;
}

