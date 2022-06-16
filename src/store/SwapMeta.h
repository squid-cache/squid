/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_STORE_SWAPMETA_H
#define SQUID_SRC_STORE_SWAPMETA_H

#include "defines.h"

#include <limits>

// basic store swap metadata interfaces shared by input and output code

namespace Store {

/**
 *
 \section StoreSwapMeta Store "swap meta" Description
 \par
 * Store "swap meta" is Store entry metadata stored at the beginning of each
 * cache_dir entry. This entry-dependent metadata typically includes entry cache
 * key, URL, size, and various timestamps. Copies of this information may also
 * be present in Squid process memory, readily accessible via StoreEntry and
 * MemObject pointers, but swap metadata is about cached entry information
 * stored in serialized form meant to cross process and instance boundaries.
 *
 \par
 * The meta data is stored using a TYPE-LENGTH-VALUE format.  That is,
 * each chunk of meta information consists of a TYPE identifier, a
 * LENGTH field, and then the VALUE (which is LENGTH octets long).
 *
 */

// XXX: Document properly
// TODO: Check that StoreSwapMeta reference below works
/// The holes in enum item values below represent deprecated/reserved IDs.
/// \sa StoreSwapMeta, DeprecatedSwapMetaType(), ReservedSwapMetaType()
enum SwapMetaType {
    /// Store swap metadata type with an unknown meaning.
    /// Never used by valid stored entries.
    STORE_META_VOID = 0,

    /**
     * This represents the MD5 cache key that Squid currently uses.
     * When Squid opens a disk file for reading, it can check that
     * this MD5 matches the MD5 of the user's request.  If not, then
     * something went wrong and this is probably the wrong object.
     * Also known under its deprecated STORE_META_KEY name.
     */
    STORE_META_KEY_MD5 = 3,

    /**
     * The object's URL.  This also may be matched against a user's
     *  request for cache hits to make sure we got the right object.
     */
    STORE_META_URL = 4,

    /**
     * This is the "standard metadata" for an object.
     * Really its just this middle chunk of the StoreEntry structure:
     \code
        time_t timestamp;
        time_t lastref;
        time_t expires;
        time_t lastmod;
        uint64_t swap_file_sz;
        uint16_t refcount;
        uint16_t flags;
     \endcode
     */
    STORE_META_STD = 5,

    /**
     * Stores Vary request headers
     */
    STORE_META_VARY_HEADERS = 8,

    /**
     * Updated version of STORE_META_STD, with support for  >2GB objects.
     * As STORE_META_STD except that the swap_file_sz is a 64-bit integer instead of 32-bit.
     */
    STORE_META_STD_LFS = 9,

    // TODO: document this TLV type code
    STORE_META_OBJSIZE = 10

    // Add new values here. The compiler or "make check" should catch mistakes,
    // but keep SwapMetaTypeMax(), DeprecatedSwapMetaType(), and
    // ReservedSwapMetaType() in sync with your changes.

    // When removing values, update DeprecatedSwapMetaType().
};

/// swap meta type ID written to or loaded from Store
using RawSwapMetaType = char;

/// The type of a serialized length field of a swap meta field (i.e. L in TLV).
/// Valid values of this type do not include the size of T and L components.
/// Lowest-level serialization code aside, we use size_t for swap meta sizes.
using RawSwapMetaLength = int;

/// Store entries with longer swap metadata field values are not swapped out and
/// are considered invalid when validating being-loaded metadata. This arbitrary
/// limit protects code that adds individual swap metadata field sizes from
/// overflowing and also prevents allocation of huge buffers when loading
/// variable-length fields. Reevaluate this limit when increasing MAX_URL.
const size_t SwapMetaFieldValueLengthMax = 64*1024;

static_assert(SwapMetaFieldValueLengthMax >= MAX_URL, "MAX_URL will fit in a Swap meta field");
static_assert(SwapMetaFieldValueLengthMax <= uint64_t(std::numeric_limits<RawSwapMetaLength>::max()), "any swap metadata value size can be stored as RawSwapMetaLength");

/// the start of the swap meta section
const char SwapMetaMagic = 0x03;

/// The type of the serialized "metadata size" field that follows SwapMetaMagic.
/// Together, the two fields form a swap metadata "prefix". The meaning of this
/// size field is different from RawSwapMetaLength! Valid values of this field
/// include the prefix size itself.
using RawSwapMetaPrefixLength = int;

// TODO: Use "inline constexpr ..." with C++17.
/// maximum value of a named swap meta type
inline SwapMetaType
SwapMetaTypeMax()
{
    // This "constant" switch forces developers to update this function when
    // they add new type values [-Wswitch]. It is better than an end_ enum
    // marker because it does not force us to add that marker to every switch
    // statement, with an assert(false) or similar "unreachable code" handler.
    // Compilers optimize this statement away into a constant, of course.
    switch (STORE_META_VOID) {
    case STORE_META_VOID:
    case STORE_META_KEY_MD5:
    case STORE_META_URL:
    case STORE_META_STD:
    case STORE_META_VARY_HEADERS:
    case STORE_META_STD_LFS:
    case STORE_META_OBJSIZE:
        // always return the last/maximum enum value
        return STORE_META_OBJSIZE;
    }
}

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
        type == static_cast<RawSwapMetaType>(DeprecatedMetas::STORE_META_KEY_URL) ||
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

/// Whether we store the given swap meta field type (and also interpret the
/// corresponding swap meta field when the Store loads it). Matches all
/// SwapMetaType enum values except for the never-stored/loaded STORE_META_VOID.
inline bool
HonoredSwapMetaType(const RawSwapMetaType type)
{
    switch (type) {
    case STORE_META_VOID:
        return false;

    case STORE_META_KEY_MD5:
    case STORE_META_URL:
    case STORE_META_STD:
    case STORE_META_VARY_HEADERS:
    case STORE_META_STD_LFS:
    case STORE_META_OBJSIZE:
        return true;

    default:
        return false;
    }
}

/// Whether the given raw swap meta field type can be safely ignored.
/// \sa HonoredSwapMetaType()
inline bool
IgnoredSwapMetaType(const RawSwapMetaType type)
{
    return DeprecatedSwapMetaType(type) || ReservedSwapMetaType(type);
}

/// Ensures that the given swap meta field can be successfully serialized and
/// subsequently de-serialized (by the same code). Also detects some failures to
/// update one of the classification functions above when editing SwapMetaType.
void CheckSwapMetaSerialization(RawSwapMetaType, RawSwapMetaLength, const void *);

} // namespace Store

#endif /* SQUID_SRC_STORE_SWAPMETA_H */

