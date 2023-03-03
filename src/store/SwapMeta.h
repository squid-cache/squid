/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_STORE_SWAPMETA_H
#define SQUID_SRC_STORE_SWAPMETA_H

#include "defines.h"

#include <limits>

// store swap metadata interfaces shared by input and output code

namespace Store {

/// "Swap meta" (a.k.a. "swap header") is Store entry metadata stored at the
/// beginning of each cache_dir entry. This entry-dependent metadata typically
/// includes entry cache key, URL, size, and various timestamps. Copies of this
/// information may also be present in Squid process memory, readily accessible
/// via StoreEntry and MemObject pointers, but swap metadata is about cached
/// entry information stored in serialized form meant to cross process and
/// instance boundaries.
///
/// Layout of swap metadata (for a single Store entry) in pseudo code:
/// struct SwapMeta {
///     struct Prefix {
///         char magic; // see SwapMetaMagic
///         int swap_hdr_sz; // total SwapMeta size: prefix and all fields
///     };
///     Prefix prefix;
///
///     struct TLV {
///         char type; // value meaning (and format); see SwapMetaType
///         int length; // value length in octets
///         char value[length]; // type-specific storage; exactly length bytes
///     };
///     TLV fields[]; // as many swap meta fields as swap_hdr_sz accommodates
///
///     // XXX: int fields above should have been using a fixed-size type.
/// };
///
/// Stored response (e.g., HTTP headers and body) follows swap metadata.

/// Identifies the meaning (and associated format) of a single swap meta field.
/// This enumeration only contains identifiers used by the current code.
/// The gaps in the enum item values below represent deprecated/reserved IDs.
/// \sa DeprecatedSwapMetaType(), ReservedSwapMetaType()
enum SwapMetaType {
    /// An invalid swap metadata field or field with an unknown meaning.
    /// Never used by swapout code.
    STORE_META_VOID = 0,

    /// This represents the MD5 cache key that Squid currently uses. When Squid
    /// opens a disk file for reading, it can check that this MD5 matches the
    /// MD5 of the user's request. If not, then something went wrong and this is
    /// probably the wrong object.
    STORE_META_KEY_MD5 = 3,

    /// The object's URL. This also may be matched against a user's request for
    /// cache hits to make sure we got the right object.
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

    /// Stores Vary request headers.
    STORE_META_VARY_HEADERS = 8,

    /// Modern STORE_META_STD version, with 64-bit swap_file_sz supporting
    /// objects larger than 2GB.
    STORE_META_STD_LFS = 9,

    // TODO: Document this type after we start using it; see UnpackHitSwapMeta()
    STORE_META_OBJSIZE = 10
};

/// The type of a serialized swap meta field part called "type" (i.e. T in TLV).
/// Meant for storing the serialized version of SwapMetaType.
using RawSwapMetaType = char;

/// The type of a serialized swap meta field part called "length" (i.e. L in TLV).
/// Valid values of this type do not include the size of T and L components.
/// Low-level serialization code aside, we use size_t for swap meta field sizes.
using RawSwapMetaLength = int;

/// Store entries with larger (serialized) swap metadata field values are not
/// swapped out and are considered invalid when validating being-loaded entries.
/// This arbitrary limit protects code that adds individual swap metadata field
/// sizes from overflowing and prevents allocation of huge buffers when loading
/// variable-length fields. Reevaluate this limit when increasing MAX_URL.
const size_t SwapMetaFieldValueLengthMax = 64*1024;

static_assert(SwapMetaFieldValueLengthMax >= MAX_URL, "MAX_URL will fit in a swap meta field");
static_assert(SwapMetaFieldValueLengthMax <= uint64_t(std::numeric_limits<RawSwapMetaLength>::max()), "any swap metadata value size can be stored as RawSwapMetaLength");

/// the start of the swap meta section
const char SwapMetaMagic = 0x03;

/// The type of the serialized "metadata size" field that follows SwapMetaMagic.
/// Together, the two fields form a swap metadata "prefix". The meaning of this
/// size field is different from RawSwapMetaLength! Valid values of this field
/// include the prefix size itself.
using RawSwapMetaPrefixLength = int;

/// The size of the initial (and required) portion of any swap metadata
const auto SwapMetaPrefixSize = sizeof(SwapMetaMagic) + sizeof(RawSwapMetaPrefixLength);

/// SwapMetaType IDs will never have this or smaller serialized value.
/// This is not the smallest RawSwapMetaType value (that is usually -128).
const RawSwapMetaType RawSwapMetaTypeBottom = 0;

/// Maximum value of a serialized SwapMetaType ID.
/// This is not the largest RawSwapMetaType value (that is usually +127).
inline constexpr RawSwapMetaType
RawSwapMetaTypeTop()
{
    // This "constant" switch forces developers to update this function when
    // they add SwapMetaType values [-Wswitch]. It is better than an end_ enum
    // marker because it does not force us to add that marker to every switch
    // statement, with an assert(false) or similar "unreachable code" handler.
    // Optimizing compilers optimize this statement away into a constant.
    // The non-constant variable is needed for older compilers.

    // always use the last/maximum enum value here
    auto top = STORE_META_OBJSIZE;
    switch (top) {
    case STORE_META_VOID:
    case STORE_META_KEY_MD5:
    case STORE_META_URL:
    case STORE_META_STD:
    case STORE_META_VARY_HEADERS:
    case STORE_META_STD_LFS:
    case STORE_META_OBJSIZE:
        break;
    }
    return top;
}

/// Whether the given raw swap meta field type represents a type that we should
/// inform the admin about (if found in a store) but can otherwise ignore.
inline constexpr bool
DeprecatedSwapMetaType(const RawSwapMetaType type)
{
    enum class DeprecatedMetas {
        /// \deprecated Using URL as the cache key, as in Squid-1.1.
        STORE_META_KEY_URL = 1,
        /// \deprecated Using SHA (secure hash algorithm) as a cache key
        STORE_META_KEY_SHA = 2,
        /// \deprecated hit-metering (RFC 2227)
        STORE_META_HITMETERING = 6,
        /// \deprecated
        STORE_META_VALID = 7
    };
    return
        type == static_cast<RawSwapMetaType>(DeprecatedMetas::STORE_META_KEY_URL) ||
        type == static_cast<RawSwapMetaType>(DeprecatedMetas::STORE_META_KEY_SHA) ||
        type == static_cast<RawSwapMetaType>(DeprecatedMetas::STORE_META_HITMETERING) ||
        type == static_cast<RawSwapMetaType>(DeprecatedMetas::STORE_META_VALID);
}

/// Whether the given raw swap meta field type represents a type that we should
/// ignore without informing the admin.
inline constexpr bool
ReservedSwapMetaType(const RawSwapMetaType type)
{
    enum class ReservedMetas {
        /// the Store-ID url, if different from the normal URL
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
/// SwapMetaType enum values except for the never-stored STORE_META_VOID.
inline constexpr bool
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
inline constexpr bool
IgnoredSwapMetaType(const RawSwapMetaType type)
{
    return DeprecatedSwapMetaType(type) || ReservedSwapMetaType(type);
}

/// Expected size of a STORE_META_STD_LFS swap meta field. XXX: The actual size
/// is environment-specific due to 4 parts that do not use fixed-size types.
const auto STORE_HDR_METASIZE =
    4*sizeof(time_t) + sizeof(uint64_t) + 2*sizeof(uint16_t);

/// Expected size of a STORE_META_STD swap meta field. XXX: The actual size is
/// environment-specific due to 5 parts that do not use fixed-size types.
const auto STORE_HDR_METASIZE_OLD =
    4*sizeof(time_t) + sizeof(size_t) + 2*sizeof(uint16_t);

/// Ensures that the given serialized swap meta field is valid and can be
/// subsequently de-serialized (by the same code). Also detects some failures to
/// update one of the classification functions above when editing SwapMetaType.
void CheckSwapMetaSerialization(RawSwapMetaType, RawSwapMetaLength, const void *);

} // namespace Store

#endif /* SQUID_SRC_STORE_SWAPMETA_H */

