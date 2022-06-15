/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_TYPELENGTHVALUE_H
#define SQUID_TYPELENGTHVALUE_H

#include "defines.h"
#include "store/forward.h"

#include <iosfwd>
#include <limits>

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
 \par
 * The holes in enum item values below represent deprecated/reserved IDs.
 * \sa Store::IgnoredSwapMetaType()
 */
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

    // When adding values, update Store::SwapMetaTypeMax().
    // When removing values, check Store::IgnoredSwapMetaType() and friends.
};

namespace Store {

/// swap meta type ID written to or loaded from Store
using RawSwapMetaType = char;

/// Store entries with longer swap metadata field values are not swapped out and
/// are considered invalid when validating being-loaded metadata. This arbitrary
/// limit protects code that adds individual swap metadata field sizes from
/// overflowing and also prevents allocation of huge buffers when loading
/// variable-length fields. Reevaluate this limit when increasing MAX_URL.
const size_t SwapMetaFieldValueLengthMax = 64*1024;

static_assert(SwapMetaFieldValueLengthMax >= MAX_URL, "MAX_URL will fit in a Swap meta field");

// TODO: Move to src/store/SwapMetaReading or similar, along with StoreMetaUnpacker.
/// a swap metadata field inside the buffer given to StoreMetaUnpacker
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
    Store::RawSwapMetaType rawType = 0;

    /// The sanitized TLV type that always matches one named by SwapMetaType:
    /// rawType (if matches a value named by SwapMetaType) or STORE_META_VOID.
    SwapMetaType type = STORE_META_VOID;

private:
    /*
     * These construction/copying methods are private so that no outside code
     * can create/own SwapMetaView objects but SwapMetaIterator. Others loop
     * StoreMetaUnpacker for read-only access to the current view of metadata.
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

/// the start of the swap meta section
const char SwapMetaMagic = 0x03;

// TODO: Move to src/store/SwapMetaWriting or similar.
/// Swap meta prefix and all swap meta fields of the given Store entry
const char *PackSwapHeader(const StoreEntry &, size_t &totalLength);

} // namespace Store

/// writes a short human-readable summary of the given SwapMetaView object
std::ostream &operator <<(std::ostream &, const Store::SwapMetaView &);

#endif /* SQUID_TYPELENGTHVALUE_H */

