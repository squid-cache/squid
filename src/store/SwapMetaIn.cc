/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Raw.h"
#include "base/TextException.h"
#include "int.h"
#include "md5.h"
#include "MemObject.h"
#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"
#include "SquidMath.h"
#include "Store.h"
#include "store/SwapMeta.h"
#include "store/SwapMetaIn.h"
#include "store/SwapMetaView.h"

namespace Store {

/// iterates serialized swap meta fields loaded into a given buffer
class SwapMetaIterator
{
public:
    /* some of the standard iterator traits */
    using iterator_category = std::forward_iterator_tag;
    using value_type = const SwapMetaView;
    using pointer = value_type *;
    using reference = value_type &;

    /// positions iterator at the start of a swap meta field extending up to end
    SwapMetaIterator(const void *start, const void *end);

    /* some of the standard iterator methods */
    reference operator *() const { return meta_; }
    pointer operator ->() const { return &meta_; }
    SwapMetaIterator& operator++();
    bool operator ==(const SwapMetaIterator &them) const { return fieldStart_ == them.fieldStart_; }
    bool operator !=(const SwapMetaIterator &them) const { return !(*this == them); }

private:
    void sync();

    const char *fieldStart_; ///< the start of the current field
    const void * const bufEnd_; ///< last field must end at this boundary
    SwapMetaView meta_; ///< current field; valid after sync() and before end
};

/// Store entry metadata view providing a for-range loop meta field iterator API
class SwapMetaUnpacker
{
public:
    SwapMetaUnpacker(const char *buf, ssize_t bufferLength, size_t &swap_hdr_sz);

    // for-range loop API for iterating over serialized swap metadata fields
    using Iterator = SwapMetaIterator;
    Iterator cbegin() const { return Iterator(metas, metas + metasSize); }
    Iterator cend() const { return Iterator(metas + metasSize, metas + metasSize); }
    Iterator begin() const { return cbegin(); }
    Iterator end() const { return cend(); }

private:
    const char *metas; ///< metadata field(s)
    size_t metasSize; ///< number of bytes in the metas buffer
};

/// validates serialized STORE_META_KEY_MD5 swap meta field
static void
CheckSwapMetaKey(const SwapMetaView &meta, const StoreEntry &entry)
{
    Assure(meta.type == STORE_META_KEY_MD5);
    meta.checkExpectedLength(SQUID_MD5_DIGEST_LENGTH);

    if (!EBIT_TEST(entry.flags, KEY_PRIVATE) &&
            memcmp(meta.rawValue, entry.key, SQUID_MD5_DIGEST_LENGTH) != 0) {

        debugs(20, 2, "stored key mismatches " << entry.getMD5Text());

        static unsigned int md5_mismatches = 0;
        if (isPowTen(++md5_mismatches))
            debugs(20, DBG_IMPORTANT, "WARNING: " << md5_mismatches << " swapin MD5 mismatches");

        // TODO: Support TextException::frequent = isPowTen(++md5_mismatches)
        // to suppress reporting, achieving the same effect as above
        throw TextException("swap meta MD5 mismatch", Here());
    }
}

/// deserializes STORE_META_KEY_MD5 swap meta field
static void
UnpackSwapMetaKey(const SwapMetaView &meta, cache_key *key)
{
    Assure(meta.type == STORE_META_KEY_MD5);
    meta.checkExpectedLength(SQUID_MD5_DIGEST_LENGTH);
    Assure(key);
    memcpy(key, meta.rawValue, SQUID_MD5_DIGEST_LENGTH);
}

/// validates serialized STORE_META_URL swap meta field
static void
CheckSwapMetaUrl(const SwapMetaView &meta, const StoreEntry &entry)
{
    Assure(meta.type == STORE_META_URL);

    // PackSwapMeta() terminates; strcasecmp() and reporting below rely on that
    if (!memrchr(meta.rawValue, '\0', meta.rawLength))
        throw TextException("unterminated URI or bad URI length", Here());

    const auto &emem = entry.mem();

    if (!emem.hasUris())
        return; // cannot validate

    const auto storedUrl = static_cast<const char *>(meta.rawValue);
    // XXX: ensure all Squid URL inputs are properly normalized then use case-sensitive compare here
    if (strcasecmp(emem.urlXXX(), storedUrl) != 0) {
        debugs(20, DBG_IMPORTANT, "WARNING: URL mismatch when loading a cached entry:" <<
               Debug::Extra << "expected: " << emem.urlXXX() <<
               Debug::Extra << "found:    " << storedUrl);
        throw TextException("URL mismatch", Here());
    }
}

/// deserializes STORE_META_VARY_HEADERS swap meta field
static SBuf
UnpackNewSwapMetaVaryHeaders(const SwapMetaView &meta, const StoreEntry &entry)
{
    Assure(meta.type == STORE_META_VARY_HEADERS);
    SBuf rawVary(static_cast<const char *>(meta.rawValue), meta.rawLength);
    // entries created before SBuf-based Vary may include string terminator
    static const SBuf nul("\0", 1);
    rawVary.trim(nul, false, true);

    const auto &knownVary = entry.mem().vary_headers;
    if (knownVary.isEmpty())
        return rawVary; // new Vary (that we cannot validate)

    if (knownVary == rawVary)
        return SBuf(); // OK: no new Vary

    throw TextException("Vary mismatch", Here());
}

/// deserializes entry metadata size from the given buffer
/// \retval total swap metadata size (a.k.a. swap_hdr_sz)
static size_t
UnpackPrefix(const char * const buf, const size_t size)
{
    Assure(buf);
    auto input = buf;
    const auto end = buf + size;

    char magic = 0;
    SwapMetaExtract(magic, input, end);

    if (magic != SwapMetaMagic)
        throw TextException("store entry metadata prefix is corrupted", Here());

    RawSwapMetaPrefixLength rawMetaSize = 0; // metadata size, including the required prefix
    SwapMetaExtract(rawMetaSize, input, end);

    if (Less(rawMetaSize, SwapMetaPrefixSize))
        throw TextException("store entry metadata length is corrupted", Here());

    return rawMetaSize; // now safe to use within (buf, buf+size)
}

} // namespace Store

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
    fieldStart_ += sizeof(RawSwapMetaLength); // swap meta value length
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

/* Store::SwapMetaUnpacker */

Store::SwapMetaUnpacker::SwapMetaUnpacker(const char * const buf, const ssize_t size, size_t &swap_hdr_sz)
{
    Assure(buf);
    Assure(size >= 0);

    const auto headerSize = UnpackPrefix(buf, size);

    // We assume the caller supplied a reasonable-size buffer. If our assumption
    // is wrong, then this is a Squid bug rather than input validation failure.
    if (Less(size, headerSize)) {
        throw TextException(ToSBuf("store entry metadata is too big",
                                   Debug::Extra, "buffer size: ", size,
                                   Debug::Extra, "metadata size: ", headerSize),
                            Here());
    }

    Assure2(headerSize >= SwapMetaPrefixSize, "UnpackPrefix() validates metadata length");
    metasSize = headerSize - SwapMetaPrefixSize;

    metas = buf + SwapMetaPrefixSize; // skip prefix
    Assure(metas + metasSize <= buf + size); // paranoid

    swap_hdr_sz = headerSize;
}

size_t
Store::UnpackSwapMetaSize(const SBuf &buf)
{
    return UnpackPrefix(buf.rawContent(), buf.length());
}

size_t
Store::UnpackIndexSwapMeta(const MemBuf &buf, StoreEntry &tmpe, cache_key * const key)
{
    size_t swap_hdr_sz = 0;

    const SwapMetaUnpacker metaFields(buf.content(), buf.contentSize(), swap_hdr_sz);
    for (const auto &meta: metaFields) {
        switch (meta.type) {
        case STORE_META_VOID:
            // this meta.type is the unpacking code signal that it took care of this field
            break;

        case STORE_META_KEY_MD5:
            // Optimization: We could postpone setting the caller's key
            // until all fields are parsed, but that would require copying
            // it. Instead, we treat key and tmpe.key as storage that can be
            // safely altered even on parsing failures. This function
            // description tells the callers that we may do that.
            UnpackSwapMetaKey(meta, key);
            Assure(key);
            tmpe.key = key;
            break;

        case STORE_META_STD: {
            // TODO: Remove. Since old_metahdr's members may have different
            // sizes on different platforms, we cannot guarantee that serialized
            // types in the being-loaded old cache are the same as these types.
            meta.checkExpectedLength(STORE_HDR_METASIZE_OLD);
            struct old_metahdr {
                // XXX: All serialized members must have fixed-size types.
                time_t timestamp;
                time_t lastref;
                time_t expires;
                time_t lastmod;
                size_t swap_file_sz;
                uint16_t refcount;
                uint16_t flags;
            };
            static_assert(offsetof(old_metahdr, flags) + sizeof(old_metahdr::flags) == STORE_HDR_METASIZE_OLD, "we reproduced old swap meta basics format");
            auto basics = static_cast<const old_metahdr*>(meta.rawValue);
            tmpe.timestamp = basics->timestamp;
            tmpe.lastref = basics->lastref;
            tmpe.expires = basics->expires;
            tmpe.lastModified(basics->lastmod);
            tmpe.swap_file_sz = basics->swap_file_sz;
            tmpe.refcount = basics->refcount;
            tmpe.flags = basics->flags;
            break;
        }

        case STORE_META_STD_LFS:
            meta.checkExpectedLength(STORE_HDR_METASIZE);
            memcpy(&tmpe.timestamp, meta.rawValue, STORE_HDR_METASIZE);
            break;

        case STORE_META_URL:
        case STORE_META_VARY_HEADERS:
        case STORE_META_OBJSIZE:
            // We do not load this information at cache index rebuild time;
            // UnpackHitSwapMeta() handles these MemObject fields.
            break;
        }
    }

    return swap_hdr_sz;
}

void
Store::UnpackHitSwapMeta(char const * const buf, const ssize_t len, StoreEntry &entry)
{
    debugs(90, 7, entry << " buf len: " << len);
    assert(len >= 0);

    size_t swap_hdr_sz = 0;
    SBuf varyHeaders;

    const SwapMetaUnpacker metaFields(buf, len, swap_hdr_sz);
    for (const auto &meta: metaFields) {
        switch (meta.type) {
        case STORE_META_VOID:
            // this meta.type is the unpacking code signal that it took care of the field
            break;

        case STORE_META_URL:
            CheckSwapMetaUrl(meta, entry);
            break;

        case STORE_META_VARY_HEADERS:
            varyHeaders = UnpackNewSwapMetaVaryHeaders(meta, entry);
            break;

        case STORE_META_OBJSIZE:
            // XXX: We swap out but never use this field; set emem.object_sz?
            break;

        case STORE_META_KEY_MD5:
            // already handled by UnpackIndexSwapMeta()
            CheckSwapMetaKey(meta, entry); // paranoid
            break;

        case STORE_META_STD:
        case STORE_META_STD_LFS:
            // already handled by UnpackIndexSwapMeta()
            break;
        }
    }

    auto &emem = entry.mem();

    emem.swap_hdr_sz = swap_hdr_sz;
    if (entry.swap_file_sz > 0) { // collapsed hits may not know swap_file_sz
        Assure(entry.swap_file_sz >= swap_hdr_sz);
        emem.object_sz = entry.swap_file_sz - swap_hdr_sz;
    }
    debugs(90, 5, "swap_file_sz=" << entry.swap_file_sz <<
           " (" << swap_hdr_sz << " + " << emem.object_sz << ")");

    if (!varyHeaders.isEmpty())
        emem.vary_headers = varyHeaders;
}

