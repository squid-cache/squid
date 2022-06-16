/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
#include "Store.h"
#include "store/SwapMeta.h"
#include "store/SwapMetaIn.h"
#include "store/SwapMetaView.h"

namespace Store {

/// iterates swapped out swap meta fields, loaded into a given buffer
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
    SwapMetaUnpacker(const char *buf, ssize_t bufferLength, int *hdrlen);

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

static void
CheckSwapMetaMd5(const SwapMetaView &meta, const StoreEntry &entry)
{
    Assure(meta.type == STORE_META_KEY_MD5);
    meta.checkExpectedLength(SQUID_MD5_DIGEST_LENGTH);

    // TODO: Refactor this code instead of reducing the change diff.
    static unsigned int md5_mismatches = 0;
    const auto e = &entry;
    const auto &value = meta.rawValue;

    if (!EBIT_TEST(e->flags, KEY_PRIVATE) &&
            memcmp(value, e->key, SQUID_MD5_DIGEST_LENGTH)) {
        debugs(20, 2, "storeClientReadHeader: swapin MD5 mismatch");
        // debugs(20, 2, "\t" << storeKeyText((const cache_key *)value));
        debugs(20, 2, "\t" << e->getMD5Text());

        if (isPowTen(++md5_mismatches))
            debugs(20, DBG_IMPORTANT, "WARNING: " << md5_mismatches << " swapin MD5 mismatches");

        // TODO: Support TextException::frequent = isPowTen(++md5_mismatches)
        // to suppress reporting, achieving the same effect as above
        throw TextException("swap meta MD5 mismatch", Here());
    }
}

static void
GetSwapMetaMd5(const SwapMetaView &meta, cache_key *key)
{
    Assure(meta.type == STORE_META_KEY_MD5);
    meta.checkExpectedLength(SQUID_MD5_DIGEST_LENGTH);
    Assure(key);
    memcpy(key, meta.rawValue, SQUID_MD5_DIGEST_LENGTH);
}

static void
CheckSwapMetaUrl(const SwapMetaView &meta, const StoreEntry &entry)
{
    Assure(meta.type == STORE_META_URL);

    // PackSwapMetas() terminates; strcasecmp() and reporting below rely on that
    if (!memrchr(meta.rawValue, '\0', meta.rawLength))
        throw TextException("unterminated URI or bad URI length", Here());

    // TODO: Refactor this code instead of reducing the change diff.
    const auto e = &entry;
    const auto value = meta.rawValue;

    if (!e->mem_obj->hasUris())
        return; // cannot validate

    // XXX: ensure all Squid URL inputs are properly normalized then use case-sensitive compare here
    if (strcasecmp(e->mem_obj->urlXXX(), (char *)value)) {
        debugs(20, DBG_IMPORTANT, "storeClientReadHeader: URL mismatch");
        debugs(20, DBG_IMPORTANT, "\t{" << (char *) value << "} != {" << e->mem_obj->urlXXX() << "}");
        throw TextException("URL mismatch", Here());
    }
}

static SBuf
GetNewSwapMetaVaryHeaders(const SwapMetaView &meta, const StoreEntry &entry)
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

Store::SwapMetaUnpacker::SwapMetaUnpacker(const char * const buf, const ssize_t size, int * const swap_hdr_len)
{
    Assure(buf);
    Assure(size >= 0);

    // buffer = <metadata> [HTTP response byte]...
    // metadata = <prefix> [metadata field]...
    // prefix = <magic> <metadata size a.k.a. swap_hdr_len>
    // We parse the prefix and then skip it, ready to iterate metadata fields.

    const auto requiredPrefixSize = sizeof(Store::SwapMetaMagic) + sizeof(Store::RawSwapMetaPrefixLength);
    Assure2(uint64_t(size) >= requiredPrefixSize, "parsing buffer accommodates metadata prefix");

    if (buf[0] != Store::SwapMetaMagic)
        throw TextException("store entry metadata prefix is corrupted", Here());

    Store::RawSwapMetaPrefixLength rawMetaSize = 0; // metadata size, including the required prefix
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

uint64_t
Store::UnpackSwapMetaSize(const SBuf &buf)
{
    // TODO: Move this logic from SwapMetaUnpacker into here?
    int swap_hdr_len = 0;
    const SwapMetaUnpacker aBuilder(buf.rawContent(), buf.length(), &swap_hdr_len);
    Assure(swap_hdr_len >= 0); // TODO: Switch SwapMetaUnpacker to uint64_t?
    return uint64_t(swap_hdr_len);
}

uint64_t
Store::UnpackIndexSwapMeta(const MemBuf &buf, StoreEntry &tmpe, cache_key * const key)
{
    int swap_hdr_len = 0;

    SwapMetaUnpacker aBuilder(buf.content(), buf.contentSize(), &swap_hdr_len);
    for (const auto &meta: aBuilder) {
        switch (meta.type) {
        case STORE_META_VOID:
            // TODO: Skip this StoreEntry instead of ignoring its field?
            // this type is aBuilder's signal that it took care of the field
            break;

        case STORE_META_KEY_MD5:
            // Optimization: We could postpone setting the caller's key
            // until all fields are parsed, but that would require copying
            // it. Instead, we treat key and tmpe.key as storage that can be
            // safely altered even on parsing failures. This function
            // description tells the callers that we may do that.
            GetSwapMetaMd5(meta, key);
            Assure(key);
            tmpe.key = key;
            break;
        // TODO: remove. Since old_metahdr's members may have different sizes on different
        // platforms, we cannot guarantee that serialized types in an old cache
        // are the same as run-time types.
        case STORE_META_STD: {
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
            // store_client::unpackHeader() handles these MemObject fields.
            break;
        }
    }

    Assure(swap_hdr_len >= 0);
    return uint64_t(swap_hdr_len);
}

void
Store::UnpackHitSwapMeta(char const * const buf, const ssize_t len, StoreEntry &entry)
{
    debugs(90, 3, "store_client::unpackHeader: len " << len << "");
    assert(len >= 0); // XXX: fix the type

    int swap_hdr_sz = 0;
    SBuf varyHeaders;

    Store::SwapMetaUnpacker aBuilder(buf, len, &swap_hdr_sz);
    for (const auto &meta: aBuilder) {
        switch (meta.type) {
        case STORE_META_VOID:
            // this type is aBuilder's signal that it took care of the field
            break;

        case STORE_META_KEY_MD5:
            // paranoid -- storeRebuildParseEntry() loads the key
            CheckSwapMetaMd5(meta, entry); // paranoid
            break;

        case STORE_META_URL:
            CheckSwapMetaUrl(meta, entry);
            break;

        case STORE_META_STD:
            // Handled by storeRebuildParseEntry()
            break;

        case STORE_META_VARY_HEADERS:
            varyHeaders = GetNewSwapMetaVaryHeaders(meta, entry);
            break;

        case STORE_META_STD_LFS:
            // Handled by storeRebuildParseEntry()
            break;

        case STORE_META_OBJSIZE:
            // TODO: Should not we set mem_obj.object_sz?
            break;
        }
    }

    auto &mem_obj = entry.mem();

    assert(swap_hdr_sz >= 0);
    mem_obj.swap_hdr_sz = swap_hdr_sz;
    if (entry.swap_file_sz > 0) { // collapsed hits may not know swap_file_sz
        assert(entry.swap_file_sz >= static_cast<uint64_t>(swap_hdr_sz));
        mem_obj.object_sz = entry.swap_file_sz - swap_hdr_sz;
    }
    debugs(90, 5, "store_client::unpackHeader: swap_file_sz=" <<
           entry.swap_file_sz << "( " << swap_hdr_sz << " + " <<
           mem_obj.object_sz << ")");

    if (!varyHeaders.isEmpty())
        mem_obj.vary_headers = varyHeaders;
}

