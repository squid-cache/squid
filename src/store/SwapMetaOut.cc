/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "md5.h"
#include "MemObject.h"
#include "sbuf/Stream.h"
#include "SquidMath.h"
#include "Store.h"
#include "store/SwapMeta.h"
#include "store/SwapMetaOut.h"

namespace Store {

/// writes a single swap meta field to the given stream
static void
PackField(std::ostream &os, const SwapMetaType type, const size_t length, const void *value)
{
    // Outside of packing/unpacking code, we correctly use SwapMetaType for
    // valid swap meta types now, but we store these values as RawSwapMetaType.
    // These paranoid assertions confirm static_cast preserves the type value.
    // TODO: Do not duplicate this assertion code.
    assert(type >= std::numeric_limits<RawSwapMetaType>::min());
    assert(type <= std::numeric_limits<RawSwapMetaType>::max());
    const auto rawType = static_cast<RawSwapMetaType>(type);

    if (length > SwapMetaFieldValueLengthMax)
        throw TextException("swap meta field value too big to store", Here());

    // Outside of packing/unpacking code, we correctly use size_t for value
    // sizes now, but old code stored these values as RawSwapMetaLength (of an
    // unknown size), so we continue to do so to be able to load meta fields
    // from (some) old caches.
    // These paranoid assertions confirm static_cast preserves the length value.
    assert(length >= std::numeric_limits<RawSwapMetaLength>::min());
    assert(length <= std::numeric_limits<RawSwapMetaLength>::max());
    const auto rawLength = static_cast<RawSwapMetaLength>(length);

    CheckSwapMetaSerialization(rawType, rawLength, value);

    if (!os.write(&rawType, sizeof(rawType)) ||
        !os.write(reinterpret_cast<const char*>(&rawLength), sizeof(rawLength)) ||
        (length && !os.write(static_cast<const char*>(value), length)))
        throw TextException("cannot store swap meta field type", Here());
}

/// writes swap meta fields of the given Store entry to the given stream
static void
PackFields(const StoreEntry &entry, std::ostream &os)
{
    // TODO: Refactor this code instead of reducing the change diff.
    const auto e = &entry;

    assert(e->mem_obj != NULL);
    const int64_t objsize = e->mem_obj->expectedReplySize();

    // e->mem_obj->request may be nil in this context
    SBuf url;
    if (e->mem_obj->request)
        url = e->mem_obj->request->storeId();
    else
        url = e->url();

    debugs(20, 3, entry << " URL: " << url);

    PackField(os, STORE_META_KEY_MD5, SQUID_MD5_DIGEST_LENGTH, e->key);

    PackField(os, STORE_META_STD_LFS, STORE_HDR_METASIZE, &e->timestamp);

    // XXX: do TLV without the c_str() termination. check readers first though
    PackField(os, STORE_META_URL, url.length() + 1U, url.c_str());

    if (objsize >= 0) {
        PackField(os, STORE_META_OBJSIZE, sizeof(objsize), &objsize);
    }

    const auto &vary = e->mem_obj->vary_headers;
    if (!vary.isEmpty()) {
        PackField(os, STORE_META_VARY_HEADERS, vary.length(), vary.rawContent());
    }
}

} // namespace Store

char const *
Store::PackSwapMeta(const StoreEntry &entry, size_t &totalLength)
{
    SBufStream os;
    PackFields(entry, os);
    const auto metas = os.buf();

    // TODO: Optimize this allocation away by returning (and swapping out) SBuf.
    const auto bufSize = NaturalSum<size_t>(sizeof(SwapMetaMagic), sizeof(RawSwapMetaPrefixLength), metas.length()).value();
    const auto buf = static_cast<char*>(xmalloc(bufSize));

    auto pos = buf; // buf writing position

    *pos = SwapMetaMagic;
    pos += sizeof(SwapMetaMagic);

    // for historical reasons, the meta size field has RawSwapMetaLength type
    const auto metaSize = NaturalSum<RawSwapMetaLength>(bufSize).value();
    memcpy(pos, &metaSize, sizeof(metaSize));
    pos += sizeof(metaSize);

    Assure(pos + metas.length() == buf + bufSize); // paranoid
    memcpy(pos, metas.rawContent(), metas.length());
    pos += metas.length();

    totalLength = bufSize;
    return buf;
}

