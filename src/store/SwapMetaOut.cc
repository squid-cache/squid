/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
    // valid swap meta types, but we store these values as RawSwapMetaType.
    const auto rawType = NaturalCast<RawSwapMetaType>(type);

    if (length > SwapMetaFieldValueLengthMax)
        throw TextException("swap meta field value too big to store", Here());

    // Outside of packing/unpacking code, we correctly use size_t for value
    // sizes, we still store these values using RawSwapMetaLength.
    const auto rawLength = NaturalCast<RawSwapMetaLength>(length);

    CheckSwapMetaSerialization(rawType, rawLength, value);

    if (!os.write(&rawType, sizeof(rawType)) ||
            !os.write(reinterpret_cast<const char*>(&rawLength), sizeof(rawLength)) ||
            (length && !os.write(static_cast<const char*>(value), length)))
        throw TextException("cannot pack a swap meta field", Here());
}

/// writes all swap meta fields of the given Store entry to the given stream
static void
PackFields(const StoreEntry &entry, std::ostream &os)
{
    const auto &emem = entry.mem();
    const auto objsize = emem.expectedReplySize();

    SBuf url;
    if (emem.request)
        url = emem.request->storeId();
    else
        url = entry.url();

    debugs(20, 3, entry << " URL: " << url);

    PackField(os, STORE_META_KEY_MD5, SQUID_MD5_DIGEST_LENGTH, entry.key);

    PackField(os, STORE_META_STD_LFS, STORE_HDR_METASIZE, &entry.timestamp);

    // XXX: Performance regression, c_str() may reallocate.
    // XXX: do TLV without the c_str() termination. check readers first though
    PackField(os, STORE_META_URL, url.length() + 1U, url.c_str());

    if (objsize >= 0)
        PackField(os, STORE_META_OBJSIZE, sizeof(objsize), &objsize);

    const auto &vary = emem.vary_headers;
    if (!vary.isEmpty())
        PackField(os, STORE_META_VARY_HEADERS, vary.length(), vary.rawContent());
}

} // namespace Store

AllocedBuf
Store::PackSwapMeta(const StoreEntry &entry, size_t &totalLength)
{
    SBufStream os;
    PackFields(entry, os);
    const auto metas = os.buf();

    // TODO: Optimize this allocation away by returning (and swapping out) SBuf.
    const auto bufSize = NaturalSum<size_t>(sizeof(SwapMetaMagic), sizeof(RawSwapMetaPrefixLength), metas.length()).value();
    AllocedBuf buf(xmalloc(bufSize));
    const auto bufStart = static_cast<char*>(buf.get());

    auto pos = bufStart; // buf writing position

    *pos = SwapMetaMagic;
    pos += sizeof(SwapMetaMagic);

    const auto metaSize = NaturalCast<RawSwapMetaLength>(bufSize);
    memcpy(pos, &metaSize, sizeof(metaSize));
    pos += sizeof(metaSize);

    Assure(pos + metas.length() == bufStart + bufSize); // paranoid
    memcpy(pos, metas.rawContent(), metas.length());
    pos += metas.length();

    totalLength = bufSize;
    return buf;
}

