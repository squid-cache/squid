/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Swapfile Metadata */

#include "squid.h"
#include "int.h"
#include "md5.h"
#include "MemObject.h"
#include "Store.h"
#include "StoreMetaMD5.h"

void
Store::CheckSwapMetaMd5(const SwapMetaView &meta, const StoreEntry &entry)
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

void
Store::GetSwapMetaMd5(const SwapMetaView &meta, cache_key *key)
{
    Assure(meta.type == STORE_META_KEY_MD5);
    meta.checkExpectedLength(SQUID_MD5_DIGEST_LENGTH);
    Assure(key);
    memcpy(key, meta.rawValue, SQUID_MD5_DIGEST_LENGTH);
}

