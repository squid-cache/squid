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

bool
StoreMetaMD5::validLength(int len) const
{
    return len == SQUID_MD5_DIGEST_LENGTH;
}

int StoreMetaMD5::md5_mismatches = 0;

bool
StoreMetaMD5::checkConsistency(StoreEntry *e) const
{
    assert (getType() == STORE_META_KEY_MD5);
    assert(length == SQUID_MD5_DIGEST_LENGTH);

    if (!EBIT_TEST(e->flags, KEY_PRIVATE) &&
            memcmp(value, e->key, SQUID_MD5_DIGEST_LENGTH)) {
        debugs(20, 2, "storeClientReadHeader: swapin MD5 mismatch");
        // debugs(20, 2, "\t" << storeKeyText((const cache_key *)value));
        debugs(20, 2, "\t" << e->getMD5Text());

        if (isPowTen(++md5_mismatches))
            debugs(20, DBG_IMPORTANT, "WARNING: " << md5_mismatches << " swapin MD5 mismatches");

        return false;
    }

    return true;
}

