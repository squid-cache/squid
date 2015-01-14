/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Swapfile Metadata */

#include "squid.h"
#include "MemObject.h"
#include "Store.h"
#include "StoreMetaURL.h"

bool
StoreMetaURL::checkConsistency(StoreEntry *e) const
{
    assert (getType() == STORE_META_URL);

    if (!e->mem_obj->hasUris())
        return true;

    if (strcasecmp(e->mem_obj->urlXXX(), (char *)value)) {
        debugs(20, DBG_IMPORTANT, "storeClientReadHeader: URL mismatch");
        debugs(20, DBG_IMPORTANT, "\t{" << (char *) value << "} != {" << e->mem_obj->urlXXX() << "}");
        return false;
    }

    return true;
}

