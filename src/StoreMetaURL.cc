/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Swapfile Metadata */

#include "squid.h"
#include "MemObject.h"
#include "Store.h"
#include "StoreMeta.h"
#include "StoreMetaURL.h"

void
Store::CheckSwapMetaUrl(const SwapMetaView &meta, const StoreEntry &entry)
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

    if (strcasecmp(e->mem_obj->urlXXX(), (char *)value)) {
        debugs(20, DBG_IMPORTANT, "storeClientReadHeader: URL mismatch");
        debugs(20, DBG_IMPORTANT, "\t{" << (char *) value << "} != {" << e->mem_obj->urlXXX() << "}");
        throw TextException("URL mismatch", Here());
    }

    // Getting here still does not guarantee of a match: We have not checked
    // whether case-sensitive parts of the URI have fully matched.
}

