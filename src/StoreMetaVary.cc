/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Swapfile Metadata */

#include "squid.h"
#include "sbuf/SBuf.h"
#include "Store.h"
#include "StoreMeta.h"
#include "StoreMetaVary.h"

SBuf
Store::GetNewSwapMetaVaryHeaders(const SwapMetaView &meta, const StoreEntry &entry)
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

