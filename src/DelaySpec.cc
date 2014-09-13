/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#include "squid.h"

#if USE_DELAY_POOLS
#include "cache_cf.h"
#include "DelaySpec.h"
#include "Parsing.h"
#include "Store.h"

DelaySpec::DelaySpec() : restore_bps(-1), max_bytes (-1)
{}

void
DelaySpec::stats (StoreEntry * sentry, char const *label) const
{
    if (restore_bps == -1) {
        storeAppendPrintf(sentry, "\t%s:\n\t\tDisabled.\n\n", label);
        return;
    }

    storeAppendPrintf(sentry, "\t%s:\n", label);
    storeAppendPrintf(sentry, "\t\tMax: %" PRId64 "\n", max_bytes);
    storeAppendPrintf(sentry, "\t\tRestore: %d\n", restore_bps);
}

void
DelaySpec::dump (StoreEntry *entry) const
{
    storeAppendPrintf(entry, " %d/%" PRId64 "", restore_bps, max_bytes);
}

void
DelaySpec::parse()
{
    int r;
    char *token;
    token = strtok(NULL, "/");

    if (token == NULL)
        self_destruct();

    if (sscanf(token, "%d", &r) != 1)
        self_destruct();

    restore_bps = r;

    max_bytes = GetInteger64();
}

#endif
