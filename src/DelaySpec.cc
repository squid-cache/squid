/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
    // get the token.
    char *token = ConfigParser::NextToken();
    if (!token) {
        self_destruct();
        return;
    }

    // no-limit value
    if (strcmp(token, "none") == 0 || token[0] == '-') {
        restore_bps = -1;
        max_bytes = -1;
        return;
    }

    // parse the first digits into restore_bps
    const char *p = NULL;
    if (!StringToInt(token, restore_bps, &p, 10) && *p != '/') {
        debugs(77, DBG_CRITICAL, "ERROR: invalid delay rate '" << token << "'. Expecting restore/max or 'none'.");
        self_destruct();
    }
    p++; // increment past the '/'

    // parse the rest into max_bytes
    if (!StringToInt64(p, max_bytes, NULL, 10)) {
        debugs(77, DBG_CRITICAL, "ERROR: restore rate in '" << token << "' is not a number.");
        self_destruct();
    }
}

#endif

