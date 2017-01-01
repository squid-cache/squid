/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "globals.h"
#include "helper/ChildConfig.h"
#include "Parsing.h"

#include <cstring>

Helper::ChildConfig::ChildConfig():
    n_max(0),
    n_startup(0),
    n_idle(1),
    concurrency(0),
    n_running(0),
    n_active(0)
{}

Helper::ChildConfig::ChildConfig(const unsigned int m):
    n_max(m),
    n_startup(0),
    n_idle(1),
    concurrency(0),
    n_running(0),
    n_active(0)
{}

Helper::ChildConfig &
Helper::ChildConfig::updateLimits(const Helper::ChildConfig &rhs)
{
    // Copy the limits only.
    // Preserve the local state values (n_running and n_active)
    n_max = rhs.n_max;
    n_startup = rhs.n_startup;
    n_idle = rhs.n_idle;
    concurrency = rhs.concurrency;
    return *this;
}

int
Helper::ChildConfig::needNew() const
{
    /* during the startup and reconfigure use our special amount... */
    if (starting_up || reconfiguring) return n_startup;

    /* keep a minimum of n_idle helpers free... */
    if ( (n_active + n_idle) < n_max) return n_idle;

    /* dont ever start more than n_max processes. */
    return (n_max - n_active);
}

void
Helper::ChildConfig::parseConfig()
{
    char const *token = ConfigParser::NextToken();

    if (!token)
        self_destruct();

    /* starts with a bare number for the max... back-compatible */
    n_max = xatoui(token);

    if (n_max < 1) {
        debugs(0, DBG_CRITICAL, "ERROR: The maximum number of processes cannot be less than 1.");
        self_destruct();
    }

    /* Parse extension options */
    for (; (token = ConfigParser::NextToken()) ;) {
        if (strncmp(token, "startup=", 8) == 0) {
            n_startup = xatoui(token + 8);
        } else if (strncmp(token, "idle=", 5) == 0) {
            n_idle = xatoui(token + 5);
            if (n_idle < 1) {
                debugs(0, DBG_CRITICAL, "WARNING OVERIDE: Using idle=0 for helpers causes request failures. Overiding to use idle=1 instead.");
                n_idle = 1;
            }
        } else if (strncmp(token, "concurrency=", 12) == 0) {
            concurrency = xatoui(token + 12);
        } else {
            debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: Undefined option: " << token << ".");
            self_destruct();
        }
    }

    /* simple sanity. */

    if (n_startup > n_max) {
        debugs(0, DBG_CRITICAL, "WARNING OVERIDE: Capping startup=" << n_startup << " to the defined maximum (" << n_max <<")");
        n_startup = n_max;
    }

    if (n_idle > n_max) {
        debugs(0, DBG_CRITICAL, "WARNING OVERIDE: Capping idle=" << n_idle << " to the defined maximum (" << n_max <<")");
        n_idle = n_max;
    }
}

