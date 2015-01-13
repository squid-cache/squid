/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "globals.h"
#include "helper/ChildConfig.h"

#define STUB_API "stub_HelperChildconfig.cc"
#include "tests/STUB.h"

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

void Helper::ChildConfig::parseConfig() STUB

