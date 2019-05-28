/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "StoreStats.cc"
#include "tests/STUB.h"

#include "StoreStats.h"
#include <cstring>

StoreInfoStats &
StoreInfoStats::operator +=(const StoreInfoStats &stats) STUB_RETVAL(*this)

StoreIoStats::StoreIoStats()
{
    // we have to implement this one because tests/stub_store.cc
    // has a StoreIoStats global
    memset(this, 0, sizeof(*this));
}

