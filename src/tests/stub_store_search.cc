/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "StoreSearch.cc"
#include "tests/STUB.h"

#include "store/LocalSearch.h"
#include "StoreSearch.h"

StoreSearch *Store::NewLocalSearch() STUB_RETVAL(NULL)
