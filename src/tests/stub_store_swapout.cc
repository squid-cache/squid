/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "StoreMeta.h"

#define STUB_API "store_swapout.cc"
#include "tests/STUB.h"

char const *Store::PackSwapHeader(const StoreEntry &, size_t &) STUB_RETVAL(nullptr)

