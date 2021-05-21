/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "StoreMeta.h"

#define STUB_API "store_swapout.cc"
#include "tests/STUB.h"

#include <iostream>

/* XXX: wrong stub file... */
void storeUnlink(StoreEntry * e) STUB

char *storeSwapMetaPack(tlv * tlv_list, int *length) STUB_RETVAL(NULL)
tlv *storeSwapMetaBuild(const StoreEntry *) STUB_RETVAL(nullptr)
void storeSwapTLVFree(tlv * n) STUB

