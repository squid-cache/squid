/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "StoreMeta.cc"
#include "tests/STUB.h"

#include "StoreMeta.h"

bool StoreMeta::validType(char) STUB_RETVAL(false)
bool StoreMeta::validLength(int) const STUB_RETVAL(false)
StoreMeta * StoreMeta::Factory (char, size_t, void const *) STUB_RETVAL(NULL)
void StoreMeta::FreeList(StoreMeta **) STUB
StoreMeta ** StoreMeta::Add(StoreMeta **, StoreMeta *) STUB_RETVAL(NULL)
bool StoreMeta::checkConsistency(StoreEntry *) const STUB_RETVAL(false)

