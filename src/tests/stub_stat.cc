/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 18    Cache Manager Statistics */

#include "squid.h"
#include "stat.h"

#define STUB_API "stat.cc"
#include "tests/STUB.h"

class StoreEntry;
const char *storeEntryFlags(const StoreEntry *) STUB_RETVAL(NULL)
int stat5minClientRequests(void) STUB_RETVAL(0)
int statMemoryAccounted(void) STUB_RETVAL(0)
StatCounters *snmpStatGet(int) STUB_RETVAL(nullptr)
double statByteHitRatio(int) STUB_RETVAL(0.0)
double statRequestHitRatio(int) STUB_RETVAL(0.0)
void statInit(void) STUB_NOP

