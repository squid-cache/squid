/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "fqdncache.h"

#define STUB_API "fqdncache.cc"
#include "tests/STUB.h"

bool Dns::ResolveClientAddressesAsap = false;

void fqdncache_init(void) STUB
void fqdnStats(StoreEntry *) STUB
void fqdncache_restart(void) STUB
void fqdncache_purgelru(void *) STUB
void fqdncacheAddEntryFromHosts(char *, SBufList &) STUB
const char *fqdncache_gethostbyaddr(const Ip::Address &, int) STUB_RETVAL(nullptr)
void fqdncache_nbgethostbyaddr(const Ip::Address &, FQDNH *, void *) STUB
