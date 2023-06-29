/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ipcache.h"

#define STUB_API "ipcache.cc"
#include "tests/STUB.h"

void ipcache_purgelru(void *) STUB
void ipcache_nbgethostbyname(const char *, IPH *, void *) STUB
const ipcache_addrs *ipcache_gethostbyname(const char *, int) STUB_RETVAL(nullptr)
void ipcacheInvalidate(const char *) STUB
void ipcacheInvalidateNegative(const char *) STUB
void ipcache_init(void) STUB
void ipcacheMarkBadAddr(const char *, const Ip::Address &) STUB
void ipcacheMarkGoodAddr(const char *, const Ip::Address &) STUB
void ipcache_restart(void) STUB
int ipcacheAddEntryFromHosts(const char *, const char *) STUB_RETVAL(-1)

