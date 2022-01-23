/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
void ipcache_nbgethostbyname(const char *name, IPH * handler, void *handlerData) STUB
const ipcache_addrs *ipcache_gethostbyname(const char *, int flags) STUB_RETVAL(NULL)
void ipcacheInvalidate(const char *) STUB
void ipcacheInvalidateNegative(const char *) STUB
void ipcache_init(void) STUB
void ipcacheMarkBadAddr(const char *name, const Ip::Address &) STUB
void ipcacheMarkGoodAddr(const char *name, const Ip::Address &) STUB
void ipcacheFreeMemory(void) STUB
void ipcache_restart(void) STUB
int ipcacheAddEntryFromHosts(const char *name, const char *ipaddr) STUB_RETVAL(-1)

