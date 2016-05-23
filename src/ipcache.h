/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_IPCACHE_H
#define _SQUID_IPCACHE_H

#include "dns/forward.h"
#include "ip/forward.h"

class ipcache_addrs
{
public:
    ipcache_addrs() : in_addrs(nullptr), bad_mask(nullptr), count(0), cur(0), badcount(0) {}

    Ip::Address *in_addrs;
    unsigned char *bad_mask;
    unsigned char count;
    unsigned char cur;
    unsigned char badcount;
};

typedef void IPH(const ipcache_addrs *, const Dns::LookupDetails &details, void *);

void ipcache_purgelru(void *);
void ipcache_nbgethostbyname(const char *name, IPH * handler, void *handlerData);
const ipcache_addrs *ipcache_gethostbyname(const char *, int flags);
void ipcacheInvalidate(const char *);
void ipcacheInvalidateNegative(const char *);
void ipcache_init(void);
void ipcacheCycleAddr(const char *name, ipcache_addrs *);
void ipcacheMarkBadAddr(const char *name, const Ip::Address &);
void ipcacheMarkGoodAddr(const char *name, const Ip::Address &);
void ipcacheMarkAllGood(const char *name);
void ipcacheFreeMemory(void);
ipcache_addrs *ipcacheCheckNumeric(const char *name);
void ipcache_restart(void);
int ipcacheAddEntryFromHosts(const char *name, const char *ipaddr);

#endif /* _SQUID_IPCACHE_H */

