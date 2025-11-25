/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 35    FQDN Cache */

#ifndef SQUID_SRC_FQDNCACHE_H
#define SQUID_SRC_FQDNCACHE_H

#include "dns/forward.h"
#include "ip/forward.h"
#include "sbuf/forward.h"
#include "store/forward.h"

namespace Dns
{
/// whether to do reverse DNS lookups for source IPs of accepted connections
extern bool ResolveClientAddressesAsap;
}

using FQDNH = void (const char *, const Dns::LookupDetails &, void *);

void fqdncache_init();
void fqdnStats(StoreEntry *);
void fqdncache_restart();
void fqdncache_purgelru(void *);
void fqdncacheAddEntryFromHosts(char *addr, SBufList &hostnames);

const char *fqdncache_gethostbyaddr(const Ip::Address &, int flags);
void fqdncache_nbgethostbyaddr(const Ip::Address &, FQDNH *, void *);

#endif /* SQUID_SRC_FQDNCACHE_H */

