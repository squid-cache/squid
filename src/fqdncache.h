/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 35    FQDN Cache */

#ifndef SQUID_FQDNCACHE_H_
#define SQUID_FQDNCACHE_H_

#include "ip/Address.h"
#include "sbuf/forward.h"

class StoreEntry;
namespace Dns
{
class LookupDetails;

/// whether to do reverse DNS lookups for source IPs of accepted connections
extern bool ResolveClientAddressesAsap;
}

typedef void FQDNH(const char *, const Dns::LookupDetails &details, void *);

void fqdncache_init(void);
void fqdnStats(StoreEntry *);
void fqdncache_restart(void);
void fqdncache_purgelru(void *);
void fqdncacheAddEntryFromHosts(char *addr, SBufList &hostnames);

const char *fqdncache_gethostbyaddr(const Ip::Address &, int flags);
void fqdncache_nbgethostbyaddr(const Ip::Address &, FQDNH *, void *);

#endif /* SQUID_FQDNCACHE_H_ */

