/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 35    FQDN Cache */

#ifndef SQUID_FQDNCACHE_H_
#define SQUID_FQDNCACHE_H_

#include "ip/Address.h"
#include "typedefs.h"

class StoreEntry;
class wordlist;

void fqdncache_init(void);
void fqdnStats(StoreEntry *);
void fqdncacheFreeMemory(void);
void fqdncache_restart(void);
void fqdncache_purgelru(void *);
void fqdncacheAddEntryFromHosts(char *addr, wordlist * hostnames);

const char *fqdncache_gethostbyaddr(const Ip::Address &, int flags);
void fqdncache_nbgethostbyaddr(const Ip::Address &, FQDNH *, void *);

#endif /* SQUID_FQDNCACHE_H_ */

