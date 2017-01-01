/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CACHEPEERDOMAINLIST_H_
#define SQUID_CACHEPEERDOMAINLIST_H_

/// representation of the cache_peer_domain list. POD.
class CachePeerDomainList
{
public:
    char *domain;
    bool do_ping;
    CachePeerDomainList *next;
};

#endif /* SQUID_CACHEPEERDOMAINLIST_H_ */

