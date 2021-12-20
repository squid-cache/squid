/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Client Database */

#ifndef _SQUID__SRC_CLIENTDB_CACHE_H
#define _SQUID__SRC_CLIENTDB_CACHE_H

#include "clientdb/ClientInfo.h"
#include "clientdb/forward.h"
#include "ip/Address.h"

#include <map>

namespace ClientDb
{

/// Create a new record for the given client IP.
/// Replaces any existing record
/// \returns a clean ClientInfo
ClientInfo *Add(const Ip::Address &);

/// Find and Update the record for the given client IP.
/// Replaces any existing entry
/// \returns a new ClientInfo
void Update(const Ip::Address &, const LogTags &, AnyP::ProtocolType, size_t size);

/// \returns ClientInfo for given IP addr, or nullptr
ClientInfo *Get(const Ip::Address &);

/// garbage collection event handler
void Prune(void *);

/// produce the CacheManager 'client_list' report
void Report(StoreEntry *);

/**
 * This function tracks the number of currently established connections
 * for a client IP address.  When a connection is accepted, call this
 * with delta = 1.  When the connection is closed, call with delta =
 * -1.  To get the current value, simply call with delta = 0.
 */
int Established(const Ip::Address &, int delta);

/// whether ICP is to be DENIED due to a cutoff window
bool IcpCutoffDenied(const Ip::Address &);

/// storage for client records, indexed by IP address
extern std::map<Ip::Address, ClientInfo::Pointer> Cache;

} // namespace ClientDb

#endif /* _SQUID__SRC_CLIENTDB_CACHE_H */
