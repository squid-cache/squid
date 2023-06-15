/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CACHEPEERS_H
#define SQUID_CACHEPEERS_H

#include "base/forward.h"
#include "CachePeer.h"
#include "mem/PoolingAllocator.h"

#include <vector>

/// Weak pointers to zero or more Config.peers.
/// Users must specify the selection algorithm and the order of entries.
using SelectedCachePeers = std::vector< CbcPointer<CachePeer>, PoolingAllocator< CbcPointer<CachePeer> > >;

/// Temporary, local storage of raw pointers to zero or more Config.peers.
using RawCachePeers = std::vector<CachePeer *, PoolingAllocator<CachePeer*> >;

#endif /* SQUID_CACHEPEERS_H */

