/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CACHEPEERS_H_
#define SQUID_CACHEPEERS_H_

#include "CachePeer.h"
#include "mem/PoolingAllocator.h"

#include <memory>
#include <vector>

/// cache_peer configuration storage
class CachePeers
{
public:
    using Storage = std::vector< std::unique_ptr<CachePeer>, PoolingAllocator< std::unique_ptr<CachePeer> > >;
    using const_iterator = Storage::const_iterator;

    /// appends a CachePeer object to the storage
    void add(CachePeer *p) { storage.emplace_back(p); }
    /// deletes a CachePeer object
    void remove(CachePeer *);

    const_iterator begin() const { return storage.cbegin(); }
    const_iterator end() const { return storage.cend(); }

    /// the current number of CachePeer objects
    size_t size() const { return storage.size(); }

    /// a CachePeer used next in neighborsUdpPing() peer ping
    CachePeer *nextPeerToPing();

private:
    Storage storage; ///< cache_peers in configuration/parsing order
    uint64_t peersPinged_ = 0; ///< total ping attempts made in neighborsUdpPing()
};

const CachePeers &CurrentCachePeers();

/// destroys the given peer after removing it from the set of configured peers
void DeleteConfigured(CachePeer *);

#endif /* SQUID_CACHEPEERS_H_ */

