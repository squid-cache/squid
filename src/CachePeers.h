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

    static peer_t parseNeighborType(const char *);

    /// parses a cache_peer line and stores the parsed CachePeer object
    void parse(ConfigParser &parser);
    /// dumps the cache peer list into the StoreEntry object
    void dump(StoreEntry *, const char *name) const;
    /// cleans the cache peer list
    void clear() { storage.clear(); }

    const_iterator begin() const { return storage.cbegin(); }
    const_iterator end() const { return storage.cend(); }

    /// the current number of CachePeer objects
    size_t size() const { return storage.size(); }

    /// deletes a CachePeer object
    void remove(CachePeer *);

    /// a CachePeer used next in neighborsUdpPing() peer poll
    const_iterator nextPeerToPoll();

private:
    Storage storage; ///< cache_peers in configuration/parsing order
    uint64_t peersPinged_ = 0; ///< total poll attempts by neighborsUdpPing() calls
};

const CachePeers &CurrentCachePeers();

void NeighborRemove(CachePeer *);

#endif /* SQUID_CACHEPEERS_H_ */

