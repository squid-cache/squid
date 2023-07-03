/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "CachePeers.h"
#include "SquidConfig.h"

CachePeer *
CachePeers::nextPeerToPing(const size_t pollIndex)
{
    Assure(size());
    const auto pos = (peerPolls_ + pollIndex) % size();

    // Remember the number of polls to keep shifting each poll starting point,
    // to avoid always polling the same group of peers before other peers and
    // risk overloading that first group with requests.
    if (!pollIndex)
        ++peerPolls_; // increment after computing pos to set the very first pos to zero

    return storage[pos].get();
}

void
CachePeers::remove(CachePeer * const p)
{
    const auto peer = std::find_if(storage.begin(), storage.end(), [&](const auto &el) {
            return el.get() == p; });
    Assure(peer != storage.end());
    storage.erase(peer);
}

const CachePeers &
CurrentCachePeers()
{
    if (!Config.peers) {
        static const CachePeers peers;
        return peers;
    }
    return *Config.peers;
}

void
DeleteConfigured(CachePeer * const peer)
{
    Assure(Config.peers);
    Config.peers->remove(peer);
}

