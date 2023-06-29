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

CachePeers::Storage::const_iterator
CachePeers::nextPeerToPoll()
{
    Assure(size());
    const auto pos = peersPinged_ % size();
    ++peersPinged_;
    return storage.begin() + pos;
}

void
CachePeers::remove(CachePeer *p)
{
    for (auto it = storage.begin(); it != storage.end(); ++it) {
        if (it->get() == p) {
            storage.erase(it);
            break;
        }
    }
}

const CachePeers &
CurrentCachePeers()
{
    if (!Config.cachePeers) {
        static CachePeers peers;
        return peers;
    }
    return *Config.cachePeers;
}

void
NeighborRemove(CachePeer *peer)
{
    Assure(Config.cachePeers);
    Config.cachePeers->remove(peer);
}

