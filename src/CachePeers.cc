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
CachePeers::nextPeerToPing()
{
    Assure(size());
    const auto pos = peersPinged_ % size();
    ++peersPinged_;
    return (storage.begin() + pos)->get();
}

void
CachePeers::remove(const CachePeer *p)
{
    Assure(Config.peers);
    // replace with storage.erase_if() after migrating to C++20
    storage.erase(std::remove_if(storage.begin(), storage.end(), [&](const auto &el) {
                return el.get() == p; }), storage.end());
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
DeleteConfigured(const CachePeer *peer)
{
    Assure(Config.peers);
    Config.peers->remove(peer);
}

