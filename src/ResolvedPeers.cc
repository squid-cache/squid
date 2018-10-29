/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "CachePeer.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "ResolvedPeers.h"
#include "SquidConfig.h"

ResolvedPeers::ResolvedPeers(): destinationsFinalized(false)
{
    paths_.reserve(Config.forward_max_tries);
}

void
ResolvedPeers::retryPath(const Comm::ConnectionPointer &path)
{
    paths_.insert(paths_.begin(), path);
}

void
ResolvedPeers::newPath(const Comm::ConnectionPointer &path)
{
    paths_.push_back(path);
}

Comm::ConnectionPointer
ResolvedPeers::extractFront()
{
    Must(!empty());
    return extractFound("first: ", paths_.begin());
}

Comm::ConnectionPointer
ResolvedPeers::extractPrime(const Comm::Connection &currentPeer)
{
    if (!paths_.empty()) {
        const auto peerToMatch = currentPeer.getPeer();
        const auto familyToMatch = ConnectionFamily(currentPeer);
        const auto &conn = paths_.front();
        if (conn->getPeer() == peerToMatch && familyToMatch == ConnectionFamily(*conn))
            return extractFound("same-peer same-family match: ", paths_.begin());
    }

    debugs(17, 7, "no same-peer same-family paths");
    return nullptr;
}

/// If spare paths exist for currentPeer, returns the first spare path iterator.
/// Otherwise, if there are paths for other peers, returns one of those.
/// Otherwise, returns the end() iterator.
Comm::ConnectionList::const_iterator
ResolvedPeers::findSpareOrNextPeer(const Comm::Connection &currentPeer) const
{
    const auto peerToMatch = currentPeer.getPeer();
    const auto familyToAvoid = ConnectionFamily(currentPeer);
    // Optimization: Also stop at the first mismatching peer because all
    // same-peer paths are grouped together.
    const auto found = std::find_if(paths_.begin(), paths_.end(),
        [peerToMatch, familyToAvoid](const Comm::ConnectionPointer &conn) {
            return peerToMatch != conn->getPeer() ||
                familyToAvoid != ConnectionFamily(*conn);
    });
    if (found != paths_.end() && peerToMatch == (*found)->getPeer())
        return found;
    return paths_.end();
}

Comm::ConnectionPointer
ResolvedPeers::extractSpare(const Comm::Connection &currentPeer)
{
    const auto found = findSpareOrNextPeer(currentPeer);
    if (found != paths_.end() && currentPeer.getPeer() == (*found)->getPeer())
        return extractFound("same-peer different-family match: ", found);

    debugs(17, 7, "no same-peer different-family paths");
    return nullptr;
}

/// convenience method to finish a successful extract*() call
Comm::ConnectionPointer
ResolvedPeers::extractFound(const char *description, const Comm::ConnectionList::const_iterator &found)
{
    const auto path = *found;
    paths_.erase(found);
    debugs(17, 7, description << path);
    return path;
}

bool
ResolvedPeers::haveSpare(const Comm::Connection &currentPeer) const
{
    const auto found = findSpareOrNextPeer(currentPeer);
    return found != paths_.end() &&
        currentPeer.getPeer() == (*found)->getPeer();
}

bool
ResolvedPeers::doneWithSpares(const Comm::Connection &currentPeer) const
{
    const auto found = findSpareOrNextPeer(currentPeer);
    if (found == paths_.end())
        return destinationsFinalized;
    return currentPeer.getPeer() != (*found)->getPeer();
}

bool
ResolvedPeers::doneWithPrimes(const Comm::Connection &currentPeer) const
{
    const auto first = paths_.begin();
    if (first == paths_.end())
        return destinationsFinalized;
    return currentPeer.getPeer() != (*first)->getPeer() ||
        ConnectionFamily(currentPeer) != ConnectionFamily(**first);
}

bool
ResolvedPeers::doneWithPeer(const Comm::Connection &currentPeer) const
{
    const auto first = paths_.begin();
    if (first == paths_.end())
        return destinationsFinalized;
    return currentPeer.getPeer() != (*first)->getPeer();
}

int
ResolvedPeers::ConnectionFamily(const Comm::Connection &conn)
{
    return conn.remote.isIPv4() ? AF_INET : AF_INET6;
}
