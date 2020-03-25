/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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

ResolvedPeers::ResolvedPeers()
{
    if (Config.forward_max_tries > 0)
        paths_.reserve(Config.forward_max_tries);
}

void
ResolvedPeers::retryPath(const Comm::ConnectionPointer &conn)
{
    debugs(17, 4, conn);
    assert(conn);
    auto found = std::find_if(paths_.begin(), paths_.end(),
    [conn](const ResolvedPeerPath &path) {
        return path.connection == conn;
    });
    assert(found != paths_.end());
    assert(found->available == false);
    found->available = true;
}

bool
ResolvedPeers::empty() const
{
    const auto anyPath = std::find_if(paths_.begin(), paths_.end(),
    [](const ResolvedPeerPath &path) {
        return path.available;
    });
    return anyPath == paths_.end();
}

ConnectionList::size_type
ResolvedPeers::size() const
{
    return std::count_if(paths_.begin(), paths_.end(),
    [](const ResolvedPeerPath &path) {
        return path.available;
    });
}

void
ResolvedPeers::addPath(const Comm::ConnectionPointer &path)
{
    paths_.emplace_back(path);
}

Comm::ConnectionPointer
ResolvedPeers::extractFront()
{
    Must(!empty());
    return extractFound("first: ", paths_.begin());
}

/// returns the first available same-peer different-family address iterator or end()
ConnectionList::iterator
ResolvedPeers::findSpare(const Comm::Connection &currentPeer)
{
    const auto peerToMatch = currentPeer.getPeer();
    const auto familyToAvoid = ConnectionFamily(currentPeer);
    return std::find_if(paths_.begin(), paths_.end(),
    [peerToMatch, familyToAvoid](const ResolvedPeerPath &path) {
        if (!path.available)
            return false;
        return peerToMatch == path.connection->getPeer() && familyToAvoid != ConnectionFamily(*path.connection);
    });
}

/// returns the first available same-peer same-family address iterator or end()
ConnectionList::iterator
ResolvedPeers::findPrime(const Comm::Connection &currentPeer)
{
    const auto peerToMatch = currentPeer.getPeer();
    const auto familyToMatch = ConnectionFamily(currentPeer);
    return std::find_if(paths_.begin(), paths_.end(),
    [peerToMatch, familyToMatch](const ResolvedPeerPath &path) {
        if (!path.available)
            return false;
        return peerToMatch == path.connection->getPeer() && familyToMatch == ConnectionFamily(*path.connection);
    });
}

/// returns the first available same-peer address iterator or end()
ConnectionList::iterator
ResolvedPeers::findPeer(const Comm::Connection &currentPeer)
{
    const auto peerToMatch = currentPeer.getPeer();
    return std::find_if(paths_.begin(), paths_.end(),
    [peerToMatch](const ResolvedPeerPath &path) {
        if (!path.available)
            return false;
        return peerToMatch == path.connection->getPeer();
    });
}

Comm::ConnectionPointer
ResolvedPeers::extractPrime(const Comm::Connection &currentPeer)
{
    auto found = findPrime(currentPeer);
    if (found != paths_.end())
        return extractFound("same-peer same-family match: ", found);

    debugs(17, 7, "no same-peer same-family paths");
    return nullptr;
}

Comm::ConnectionPointer
ResolvedPeers::extractSpare(const Comm::Connection &currentPeer)
{
    auto found = findSpare(currentPeer);
    if (found != paths_.end())
        return extractFound("same-peer different-family match: ", found);

    debugs(17, 7, "no same-peer different-family paths");
    return nullptr;
}

/// convenience method to finish a successful extract*() call
Comm::ConnectionPointer
ResolvedPeers::extractFound(const char *description, const ConnectionList::iterator &found)
{
    found->available = false;
    debugs(17, 7, description << found->connection);
    return found->connection;
}

bool
ResolvedPeers::haveSpare(const Comm::Connection &currentPeer)
{
    return findSpare(currentPeer) != paths_.end();
}

bool
ResolvedPeers::doneWithSpares(const Comm::Connection &currentPeer)
{
    return (findSpare(currentPeer) == paths_.end()) ? destinationsFinalized : false;
}

bool
ResolvedPeers::doneWithPrimes(const Comm::Connection &currentPeer)
{
    return (findPrime(currentPeer) == paths_.end()) ? destinationsFinalized : false;
}

bool
ResolvedPeers::doneWithPeer(const Comm::Connection &currentPeer)
{
    return (findPeer(currentPeer) == paths_.end()) ? destinationsFinalized : false;
}

int
ResolvedPeers::ConnectionFamily(const Comm::Connection &conn)
{
    return conn.remote.isIPv4() ? AF_INET : AF_INET6;
}

std::ostream &
operator <<(std::ostream &os, const ResolvedPeers &peers)
{
    const auto size = peers.size();
    if (!size)
        return os << "[no paths]";
    return os << size << (peers.destinationsFinalized ? "" : "+") << " paths";
}

