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
ResolvedPeers::retryPath(const Comm::ConnectionPointer &path)
{
    debugs(17, 4, path);
    assert(path);
    const auto found = std::find_if(paths_.begin(), paths_.end(),
    [path](const ResolvedPeerPath &candidate) {
        return candidate.connection == path; // (refcounted) pointer comparison
    });
    assert(found != paths_.end());
    assert(found->available == false);
    found->available = true;

    // if we restored availability of a candidate that we used to skip, update
    const auto candidatesToTheLeft = static_cast<size_type>(found - paths_.begin());
    if (candidatesToTheLeft < candidatesToSkip) {
        candidatesToSkip = candidatesToTheLeft;
    } else {
        // *found was unavailable so candidatesToSkip could not end at it
        Must(candidatesToTheLeft != candidatesToSkip);
    }
}

bool
ResolvedPeers::empty() const
{
    return !std::any_of(paths_.begin(), paths_.end(),
    [](const ResolvedPeerPath &path) {
        return path.available;
    });
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
    Must(paths_.back().available); // no candidatesToSkip updates are needed
}

Comm::ConnectionPointer
ResolvedPeers::extractFront()
{
    return extractFound("first: ", start());
}

/// \returns the beginning iterator for any available-path search
ConnectionList::iterator
ResolvedPeers::start()
{
    Must(candidatesToSkip <= paths_.size());
    return paths_.begin() + candidatesToSkip; // may return end()
}

/// \returns the first available same-peer same-family address iterator or end()
/// If not found and there is an other-family or other-peer address, the optional *hasNext
/// becomes true
ConnectionList::iterator
ResolvedPeers::findPrime(const Comm::Connection &currentPeer, bool *hasNext)
{
    const auto peerToMatch = currentPeer.getPeer();
    const auto familyToMatch = ConnectionFamily(currentPeer);
    bool foundSpareOrNext = false;
    const auto found = std::find_if(start(), paths_.end(),
    [&](const ResolvedPeerPath &path) {
        if (!path.available) // skip unavailable
            return false;
        // a spare or an other-peer address means that there are no primes left
        if (familyToMatch != ConnectionFamily(*path.connection) || peerToMatch != path.connection->getPeer())
            foundSpareOrNext = true;
        return true;
    });
    if (hasNext)
        *hasNext = foundSpareOrNext;
    return foundSpareOrNext ? paths_.end() : found;
}

/// \returns the first available same-peer different-family address iterator or end()
/// If not found and there is an other-peer address, the optional *hasNext becomes true
ConnectionList::iterator
ResolvedPeers::findSpare(const Comm::Connection &currentPeer, bool *hasNext)
{
    const auto peerToMatch = currentPeer.getPeer();
    const auto familyToAvoid = ConnectionFamily(currentPeer);
    bool foundNext = false;
    const auto found = std::find_if(start(), paths_.end(),
    [&](const ResolvedPeerPath &path) {
        if (!path.available || familyToAvoid == ConnectionFamily(*path.connection)) // skip unavailable and prime
            return false;
        // an other-peer address means that there are no spares left
        if (peerToMatch != path.connection->getPeer())
            foundNext = true;
        return true;
    });
    if (hasNext)
        *hasNext = foundNext;
    return foundNext ? paths_.end() : found;
}

/// \returns the first available same-peer address iterator or end()
/// If not found and there is an other-peer address, the optional *hasNext becomes true
ConnectionList::iterator
ResolvedPeers::findPeer(const Comm::Connection &currentPeer, bool *hasNext)
{
    const auto peerToMatch = currentPeer.getPeer();
    bool foundNext = false;
    const auto found = std::find_if(start(), paths_.end(),
    [&](const ResolvedPeerPath &path) {
        if (!path.available) // skip unavailable
            return false;
        // an other-peer address means that there are no current peer addresses left
        if (peerToMatch != path.connection->getPeer())
            foundNext = true;
        return true;
    });
    if (hasNext)
        *hasNext = foundNext;
    return foundNext ? paths_.end() : found;
}

Comm::ConnectionPointer
ResolvedPeers::extractPrime(const Comm::Connection &currentPeer)
{
    const auto found = findPrime(currentPeer);
    if (found != paths_.end())
        return extractFound("same-peer same-family match: ", found);

    debugs(17, 7, "no same-peer same-family paths");
    return nullptr;
}

Comm::ConnectionPointer
ResolvedPeers::extractSpare(const Comm::Connection &currentPeer)
{
    const auto found = findSpare(currentPeer);
    if (found != paths_.end())
        return extractFound("same-peer different-family match: ", found);

    debugs(17, 7, "no same-peer different-family paths");
    return nullptr;
}

/// convenience method to finish a successful extract*() call
Comm::ConnectionPointer
ResolvedPeers::extractFound(const char *description, const ConnectionList::iterator &found)
{
    assert(found->available);
    found->available = false;
    debugs(17, 7, description << found->connection);

    // if we extracted the left-most available candidate, find the next one
    if (static_cast<size_type>(found - paths_.begin()) == candidatesToSkip) {
        while (++candidatesToSkip < paths_.size() && !paths_[candidatesToSkip].available) {}
    }

    return found->connection;
}

bool
ResolvedPeers::haveSpare(const Comm::Connection &currentPeer)
{
    return findSpare(currentPeer) != paths_.end();
}

/// a common code for all ResolvedPeers::doneWith*()
bool
ResolvedPeers::doneWith(const Comm::Connection &currentPeer, findSmthFun findSmth)
{
    bool hasNext = false;
    if ((*this.*findSmth)(currentPeer, &hasNext) != paths_.end())
        return false;
    return hasNext ? true : destinationsFinalized;
}

bool
ResolvedPeers::doneWithSpares(const Comm::Connection &currentPeer)
{
    return doneWith(currentPeer, &ResolvedPeers::findSpare);
}

bool
ResolvedPeers::doneWithPrimes(const Comm::Connection &currentPeer)
{
    return doneWith(currentPeer, &ResolvedPeers::findPrime);
}

bool
ResolvedPeers::doneWithPeer(const Comm::Connection &currentPeer)
{
    return doneWith(currentPeer, &ResolvedPeers::findPeer);
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

