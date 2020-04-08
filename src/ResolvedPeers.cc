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
    // Cannot use candidatesToSkip for a faster (reverse) search because there
    // may be unavailable candidates past candidatesToSkip. We could remember
    // the last extraction index, but, to completely avoid a linear search,
    // extract*() methods should return the candidate index.
    const auto found = std::find_if(paths_.begin(), paths_.end(),
    [path](const ResolvedPeerPath &candidate) {
        return candidate.connection == path; // (refcounted) pointer comparison
    });
    assert(found != paths_.end());
    assert(!found->available);
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

ConnectionList::size_type
ResolvedPeers::size() const
{
    return std::count_if(start(), paths_.end(),
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

/// \returns the beginning iterator for any available-path search
ConnectionList::iterator
ResolvedPeers::start()
{
    Must(candidatesToSkip <= paths_.size());
    return paths_.begin() + candidatesToSkip; // may return end()
}

/// finalizes the iterator part of the given preliminary find*() result
ResolvedPeers::Finding
ResolvedPeers::makeFinding(const ConnectionList::iterator &candidate, bool foundOther)
{
    return std::make_pair((foundOther ? paths_.end() : candidate), foundOther);
}

/// \returns the first available same-peer same-family address iterator or end()
ResolvedPeers::Finding
ResolvedPeers::findPrime(const Comm::Connection &currentPeer)
{
    const auto candidate = start();
    const auto foundNextOrSpare = candidate != paths_.end() &&
        (currentPeer.getPeer() != candidate->connection->getPeer() || // next peer
            ConnectionFamily(currentPeer) != ConnectionFamily(*candidate->connection));
    return makeFinding(candidate, foundNextOrSpare);
}

/// \returns the first available same-peer different-family address iterator or end()
ResolvedPeers::Finding
ResolvedPeers::findSpare(const Comm::Connection &currentPeer)
{
    const auto primeFamily = ConnectionFamily(currentPeer);
    const auto candidate = std::find_if(start(), paths_.end(),
    [primeFamily](const ResolvedPeerPath &path) {
        if (!path.available)
            return false;
        if (primeFamily == ConnectionFamily(*path.connection))
            return false;
        return true; // found either spare or next peer
    });
    const auto foundNext = candidate != paths_.end() &&
        currentPeer.getPeer() != candidate->connection->getPeer();
    return makeFinding(candidate, foundNext);
}

/// \returns the first available same-peer address iterator or end()
ResolvedPeers::Finding
ResolvedPeers::findPeer(const Comm::Connection &currentPeer)
{
    const auto candidate = start();
    const auto foundNext = candidate != paths_.end() &&
        currentPeer.getPeer() != candidate->connection->getPeer();
    return makeFinding(candidate, foundNext);
}

Comm::ConnectionPointer
ResolvedPeers::extractFront()
{
    Must(!empty());
    return extractFound("first: ", start());
}

Comm::ConnectionPointer
ResolvedPeers::extractPrime(const Comm::Connection &currentPeer)
{
    const auto found = findPrime(currentPeer).first;
    if (found != paths_.end())
        return extractFound("same-peer same-family match: ", found);

    debugs(17, 7, "no same-peer same-family paths");
    return nullptr;
}

Comm::ConnectionPointer
ResolvedPeers::extractSpare(const Comm::Connection &currentPeer)
{
    const auto found = findSpare(currentPeer).first;
    if (found != paths_.end())
        return extractFound("same-peer different-family match: ", found);

    debugs(17, 7, "no same-peer different-family paths");
    return nullptr;
}

/// convenience method to finish a successful extract*() call
Comm::ConnectionPointer
ResolvedPeers::extractFound(const char *description, const ConnectionList::iterator &found)
{
    auto &path = *found;
    debugs(17, 7, description << path.connection);
    assert(path.available);
    path.available = false;

    // if we extracted the left-most available candidate, find the next one
    if (static_cast<size_type>(found - paths_.begin()) == candidatesToSkip) {
        while (++candidatesToSkip < paths_.size() && !paths_[candidatesToSkip].available) {}
    }

    return path.connection;
}

bool
ResolvedPeers::haveSpare(const Comm::Connection &currentPeer)
{
    return findSpare(currentPeer).first != paths_.end();
}

/// whether paths_ have no (and will have no) Xs for the current peer based on
/// the given findX(current peer) result
bool
ResolvedPeers::doneWith(const Finding &findings) const
{
    if (findings.first != paths_.end())
        return false; // not done because the caller found a viable candidate X

    // The caller did not find any candidate X. If the caller found any "other"
    // candidates, then we are doing with candidates X. If there are no
    // candidates in paths_, then destinationsFinalized is the answer.
    return findings.second ? true : destinationsFinalized;
}

bool
ResolvedPeers::doneWithSpares(const Comm::Connection &currentPeer)
{
    return doneWith(findSpare(currentPeer));
}

bool
ResolvedPeers::doneWithPrimes(const Comm::Connection &currentPeer)
{
    return doneWith(findPrime(currentPeer));
}

bool
ResolvedPeers::doneWithPeer(const Comm::Connection &currentPeer)
{
    return doneWith(findPeer(currentPeer));
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

