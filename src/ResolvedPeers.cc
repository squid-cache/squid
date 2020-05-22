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
    // Cannot use pathsToSkip for a faster (reverse) search because there
    // may be unavailable paths past pathsToSkip. We could remember
    // the last extraction index, but, to completely avoid a linear search,
    // extract*() methods should return the path index.
    const auto found = std::find_if(paths_.begin(), paths_.end(),
    [path](const ResolvedPeerPath &candidate) {
        return candidate.connection == path; // (refcounted) pointer comparison
    });
    assert(found != paths_.end());
    assert(!found->available);
    found->available = true;
    increaseAvailability();

    // if we restored availability of a path that we used to skip, update
    const auto pathsToTheLeft = static_cast<size_type>(found - paths_.begin());
    if (pathsToTheLeft < pathsToSkip) {
        pathsToSkip = pathsToTheLeft;
    } else {
        // *found was unavailable so pathsToSkip could not end at it
        Must(pathsToTheLeft != pathsToSkip);
    }
}

void
ResolvedPeers::addPath(const Comm::ConnectionPointer &path)
{
    paths_.emplace_back(path);
    Must(paths_.back().available); // no pathsToSkip updates are needed
    increaseAvailability();
}

/// \returns the beginning iterator for any available-path search
ResolvedPeers::Paths::iterator
ResolvedPeers::start()
{
    Must(pathsToSkip <= paths_.size());
    return paths_.begin() + pathsToSkip; // may return end()
}

/// finalizes the iterator part of the given preliminary find*() result
ResolvedPeers::Finding
ResolvedPeers::makeFinding(const Paths::iterator &path, bool foundOther)
{
    return std::make_pair((foundOther ? paths_.end() : path), foundOther);
}

/// \returns the first available same-peer same-family Finding or <end,...>
ResolvedPeers::Finding
ResolvedPeers::findPrime(const Comm::Connection &currentPeer)
{
    const auto path = start();
    const auto foundNextOrSpare = path != paths_.end() &&
        (currentPeer.getPeer() != path->connection->getPeer() || // next peer
            ConnectionFamily(currentPeer) != ConnectionFamily(*path->connection));
    return makeFinding(path, foundNextOrSpare);
}

/// \returns the first available same-peer different-family Finding or <end,...>
ResolvedPeers::Finding
ResolvedPeers::findSpare(const Comm::Connection &currentPeer)
{
    const auto primeFamily = ConnectionFamily(currentPeer);
    const auto primePeer = currentPeer.getPeer();
    const auto path = std::find_if(start(), paths_.end(),
    [primeFamily, primePeer](const ResolvedPeerPath &candidate) {
        if (!candidate.available)
            return false;
        if (primePeer != candidate.connection->getPeer())
            return true; // found next peer
        if (primeFamily != ConnectionFamily(*candidate.connection))
            return true; // found spare
        return false;
    });
    const auto foundNext = path != paths_.end() &&
        primePeer != path->connection->getPeer();
    return makeFinding(path, foundNext);
}

/// \returns the first available same-peer Finding or <end,...>
ResolvedPeers::Finding
ResolvedPeers::findPeer(const Comm::Connection &currentPeer)
{
    const auto path = start();
    const auto foundNext = path != paths_.end() &&
        currentPeer.getPeer() != path->connection->getPeer();
    return makeFinding(path, foundNext);
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
ResolvedPeers::extractFound(const char *description, const Paths::iterator &found)
{
    auto &path = *found;
    debugs(17, 7, description << path.connection);
    assert(path.available);
    path.available = false;
    decreaseAvailability();

    // if we extracted the left-most available path, find the next one
    if (static_cast<size_type>(found - paths_.begin()) == pathsToSkip) {
        while (++pathsToSkip < paths_.size() && !paths_[pathsToSkip].available) {}
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
        return false; // not done because the caller found a viable path X

    // The caller did not find any path X. If the caller found any "other"
    // paths, then we are done with paths X. If there are no "other" paths,
    // then destinationsFinalized is the answer.
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

/// increments the number of available paths
void
ResolvedPeers::increaseAvailability()
{
    ++availablePaths;
    assert(availablePaths <= paths_.size());
}

/// decrements the number of available paths
void
ResolvedPeers::decreaseAvailability()
{
    assert(availablePaths > 0);
    --availablePaths;
}

std::ostream &
operator <<(std::ostream &os, const ResolvedPeers &peers)
{
    if (peers.empty())
        return os << "[no paths]";
    return os << peers.size() << (peers.destinationsFinalized ? "" : "+") << " paths";
}

