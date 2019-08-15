/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_RESOLVEDPEERS_H
#define SQUID_RESOLVEDPEERS_H

#include "base/RefCount.h"
#include "comm/forward.h"

#include <iosfwd>

/// cache_peer and origin server addresses (a.k.a. paths)
/// selected and resolved by the peering code
class ResolvedPeers: public RefCountable
{
    MEMPROXY_CLASS(ResolvedPeers);

public:
    typedef RefCount<ResolvedPeers> Pointer;

    ResolvedPeers();

    /// whether we lack any known candidate paths
    bool empty() const { return paths_.empty(); }

    /// add a candidate path to try after all the existing paths
    void addPath(const Comm::ConnectionPointer &);

    /// add a candidate path to try before all the existing paths
    void retryPath(const Comm::ConnectionPointer &);

    /// extracts and returns the first queued address
    Comm::ConnectionPointer extractFront();

    /// extracts and returns the first same-peer same-family address
    /// \returns nil if it cannot find the requested address
    Comm::ConnectionPointer extractPrime(const Comm::Connection &currentPeer);

    /// extracts and returns the first same-peer different-family address
    /// \returns nil if it cannot find the requested address
    Comm::ConnectionPointer extractSpare(const Comm::Connection &currentPeer);

    /// whether extractSpare() would return a non-nil path right now
    bool haveSpare(const Comm::Connection &currentPeer);

    /// whether extractPrime() returns and will continue to return nil
    bool doneWithPrimes(const Comm::Connection &currentPeer) const;

    /// whether extractSpare() returns and will continue to return nil
    bool doneWithSpares(const Comm::Connection &currentPeer);

    /// whether doneWithPrimes() and doneWithSpares() are true for currentPeer
    bool doneWithPeer(const Comm::Connection &currentPeer) const;

    /// the current number of candidate paths
    Comm::ConnectionList::size_type size() const { return paths_.size(); }

    /// whether all of the available candidate paths received from DNS
    bool destinationsFinalized = false;

    /// whether HappyConnOpener::noteCandidatesChange() is scheduled to fire
    bool notificationPending = false;

private:
    /// The protocol family of the given path, AF_INET or AF_INET6
    static int ConnectionFamily(const Comm::Connection &conn);

    Comm::ConnectionList::iterator findSpareOrNextPeer(const Comm::Connection &currentPeer);
    Comm::ConnectionPointer extractFound(const char *description, const Comm::ConnectionList::iterator &found);

    Comm::ConnectionList paths_;
};

/// summarized ResolvedPeers (for debugging)
std::ostream &operator <<(std::ostream &, const ResolvedPeers &);

#endif /* SQUID_RESOLVEDPEERS_H */

