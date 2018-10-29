/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_RESOLVEDPEERS_H
#define SQUID_RESOLVEDPEERS_H

#include "base/RefCount.h"
#include "comm/forward.h"

/// origin server and cache_peer addresses
/// selected and resolved by the peering code
class ResolvedPeers: public RefCountable
{
public:
    typedef RefCount<ResolvedPeers> Pointer;
    ResolvedPeers();

    /// Add the path to the top of candidate paths. Normally used
    /// to retry a failed connection.
    void retryPath(const Comm::ConnectionPointer &);

    /// Add a new path to the end of candidate paths.
    void newPath(const Comm::ConnectionPointer &);

    /// Whether the list is empty
    bool empty() {return paths_.empty();}

    /// extracts and returns the first queued address
    Comm::ConnectionPointer extractFront();

    /// extracts and returns the first same-peer same-family address
    /// \returns nil if it cannot find the requested address
    Comm::ConnectionPointer extractPrime(const Comm::Connection &currentPeer);
    /// extracts and returns the first same-peer different-family address
    /// \returns nil if it cannot find the requested address
    Comm::ConnectionPointer extractSpare(const Comm::Connection &currentPeer);

    /// whether extractSpare() would return a non-nil path right now
    bool haveSpare(const Comm::Connection &currentPeer) const;

    /// whether extractPrime() returns and will continue to return nil
    bool doneWithPrimes(const Comm::Connection &currentPeer) const;

    /// whether extractSpare() returns and will continue to return nil
    bool doneWithSpares(const Comm::Connection &currentPeer) const;

    /// whether doneWithPrimes() and doneWithSpares() are true for currentPeer
    bool doneWithPeer(const Comm::Connection &currentPeer) const;

    /// the current number of candidate paths
    int size() {return paths_.size();}

    /// The protocol family of the given path, AF_INET or AF_INET6
    static int ConnectionFamily(const Comm::Connection &conn);

    /// whether all of the available candidate paths received from DNS
    bool destinationsFinalized;

    /// whether all of the available candidate paths received from DNS
    bool updateNotificationPending = false;

private:
    Comm::ConnectionList::const_iterator findSpareOrNextPeer(const Comm::Connection &currentPeer) const;
    Comm::ConnectionPointer extractFound(const char *description, const Comm::ConnectionList::const_iterator &found);

    Comm::ConnectionList paths_;
};

#endif /* SQUID_RESOLVEDPEERS_H */

