/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PINGDATA_H
#define SQUID_PINGDATA_H

#include "mem/PoolingAllocator.h"

#include <map>

class PeerSelector;
class PeerSelectorPingMonitor;

typedef std::pair<timeval, PeerSelector *> WaitingPeerSelector;
/// waiting PeerSelector objects, ordered by their absolute deadlines
typedef std::multimap<timeval, PeerSelector *, std::less<timeval>, PoolingAllocator<WaitingPeerSelector> > WaitingPeerSelectors;
typedef WaitingPeerSelectors::iterator WaitingPeerSelectorPosition;

/// ICP probing of cache_peers during peer selection
class ping_data
{

public:
    ping_data();

    /// no ICP responses are expected beyond the returned absolute time
    /// \returns start + timeout
    timeval deadline() const;

    struct timeval start;

    struct timeval stop;
    int n_sent;
    int n_recv;
    int n_replies_expected;
    int timeout;        /* msec */
    int timedout;
    int w_rtt;
    int p_rtt;

private:
    friend PeerSelectorPingMonitor;
    /// maintained by PeerSelectorPingMonitor
    WaitingPeerSelectorPosition monitorRegistration;
};

#endif /* SQUID_PINGDATA_H */

