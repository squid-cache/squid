/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef   SQUID_PEERSELECTSTATE_H
#define   SQUID_PEERSELECTSTATE_H

#include "AccessLogEntry.h"
#include "acl/Checklist.h"
#include "base/CbcPointer.h"
#include "comm/forward.h"
#include "hier_code.h"
#include "ip/Address.h"
#include "mem/forward.h"
#include "PingData.h"

class HttpRequest;
class StoreEntry;
class ErrorState;

void peerSelectInit(void);

/// Interface for those who need a list of peers to forward a request to.
class PeerSelectionInitiator: public CbdataParent
{
public:
    virtual ~PeerSelectionInitiator() = default;

    /// called when a new unique destination has been found
    virtual void noteDestination(Comm::ConnectionPointer path) = 0;

    /// called when there will be no more noteDestination() calls
    /// \param error is a possible reason why no destinations were found; it is
    /// guaranteed to be nil if there was at least one noteDestination() call
    virtual void noteDestinationsEnd(ErrorState *error) = 0;

    /// whether noteDestination() and noteDestinationsEnd() calls are allowed
    bool subscribed = false;

/* protected: */
    /// Initiates asynchronous peer selection that eventually
    /// results in zero or more noteDestination() calls and
    /// exactly one noteDestinationsEnd() call.
    void startSelectingDestinations(HttpRequest *request, const AccessLogEntry::Pointer &ale, StoreEntry *entry);
};

class FwdServer;

class ps_state
{
    CBDATA_CLASS(ps_state);

public:
    explicit ps_state(PeerSelectionInitiator *initiator);
    ~ps_state();

    // Produce a URL for display identifying the transaction we are
    // trying to locate a peer for.
    const SBuf url() const;

    /// \returns valid/interested peer initiator or nil
    PeerSelectionInitiator *interestedInitiator();

    /// \returns whether the initiator may use more destinations
    bool wantsMoreDestinations() const;

    /// processes a newly discovered/finalized path
    void handlePath(Comm::ConnectionPointer &path, FwdServer &fs);

    HttpRequest *request;
    AccessLogEntry::Pointer al; ///< info for the future access.log entry
    StoreEntry *entry;
    allow_t always_direct;
    allow_t never_direct;
    int direct;   // TODO: fold always_direct/never_direct/prefer_direct into this now that ACL can do a multi-state result.
    size_t foundPaths = 0; ///< number of unique destinations identified so far
    void *peerCountMcastPeerXXX = nullptr; ///< a hack to help peerCountMcastPeersStart()
    ErrorState *lastError;

    FwdServer *servers;    ///< temporary linked list of peers we will pass back.

    /*
     * Why are these Ip::Address instead of CachePeer *?  Because a
     * CachePeer structure can become invalid during the CachePeer selection
     * phase, specifically after a reconfigure.  Thus we need to lookup
     * the CachePeer * based on the address when we are finally ready to
     * reference the CachePeer structure.
     */

    Ip::Address first_parent_miss;

    Ip::Address closest_parent_miss;
    /*
     * ->hit can be CachePeer* because it should only be
     * accessed during the thread when it is set
     */
    CachePeer *hit;
    peer_t hit_type;
    ping_data ping;
    ACLChecklist *acl_checklist;

    const InstanceId<ps_state> id; ///< unique identification in worker log

private:

    typedef CbcPointer<PeerSelectionInitiator> Initiator;
    Initiator initiator_; ///< recipient of the destinations we select; use interestedInitiator() to access
};

#endif /* SQUID_PEERSELECTSTATE_H */

