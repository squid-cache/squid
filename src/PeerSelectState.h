/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
#include "ipcache.h"
#include "mem/forward.h"
#include "PingData.h"
#include "typedefs.h" /* for IRCB */

class ErrorState;
class HtcpReplyData;
class HttpRequest;
class icp_common_t;
class StoreEntry;

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

/// Finds peer (including origin server) IPs for forwarding a single request.
/// Gives PeerSelectionInitiator each found destination, in the right order.
class PeerSelector: public Dns::IpReceiver
{
    CBDATA_CHILD(PeerSelector);

public:
    explicit PeerSelector(PeerSelectionInitiator*);
    virtual ~PeerSelector() override;

    /* Dns::IpReceiver API */
    virtual void noteIp(const Ip::Address &ip) override;
    virtual void noteIps(const Dns::CachedIps *ips, const Dns::LookupDetails &details) override;
    virtual void noteLookup(const Dns::LookupDetails &details) override;

    // Produce a URL for display identifying the transaction we are
    // trying to locate a peer for.
    const SBuf url() const;

    /// \returns valid/interested peer initiator or nil
    PeerSelectionInitiator *interestedInitiator();

    /// \returns whether the initiator may use more destinations
    bool wantsMoreDestinations() const;

    /// processes a newly discovered/finalized path
    void handlePath(const Comm::ConnectionPointer &path, FwdServer &fs);

    /// a single selection loop iteration: attempts to add more destinations
    void selectMore();

    /// switches into the PING_WAITING state (and associated timeout monitoring)
    void startPingWaiting();

    /// terminates ICP ping timeout monitoring
    void cancelPingTimeoutMonitoring();

    /// called when the given selector should stop expecting ICP ping responses
    static void HandlePingTimeout(PeerSelector *);

    HttpRequest *request;
    AccessLogEntry::Pointer al; ///< info for the future access.log entry
    StoreEntry *entry;

    void *peerCountMcastPeerXXX = nullptr; ///< a hack to help peerCountMcastPeersStart()

    ping_data ping;

protected:
    bool selectionAborted();

    void handlePingTimeout();
    void handleIcpReply(CachePeer*, const peer_t, icp_common_t *header);
    void handleIcpParentMiss(CachePeer*, icp_common_t*);
#if USE_HTCP
    void handleHtcpParentMiss(CachePeer*, HtcpReplyData*);
    void handleHtcpReply(CachePeer*, const peer_t, HtcpReplyData*);
#endif

    int checkNetdbDirect();
    void checkAlwaysDirectDone(const Acl::Answer answer);
    void checkNeverDirectDone(const Acl::Answer answer);

    void selectSomeNeighbor();
    void selectSomeNeighborReplies();
    void selectSomeDirect();
    void selectSomeParent();
    void selectAllParents();
    void selectPinned();

    void addSelection(CachePeer*, const hier_code);

    void resolveSelected();

    static IRCB HandlePingReply;
    static ACLCB CheckAlwaysDirectDone;
    static ACLCB CheckNeverDirectDone;

private:
    Acl::Answer always_direct;
    Acl::Answer never_direct;
    int direct;   // TODO: fold always_direct/never_direct/prefer_direct into this now that ACL can do a multi-state result.
    size_t foundPaths = 0; ///< number of unique destinations identified so far
    ErrorState *lastError;

    FwdServer *servers; ///< a linked list of (unresolved) selected peers

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
    ACLChecklist *acl_checklist;

    typedef CbcPointer<PeerSelectionInitiator> Initiator;
    Initiator initiator_; ///< recipient of the destinations we select; use interestedInitiator() to access

    const InstanceId<PeerSelector> id; ///< unique identification in worker log
};

#endif /* SQUID_PEERSELECTSTATE_H */

