/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PEERPOOLMGR_H
#define SQUID_PEERPOOLMGR_H

#include "base/AsyncJob.h"
#include "comm/forward.h"
#include "security/forward.h"

class HttpRequest;
class CachePeer;
class CommConnectCbParams;

/// Maintains an fixed-size "standby" PconnPool for a single CachePeer.
class PeerPoolMgr: public AsyncJob
{
    CBDATA_CLASS(PeerPoolMgr);

public:
    typedef CbcPointer<PeerPoolMgr> Pointer;

    // syncs mgr state whenever connection-related peer or pool state changes
    static void Checkpoint(const Pointer &mgr, const char *reason);

    explicit PeerPoolMgr(CachePeer *aPeer);
    virtual ~PeerPoolMgr();

protected:
    /* AsyncJob API */
    virtual void start();
    virtual void swanSong();
    virtual bool doneAll() const;

    /// whether the peer is still out there and in a valid state we can safely use
    bool validPeer() const;

    /// Starts new connection, or closes the excess connections
    /// according pool configuration
    void checkpoint(const char *reason);
    /// starts the process of opening a new standby connection (if possible)
    void openNewConnection();
    /// closes 'howMany' standby connections
    void closeOldConnections(const int howMany);

    /// Comm::ConnOpener calls this when done opening a connection for us
    void handleOpenedConnection(const CommConnectCbParams &params);

    /// Security::PeerConnector callback
    void handleSecuredPeer(Security::EncryptorAnswer &answer);

    /// called when the connection we are trying to secure is closed by a 3rd party
    void handleSecureClosure(const CommCloseCbParams &params);

    /// the final step in connection opening (and, optionally, securing) sequence
    void pushNewConnection(const Comm::ConnectionPointer &conn);

private:
    CachePeer *peer; ///< the owner of the pool we manage
    RefCount<HttpRequest> request; ///< fake HTTP request for conn opening code
    AsyncCall::Pointer opener; ///< whether we are opening a connection
    AsyncCall::Pointer securer; ///< whether we are securing a connection
    AsyncCall::Pointer closer; ///< monitors conn while we are securing it
    unsigned int addrUsed; ///< counter for cycling through peer addresses
};

#endif /* SQUID_PEERPOOLMGR_H */

