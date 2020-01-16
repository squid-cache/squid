/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "base/AsyncJobCalls.h"
#include "base/RunnersRegistry.h"
#include "CachePeer.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "Debug.h"
#include "fd.h"
#include "FwdState.h"
#include "globals.h"
#include "HttpRequest.h"
#include "MasterXaction.h"
#include "neighbors.h"
#include "pconn.h"
#include "PeerPoolMgr.h"
#include "security/BlindPeerConnector.h"
#include "SquidConfig.h"
#include "SquidTime.h"

CBDATA_CLASS_INIT(PeerPoolMgr);

/// Gives Security::PeerConnector access to Answer in the PeerPoolMgr callback dialer.
class MyAnswerDialer: public UnaryMemFunT<PeerPoolMgr, Security::EncryptorAnswer, Security::EncryptorAnswer&>,
    public Security::PeerConnector::CbDialer
{
public:
    MyAnswerDialer(const JobPointer &aJob, Method aMethod):
        UnaryMemFunT<PeerPoolMgr, Security::EncryptorAnswer, Security::EncryptorAnswer&>(aJob, aMethod, Security::EncryptorAnswer()) {}

    /* Security::PeerConnector::CbDialer API */
    virtual Security::EncryptorAnswer &answer() { return arg1; }
};

PeerPoolMgr::PeerPoolMgr(CachePeer *aPeer): AsyncJob("PeerPoolMgr"),
    peer(cbdataReference(aPeer)),
    request(),
    opener(),
    securer(),
    closer(),
    addrUsed(0)
{
}

PeerPoolMgr::~PeerPoolMgr()
{
    cbdataReferenceDone(peer);
}

void
PeerPoolMgr::start()
{
    AsyncJob::start();

    const MasterXaction::Pointer mx = new MasterXaction(XactionInitiator::initPeerPool);
    // ErrorState, getOutgoingAddress(), and other APIs may require a request.
    // We fake one. TODO: Optionally send this request to peers?
    request = new HttpRequest(Http::METHOD_OPTIONS, AnyP::PROTO_HTTP, "http", "*", mx);
    request->url.host(peer->host);

    checkpoint("peer initialized");
}

void
PeerPoolMgr::swanSong()
{
    AsyncJob::swanSong();
}

bool
PeerPoolMgr::validPeer() const
{
    return peer && cbdataReferenceValid(peer) && peer->standby.pool;
}

bool
PeerPoolMgr::doneAll() const
{
    return !(validPeer() && peer->standby.limit) && AsyncJob::doneAll();
}

void
PeerPoolMgr::handleOpenedConnection(const CommConnectCbParams &params)
{
    opener = NULL;

    if (!validPeer()) {
        debugs(48, 3, "peer gone");
        if (params.conn != NULL)
            params.conn->close();
        return;
    }

    if (params.flag != Comm::OK) {
        /* it might have been a timeout with a partially open link */
        if (params.conn != NULL)
            params.conn->close();
        peerConnectFailed(peer);
        checkpoint("conn opening failure"); // may retry
        return;
    }

    Must(params.conn != NULL);

    // Handle TLS peers.
    if (peer->secure.encryptTransport) {
        typedef CommCbMemFunT<PeerPoolMgr, CommCloseCbParams> CloserDialer;
        closer = JobCallback(48, 3, CloserDialer, this,
                             PeerPoolMgr::handleSecureClosure);
        comm_add_close_handler(params.conn->fd, closer);

        securer = asyncCall(48, 4, "PeerPoolMgr::handleSecuredPeer",
                            MyAnswerDialer(this, &PeerPoolMgr::handleSecuredPeer));

        const int peerTimeout = peerConnectTimeout(peer);
        const int timeUsed = squid_curtime - params.conn->startTime();
        // Use positive timeout when less than one second is left for conn.
        const int timeLeft = positiveTimeout(peerTimeout - timeUsed);
        auto *connector = new Security::BlindPeerConnector(request, params.conn, securer, nullptr, timeLeft);
        AsyncJob::Start(connector); // will call our callback
        return;
    }

    pushNewConnection(params.conn);
}

void
PeerPoolMgr::pushNewConnection(const Comm::ConnectionPointer &conn)
{
    Must(validPeer());
    Must(Comm::IsConnOpen(conn));
    peer->standby.pool->push(conn, NULL /* domain */);
    // push() will trigger a checkpoint()
}

void
PeerPoolMgr::handleSecuredPeer(Security::EncryptorAnswer &answer)
{
    Must(securer != NULL);
    securer = NULL;

    if (closer != NULL) {
        if (answer.conn != NULL)
            comm_remove_close_handler(answer.conn->fd, closer);
        else
            closer->cancel("securing completed");
        closer = NULL;
    }

    if (!validPeer()) {
        debugs(48, 3, "peer gone");
        if (answer.conn != NULL)
            answer.conn->close();
        return;
    }

    if (answer.error.get()) {
        if (answer.conn != NULL)
            answer.conn->close();
        // PeerConnector calls peerConnectFailed() for us;
        checkpoint("conn securing failure"); // may retry
        return;
    }

    pushNewConnection(answer.conn);
}

void
PeerPoolMgr::handleSecureClosure(const CommCloseCbParams &params)
{
    Must(closer != NULL);
    Must(securer != NULL);
    securer->cancel("conn closed by a 3rd party");
    securer = NULL;
    closer = NULL;
    // allow the closing connection to fully close before we check again
    Checkpoint(this, "conn closure while securing");
}

void
PeerPoolMgr::openNewConnection()
{
    // KISS: Do nothing else when we are already doing something.
    if (opener != NULL || securer != NULL || shutting_down) {
        debugs(48, 7, "busy: " << opener << '|' << securer << '|' << shutting_down);
        return; // there will be another checkpoint when we are done opening/securing
    }

    // Do not talk to a peer until it is ready.
    if (!neighborUp(peer)) // provides debugging
        return; // there will be another checkpoint when peer is up

    // Do not violate peer limits.
    if (!peerCanOpenMore(peer)) { // provides debugging
        peer->standby.waitingForClose = true; // may already be true
        return; // there will be another checkpoint when a peer conn closes
    }

    // Do not violate global restrictions.
    if (fdUsageHigh()) {
        debugs(48, 7, "overwhelmed");
        peer->standby.waitingForClose = true; // may already be true
        // There will be another checkpoint when a peer conn closes OR when
        // a future pop() fails due to an empty pool. See PconnPool::pop().
        return;
    }

    peer->standby.waitingForClose = false;

    Comm::ConnectionPointer conn = new Comm::Connection;
    Must(peer->n_addresses); // guaranteed by neighborUp() above
    // cycle through all available IP addresses
    conn->remote = peer->addresses[addrUsed++ % peer->n_addresses];
    conn->remote.port(peer->http_port);
    conn->peerType = STANDBY_POOL; // should be reset by peerSelect()
    conn->setPeer(peer);
    getOutgoingAddress(request.getRaw(), conn);
    GetMarkingsToServer(request.getRaw(), *conn);

    const int ctimeout = peerConnectTimeout(peer);
    typedef CommCbMemFunT<PeerPoolMgr, CommConnectCbParams> Dialer;
    opener = JobCallback(48, 5, Dialer, this, PeerPoolMgr::handleOpenedConnection);
    Comm::ConnOpener *cs = new Comm::ConnOpener(conn, opener, ctimeout);
    AsyncJob::Start(cs);
}

void
PeerPoolMgr::closeOldConnections(const int howMany)
{
    debugs(48, 8, howMany);
    peer->standby.pool->closeN(howMany);
}

void
PeerPoolMgr::checkpoint(const char *reason)
{
    if (!validPeer()) {
        debugs(48, 3, reason << " and peer gone");
        return; // nothing to do after our owner dies; the job will quit
    }

    const int count = peer->standby.pool->count();
    const int limit = peer->standby.limit;
    debugs(48, 7, reason << " with " << count << " ? " << limit);

    if (count < limit)
        openNewConnection();
    else if (count > limit)
        closeOldConnections(count - limit);
}

void
PeerPoolMgr::Checkpoint(const Pointer &mgr, const char *reason)
{
    CallJobHere1(48, 5, mgr, PeerPoolMgr, checkpoint, reason);
}

/// launches PeerPoolMgrs for peers configured with standby.limit
class PeerPoolMgrsRr: public RegisteredRunner
{
public:
    /* RegisteredRunner API */
    virtual void useConfig() { syncConfig(); }
    virtual void syncConfig();
};

RunnerRegistrationEntry(PeerPoolMgrsRr);

void
PeerPoolMgrsRr::syncConfig()
{
    for (CachePeer *p = Config.peers; p; p = p->next) {
        // On reconfigure, Squid deletes the old config (and old peers in it),
        // so should always be dealing with a brand new configuration.
        assert(!p->standby.mgr);
        assert(!p->standby.pool);
        if (p->standby.limit) {
            p->standby.mgr = new PeerPoolMgr(p);
            p->standby.pool = new PconnPool(p->name, p->standby.mgr);
            AsyncJob::Start(p->standby.mgr.get());
        }
    }
}

