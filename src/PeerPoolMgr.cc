/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "base/AsyncCallbacks.h"
#include "base/RunnersRegistry.h"
#include "CachePeer.h"
#include "comm/Connection.h"
#include "comm/ConnOpener.h"
#include "debug/Stream.h"
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

CBDATA_CLASS_INIT(PeerPoolMgr);

PeerPoolMgr::PeerPoolMgr(CachePeer *aPeer): AsyncJob("PeerPoolMgr"),
    peer(cbdataReference(aPeer)),
    request(),
    transportWait(),
    encryptionWait(),
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

    const auto mx = MasterXaction::MakePortless<XactionInitiator::initPeerPool>();
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
    transportWait.finish();

    if (!validPeer()) {
        debugs(48, 3, "peer gone");
        if (params.conn != nullptr)
            params.conn->close();
        return;
    }

    if (params.flag != Comm::OK) {
        NoteOutgoingConnectionFailure(peer, Http::scNone);
        checkpoint("conn opening failure"); // may retry
        return;
    }

    Must(params.conn != nullptr);

    // Handle TLS peers.
    if (peer->secure.encryptTransport) {
        // XXX: Exceptions orphan params.conn
        const auto callback = asyncCallback(48, 4, PeerPoolMgr::handleSecuredPeer, this);

        const auto peerTimeout = peer->connectTimeout();
        const int timeUsed = squid_curtime - params.conn->startTime();
        // Use positive timeout when less than one second is left for conn.
        const int timeLeft = positiveTimeout(peerTimeout - timeUsed);
        const auto connector = new Security::BlindPeerConnector(request, params.conn, callback, nullptr, timeLeft);
        encryptionWait.start(connector, callback);
        return;
    }

    pushNewConnection(params.conn);
}

void
PeerPoolMgr::pushNewConnection(const Comm::ConnectionPointer &conn)
{
    Must(validPeer());
    Must(Comm::IsConnOpen(conn));
    peer->standby.pool->push(conn, nullptr /* domain */);
    // push() will trigger a checkpoint()
}

void
PeerPoolMgr::handleSecuredPeer(Security::EncryptorAnswer &answer)
{
    encryptionWait.finish();

    if (!validPeer()) {
        debugs(48, 3, "peer gone");
        if (answer.conn != nullptr)
            answer.conn->close();
        return;
    }

    assert(!answer.tunneled);
    if (answer.error.get()) {
        assert(!answer.conn);
        // PeerConnector calls NoteOutgoingConnectionFailure() for us
        checkpoint("conn securing failure"); // may retry
        return;
    }

    assert(answer.conn);

    // The socket could get closed while our callback was queued. Sync
    // Connection. XXX: Connection::fd may already be stale/invalid here.
    if (answer.conn->isOpen() && fd_table[answer.conn->fd].closing()) {
        answer.conn->noteClosure();
        checkpoint("external connection closure"); // may retry
        return;
    }

    pushNewConnection(answer.conn);
}

void
PeerPoolMgr::openNewConnection()
{
    // KISS: Do nothing else when we are already doing something.
    if (transportWait || encryptionWait || shutting_down) {
        debugs(48, 7, "busy: " << transportWait << '|' << encryptionWait << '|' << shutting_down);
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

    const auto ctimeout = peer->connectTimeout();
    typedef CommCbMemFunT<PeerPoolMgr, CommConnectCbParams> Dialer;
    AsyncCall::Pointer callback = JobCallback(48, 5, Dialer, this, PeerPoolMgr::handleOpenedConnection);
    const auto cs = new Comm::ConnOpener(conn, callback, ctimeout);
    transportWait.start(cs, callback);
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
    void useConfig() override { syncConfig(); }
    void syncConfig() override;
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

