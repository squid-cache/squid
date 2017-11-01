#include "squid.h"
#include "CachePeer.h"
#include "FwdState.h"
#include "HappyConnOpener.h"
#include "HttpRequest.h"
#include "ip/QosConfig.h"
#include "neighbors.h"
#include "pconn.h"
#include "PeerPoolMgr.h"
#include "SquidConfig.h"

CBDATA_CLASS_INIT(HappyConnOpener);

static PconnPool *fwdPconnPool = new PconnPool("server-peers", NULL);

static std::queue<HappyConnOpener::Pointer> HappyConnectorsQueue;

int HappyConnOpener::SpareConnects = 0;
double HappyConnOpener::LastAttempt = 0;

std::ostream &operator <<(std::ostream &os, const HappyConnOpener::Answer &answer)
{
    return os << answer.conn << ", " << answer.ioStatus << ", " << answer.xerrno << ", " << (answer.reused ? "reused" : "new");
}

HappyConnOpener::HappyConnOpener(const CandidatePaths::Pointer &destinations, const AsyncCall::Pointer &aCall, const time_t fwdStart, int tries) : AsyncJob("HappyConnOpener"),callback_(aCall), dests_(destinations), allowPconn(true), retriable_(true), host_(nullptr), fwdStart_(fwdStart), maxTries(tries), n_tries(0), useTos(0), useNfmark(0)
{
    assert(dynamic_cast<HappyConnOpener::CbDialer *>(callback_->getDialer()));
}

HappyConnOpener::~HappyConnOpener()
{
    safe_free(host_);
    debugs(17,5, "destroyed");
}

void
HappyConnOpener::setHost(const char *h)
{
    safe_free(host_);
    if (h)
        host_ = xstrdup(h);
}

void
HappyConnOpener::start()
{
}

bool
HappyConnOpener::doneAll() const
{
    if (!callback_ || callback_->canceled())
        return AsyncJob::doneAll();
    return false;
}

void
HappyConnOpener::swanSong()
{
    debugs(17,5, "HappyConnOpener::swanSong: Job finished, cleanup");
    if (callback_ != nullptr) {
        callCallback(nullptr, Comm::ERR_CONNECT, 0, false, "unexpected end");
    }

    if (master.path != nullptr) {
        if (master.connector != nullptr)
            master.connector->cancel("HappyConnOpener object destructed");
        master.connector = nullptr;
        master.path = nullptr;
    }

    if (spare.path == nullptr) {
        if (spare.connector != nullptr)
            spare.connector->cancel("HappyConnOpener object destructed");
        spare.connector = nullptr;
        spare.path = nullptr;
    }

    AsyncJob::swanSong();
}

void
HappyConnOpener::callCallback(const Comm::ConnectionPointer &conn, Comm::Flag err, int xerrno, bool reused, const char *msg)
{
    if (callback_ && !callback_->canceled()) {
        HappyConnOpener::CbDialer *cd = dynamic_cast<HappyConnOpener::CbDialer *>(callback_->getDialer());
        cd->answer_.conn = conn;
        cd->answer_.host = nullptr;
        cd->answer_.ioStatus = err;
        cd->answer_.xerrno = xerrno;
        cd->answer_.status = msg;
        cd->answer_.n_tries = n_tries;
        cd->answer_.reused = reused;
        ScheduleCallHere(callback_);
    }
    callback_ = nullptr;
}

void
HappyConnOpener::noteCandidatePath()
{
    assert(dests_ != nullptr);
    debugs(17, 8, "New candidate path from caller, number of destinations " << dests_->count());
    checkForNewConnection();
}

bool
HappyConnOpener::SystemPreconditions()
{
    if (Config.happyEyeballs.connect_limit > 0 && HappyConnOpener::SpareConnects >= Config.happyEyeballs.connect_limit)
        return false;

    if (HappyConnOpener::LastAttempt > current_dtime - (double)Config.happyEyeballs.connect_gap/1000.0)
        return false;

    return true;
}

bool
HappyConnOpener::timeCondition()
{
    if (lastStart > current_dtime - (double)Config.happyEyeballs.connect_timeout/1000.0)
        return false;
    return true;
}

bool
HappyConnOpener::preconditions()
{
    
    if (dests_->empty())
        return false;

    // If no available connection start one
    if (master.path == nullptr)
        return true;

    if (n_tries >= maxTries)
        return false;

    if (!timeCondition())
        return false;

    if (!HappyConnOpener::SystemPreconditions())
        return false;

    return (spare.path == nullptr);
}

/**
 * Called after forwarding path selection (via peer select) has taken place
 * and whenever forwarding needs to attempt a new connection (routing failover).
 * We have a vector of possible localIP->remoteIP paths now ready to start being connected.
 */
void
HappyConnOpener::startConnecting(Comm::ConnectionPointer &dest)
{
    assert(spare.path == nullptr);
    assert(spare.connector == nullptr);
    // Use pconn to avoid opening a new connection.
    Comm::ConnectionPointer temp;
    if (allowPconn)
        temp = PconnPop(dest, (dest->getPeer() ? nullptr : host_), retriable_);

    const bool openedPconn = Comm::IsConnOpen(temp);

    // if we found an open persistent connection to use. use it.
    if (openedPconn) {
        if (master.path == nullptr)
            master.path = temp;
        else
            spare.path = temp;

        ++n_tries;
        callCallback(temp, Comm::OK, 0, true, "reusing pconn");
        return;
    }

#if URL_CHECKSUM_DEBUG
    entry->mem_obj->checkUrlChecksum();
#endif

    //GetMarkingsToServer(request, *dest);
    dest->tos = useTos;
    dest->nfmark = useNfmark;

    dest->local.port(0);
    ++n_tries;

    typedef CommCbMemFunT<HappyConnOpener, CommConnectCbParams> Dialer;
    AsyncCall::Pointer callConnect = JobCallback(48, 5, Dialer, this, HappyConnOpener::connectDone);
    const time_t connTimeout = dest->connectTimeout(fwdStart_);
    Comm::ConnOpener *cs = new Comm::ConnOpener(dest, callConnect, connTimeout);
    if (!dest->getPeer())
        cs->setHost(host_);

    if (master.path == nullptr) {
        master.path = dest;
        master.connector = callConnect;
    } else {
        spare.path = dest;
        spare.connector = callConnect;
        HappyConnOpener::SpareConnects++;
    }

    lastStart = current_dtime;
    HappyConnOpener::LastAttempt = current_dtime;
    AsyncJob::Start(cs);
}

void
HappyConnOpener::connectDone(const CommConnectCbParams &params)
{
    if (master.path == params.conn) {
        // master connection is now the remaining spare if exist, or null
        master = spare;
    } else {
        assert(spare.path == params.conn);
        HappyConnOpener::SpareConnects--;
        spare.path = nullptr;
        spare.connector = nullptr;
    }

    if (params.flag != Comm::OK) {
        /* it might have been a timeout with a partially open link */
        if (params.conn != NULL) {
            if (params.conn->getPeer())
                peerConnectFailed(params.conn->getPeer());

            params.conn->close();
        }

        checkForNewConnection();
        return;
    }

    if (master.path) {
        Must(master.connector != nullptr);
        master.connector->cancel("Already connected");
        master.connector = nullptr;
        master.path = nullptr;
    }

    callCallback(params.conn, Comm::OK, 0, false, "new connection");
    return;
}

Comm::ConnectionPointer
HappyConnOpener::getCandidatePath()
{
    // if there is not any pending connection just get the first available destination
    if (master.path == nullptr)
        return dests_->popFirst();

    // Check if there is available destination with different protocol
    // than the last connector
    int lastConnectionFamily = CandidatePaths::ConnectionFamily(master.path);
    return dests_->popFirstNotInFamily(lastConnectionFamily);
}

void
HappyConnOpener::checkForNewConnection()
{
    debugs(17, 8, "Check for starting new connection");
    assert(dests_ != nullptr);

    if (preconditions()) {
        assert(!dests_->empty());
        Comm::ConnectionPointer dest = getCandidatePath();
        if (dest != nullptr)
            startConnecting(dest);
        return;
    }

    if (Config.happyEyeballs.connect_limit == 0)
        return; // feature disabled

    // Else check to start a monitoring process to start secondary connections
    // if required.
    if (!dests_->empty()  && spare.path == nullptr) {
        if (HappyConnectorsQueue.empty()) // Restart queue run
            eventAdd("ManageHappyConnections", ManageConnections, NULL, 0.010, false);
        HappyConnectorsQueue.push(HappyConnOpener::Pointer(this));
    }
}

/**
 * Decide where details need to be gathered to correctly describe a persistent connection.
 * What is needed:
 *  -  the address/port details about this link
 *  -  domain name of server at other end of this link (either peer or requested host)
 */
void
HappyConnOpener::PconnPush(Comm::ConnectionPointer &conn, const char *domain)
{
    if (conn->getPeer()) {
        fwdPconnPool->push(conn, NULL);
    } else {
        fwdPconnPool->push(conn, domain);
    }
}

Comm::ConnectionPointer
HappyConnOpener::PconnPop(const Comm::ConnectionPointer &dest, const char *domain, bool retriable)
{
    // always call shared pool first because we need to close an idle
    // connection there if we have to use a standby connection.
    Comm::ConnectionPointer conn = fwdPconnPool->pop(dest, domain, retriable);
    if (!Comm::IsConnOpen(conn)) {
        // either there was no pconn to pop or this is not a retriable xaction
        if (CachePeer *peer = dest->getPeer()) {
            if (peer->standby.pool)
                conn = peer->standby.pool->pop(dest, domain, true);
        }
    }
    return conn; // open, closed, or nil
}

void
HappyConnOpener::ConnectionClosed(const Comm::ConnectionPointer &conn)
{
    fwdPconnPool->noteUses(fd_table[conn->fd].pconn.uses);
}

void
HappyConnOpener::ManageConnections(void *)
{
    debugs(17, 8, "Queue size: " << HappyConnectorsQueue.size());

    if (HappyConnOpener::SystemPreconditions()) {
        while (!HappyConnectorsQueue.empty() && (!HappyConnectorsQueue.front().valid() || HappyConnectorsQueue.front()->timeCondition())) {
            HappyConnOpener::Pointer he = HappyConnectorsQueue.front();
            HappyConnectorsQueue.pop();
            if (he.valid()) {
                typedef NullaryMemFunT<HappyConnOpener> CbDialer;
                AsyncCall::Pointer informCall = JobCallback(17, 5, CbDialer, he, HappyConnOpener::checkForNewConnection);
                ScheduleCallHere(informCall);
            }
        }
    }

    if (!HappyConnectorsQueue.empty())
        eventAdd("ManageHappyConnections", ManageConnections, NULL, 0.010, false);
}
