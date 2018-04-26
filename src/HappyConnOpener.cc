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

int HappyConnOpener::SpareConnects = 0;
double HappyConnOpener::LastAttempt = 0;

/// Manages a queue of HappyConnOpeners objects waiting the preconditions
/// to be satisfied in order to start an attempt for a new spare connection
class HappyConnQueue {
public:
    /// Schedule the next check for starting new connection attempts
    void scheduleConnectorsListCheck();

    /// Check if the next HappyConnOpener in queue satisfies the preconditions
    /// to start a new connection attempt
    void checkForConnectionAttempts();

    /// \return pointer to the first valid connector in queue or nil
    const HappyConnOpener::Pointer &frontOpener();

    /// Add the HappyConnOpener object to the queue
    void waitingForConnectionAttempt(HappyConnOpener::Pointer happy);

    /// The list of connectors waiting to start a new spare connection attempt
    /// when system and current request preconditions satisfied.
    std::list<HappyConnOpener::Pointer> waitingConnectors;
};

HappyConnQueue HappyQueue;

std::ostream &operator <<(std::ostream &os, const HappyConnOpener::Answer &answer)
{
    return os << answer.conn << ", " << answer.ioStatus << ", " << answer.xerrno << ", " << (answer.reused ? "reused" : "new");
}

HappyConnOpener::HappyConnOpener(const CandidatePaths::Pointer &destinations, const AsyncCall::Pointer &aCall, const time_t fwdStart, int tries) : AsyncJob("HappyConnOpener"), useTos(0), useNfmark(0), callback_(aCall), dests_(destinations), allowPconn_(true), retriable_(true), waitingSpareConnection_(false), host_(nullptr), fwdStart_(fwdStart), maxTries(tries), n_tries(0)
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
    debugs(17, 8, "Start connecting");
    checkForNewConnection();
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
    if (callback_) {
        callCallback(nullptr, Comm::ERR_CONNECT, 0, false, "unexpected end");
    }

    if (master.path) {
        if (master.connector)
            master.connector->cancel("HappyConnOpener object destructed");
        master.connector = nullptr;
        master.path = nullptr;
    }

    if (!spare.path) {
        if (spare.connector)
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
    assert(dests_);
    debugs(17, 8, "New candidate path from caller, number of destinations " << dests_->size());
    checkForNewConnection();
}

bool
HappyConnOpener::primaryConnectTooSlow() const
{
    return (nextAttemptTime <= current_dtime);
}

bool
HappyConnOpener::spareConnectionPreconditions() const
{
    assert(spare.path == nullptr);

    if (n_tries >= maxTries)
        return false;

    if (!primaryConnectTooSlow())
        return false;

    if (!SpareConnectionAllowedNow())
        return false;

    return true;
}

void
HappyConnOpener::startConnecting(PendingConnection &pconn, Comm::ConnectionPointer &dest)
{
    assert(!spare.path);
    assert(!spare.connector);
    // Use pconn to avoid opening a new connection.
    Comm::ConnectionPointer temp;
    if (allowPconn_)
        temp = PconnPop(dest, (dest->getPeer() ? nullptr : host_), retriable_);

    const bool openedPconn = Comm::IsConnOpen(temp);

    // if we found an open persistent connection to use. use it.
    if (openedPconn) {
        pconn.path = temp;
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

        pconn.path = dest;
        pconn.connector = callConnect;
        if (&pconn == &spare) // this is a spare connection
            ++SpareConnects;

    nextAttemptTime = current_dtime + (double)Config.happyEyeballs.connect_timeout/1000.0;
    LastAttempt = current_dtime;
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
    }

    if (spare.path) {
        --SpareConnects;
        spare.path = nullptr;
        spare.connector = nullptr;
    }

    if (params.flag != Comm::OK) {
        debugs(17, 8, "Connections to " << params.conn << " failed");
        /* it might have been a timeout with a partially open link */
        if (params.conn != NULL) {
            if (params.conn->getPeer())
                peerConnectFailed(params.conn->getPeer());

            params.conn->close();
        }

        checkForNewConnection();
        return;
    }

    debugs(17, 8, "Connections to " << params.conn << " succeed");
    if (master.path) {
        Must(master.connector);
        master.connector->cancel("Already connected");
        master.connector = nullptr;
        master.path = nullptr;
    }

    callCallback(params.conn, Comm::OK, 0, false, "new connection");
    return;
}

Comm::ConnectionPointer
HappyConnOpener::getCandidatePath(int excludeFamily)
{
    if (dests_->empty())
        return Comm::ConnectionPointer();

    // if no excludeFamily given, just get the first available destination
    if (!excludeFamily)
        return dests_->popFirst();

    return dests_->popFirstFromDifferentFamily(excludeFamily);
}

bool
HappyConnOpener::existCandidatePath()
{
    if (!master.path)
        return !dests_->empty();

    const auto lastConnectionFamily = CandidatePaths::ConnectionFamily(master.path);
    return dests_->existPathNotInFamily(lastConnectionFamily);
}

void
HappyConnOpener::checkForNewConnection()
{
    debugs(17, 8, "Check for starting new connection");
    assert(dests_);

    // If it is already waiting stop here even if we need the connection immediately.
    // Starting new connection will alter the this->nextAttemptTime member
    // which affects the waiting connectors ordering in HappyQueue.
    // XXX: check if in the case there is not any connection attempt in the go,
    // it is better to unregister from HappyQueue and start a connection immediately.
    if (waitingSpareConnection_) {
        debugs(17, 8, "already subscribed for starting new connection when ready");
        return;
    }

    if (spare.path) {
        Must(master.path);
        debugs(17, 8, "master and spare connections are pending");
        return;
    }

    if (!master.path) {
        Comm::ConnectionPointer dest = getCandidatePath(0);
        if (!dest)
            return; // wait for more destinations
        startConnecting(master, dest);
    }

    if (!spareConnectionsAllowed()) {
        debugs(17, 8, "Spare connections are disabled");
        return;
    }

    if (spareConnectionPreconditions()) {
        Comm::ConnectionPointer dest = getCandidatePath(CandidatePaths::ConnectionFamily(master.path));
        if (dest)
            startConnecting(spare, dest);
        return;
    }

    // Else check to start a monitoring process to start secondary connections
    // if required.
    if (existCandidatePath()) {
        debugs(17, 8, "Schedule a new attempt for later");
        HappyQueue.waitingForConnectionAttempt(HappyConnOpener::Pointer(this));
        waitingSpareConnection_ = true;
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

bool
HappyConnOpener::newSpareConnectionAttempt()
{
    if (!SpareConnectionAllowedNow())
        return false;

    if (!primaryConnectTooSlow())
        return false;

    waitingSpareConnection_ = false;

    typedef NullaryMemFunT<HappyConnOpener> CbDialer;
    AsyncCall::Pointer informCall = JobCallback(17, 5, CbDialer, this, HappyConnOpener::checkForNewConnection);
    ScheduleCallHere(informCall);
    return true;
}

bool
HappyConnOpener::SpareConnectionAllowedNow()
{
    int limit = ConnectLimit();
    if (limit >= 0 && SpareConnects >= limit)
        return false;

    if (LastAttempt > current_dtime - (double)ConnectGap()/1000.0)
        return false;

    return true;
}

int
HappyConnOpener::ConnectGap()
{
    if (Config.happyEyeballs.connect_gap < 0) // no explicit configuration
        return 5; // ms per worker

    // keep opening rate in check despite the lack of SMP sharing
    return Config.happyEyeballs.connect_gap * Config.workers;
}

int
HappyConnOpener::ConnectLimit()
{
    if (Config.happyEyeballs.connect_limit <= 0)
        return Config.happyEyeballs.connect_limit;

    int limit = Config.happyEyeballs.connect_limit / Config.workers;
    return (limit == 0 ? 1 : limit);
}

void CheckForConnectionAttempts(void *data)
{
    HappyConnQueue *queue = static_cast<HappyConnQueue *>(data);
    queue->checkForConnectionAttempts();
}

void
HappyConnQueue::scheduleConnectorsListCheck()
{
    HappyConnOpener::Pointer he = frontOpener();
    if (he.valid()) {
        double startAfter = he->nextAttempt() > current_dtime ? he->nextAttempt() - current_dtime : 0.000;
        eventAdd("HappyConnQueue::checkForConnectionAttempts", CheckForConnectionAttempts, this, startAfter, false);
    }
}

void
HappyConnQueue::waitingForConnectionAttempt(HappyConnOpener::Pointer happy)
{
    if (waitingConnectors.empty()) {
        waitingConnectors.push_back(happy);
        scheduleConnectorsListCheck(); // Restart queue run
        return;
    }
    // Exist at least one item in list
    auto it = waitingConnectors.rbegin();
    for (; it != waitingConnectors.rend(); ++it) {
        if ((*it).valid() && (*it)->nextAttempt() < happy->nextAttempt()) {
            waitingConnectors.insert(it.base(), happy);
            return;
        }
    }
    waitingConnectors.push_front(happy);
}

void
HappyConnQueue::checkForConnectionAttempts()
{
    debugs(17, 8, "Queue size: " << waitingConnectors.size());

    HappyConnOpener::Pointer he = frontOpener();
    if (he.valid() && he->newSpareConnectionAttempt())
        waitingConnectors.pop_front();

    scheduleConnectorsListCheck();
}

const HappyConnOpener::Pointer &
HappyConnQueue::frontOpener()
{
    while (!waitingConnectors.empty()) {
        if (waitingConnectors.front().valid())
            return waitingConnectors.front();
        waitingConnectors.pop_front();
    }
    static HappyConnOpener::Pointer nil;
    return nil;
}
