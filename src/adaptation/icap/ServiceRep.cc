/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    ICAP (RFC 3507) Client */

#include "squid.h"
#include "adaptation/Answer.h"
#include "adaptation/icap/Config.h"
#include "adaptation/icap/ModXact.h"
#include "adaptation/icap/Options.h"
#include "adaptation/icap/OptXact.h"
#include "adaptation/icap/ServiceRep.h"
#include "base/TextException.h"
#include "comm/Connection.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "fde.h"
#include "globals.h"
#include "HttpReply.h"
#include "ip/tools.h"
#include "SquidConfig.h"
#include "SquidTime.h"

#define DEFAULT_ICAP_PORT   1344
#define DEFAULT_ICAPS_PORT 11344

CBDATA_NAMESPACED_CLASS_INIT(Adaptation::Icap, ServiceRep);

Adaptation::Icap::ServiceRep::ServiceRep(const ServiceConfigPointer &svcCfg):
    AsyncJob("Adaptation::Icap::ServiceRep"), Adaptation::Service(svcCfg),
    theOptions(NULL), theOptionsFetcher(0), theLastUpdate(0),
    theBusyConns(0),
    theAllWaiters(0),
    connOverloadReported(false),
    theIdleConns(NULL),
    isSuspended(0), notifying(false),
    updateScheduled(false),
    wasAnnouncedUp(true), // do not announce an "up" service at startup
    isDetached(false)
{
    setMaxConnections();
    theIdleConns = new IdleConnList("ICAP Service", NULL);
}

Adaptation::Icap::ServiceRep::~ServiceRep()
{
    delete theIdleConns;
    Must(!theOptionsFetcher);
    delete theOptions;
}

void
Adaptation::Icap::ServiceRep::finalize()
{
    Adaptation::Service::finalize();

    // use /etc/services or default port if needed
    const bool have_port = cfg().port >= 0;
    if (!have_port) {
        struct servent *serv;
        if (cfg().protocol.caseCmp("icaps") == 0)
            serv = getservbyname("icaps", "tcp");
        else
            serv = getservbyname("icap", "tcp");

        if (serv) {
            writeableCfg().port = htons(serv->s_port);
        } else {
            writeableCfg().port = cfg().protocol.caseCmp("icaps") == 0 ? DEFAULT_ICAPS_PORT : DEFAULT_ICAP_PORT;
        }
    }

    if (cfg().protocol.caseCmp("icaps") == 0)
        writeableCfg().secure.encryptTransport = true;

    if (cfg().secure.encryptTransport) {
        debugs(3, DBG_IMPORTANT, "Initializing service " << cfg().resource << " SSL context");
        sslContext = writeableCfg().secure.createClientContext(true);
    }

    if (!cfg().connectionEncryption.configured())
        writeableCfg().connectionEncryption.defaultTo(cfg().secure.encryptTransport);

    theSessionFailures.configure(TheConfig.oldest_service_failure > 0 ?
                                 TheConfig.oldest_service_failure : -1);
}

void Adaptation::Icap::ServiceRep::noteFailure()
{
    const int failures = theSessionFailures.count(1);
    debugs(93,4, HERE << " failure " << failures << " out of " <<
           TheConfig.service_failure_limit << " allowed in " <<
           TheConfig.oldest_service_failure << "sec " << status());

    if (isSuspended)
        return;

    if (TheConfig.service_failure_limit >= 0 &&
            failures > TheConfig.service_failure_limit)
        suspend("too many failures");

    // TODO: Should bypass setting affect how much Squid tries to talk to
    // the ICAP service that is currently unusable and is likely to remain
    // so for some time? The current code says "no". Perhaps the answer
    // should be configurable.
}

// returns a persistent or brand new connection; negative int on failures
Comm::ConnectionPointer
Adaptation::Icap::ServiceRep::getConnection(bool retriableXact, bool &reused)
{
    Comm::ConnectionPointer connection;

    /* 2011-06-17: rousskov:
     *  There are two things that happen at the same time in pop(). Both are important.
     *    1) Ensure that we can use a pconn for this transaction.
     *    2) Ensure that the number of idle pconns does not grow without bounds.
     *
     * Both happen in the beginning of the transaction. Both are dictated by real-world problems.
     * retriable means you can repeat the request if you suspect the first try failed due to a pconn race.
     * HTTP and ICAP rules prohibit the use of pconns for non-retriable requests.
     *
     * If there are zero idle connections, (2) is irrelevant. (2) is only relevant when there are many
     * idle connections and we should not open more connections without closing some idle ones,
     * or instead of just opening a new connection and leaving idle connections as is.
     * In other words, (2) tells us to close one FD for each new one we open due to retriable.
     */
    if (retriableXact)
        connection = theIdleConns->pop();
    else
        theIdleConns->closeN(1);

    reused = Comm::IsConnOpen(connection);
    ++theBusyConns;
    debugs(93,3, HERE << "got connection: " << connection);
    return connection;
}

// pools connection if it is reusable or closes it
void Adaptation::Icap::ServiceRep::putConnection(const Comm::ConnectionPointer &conn, bool isReusable, bool sendReset, const char *comment)
{
    Must(Comm::IsConnOpen(conn));
    // do not pool an idle connection if we owe connections
    if (isReusable && excessConnections() == 0) {
        debugs(93, 3, HERE << "pushing pconn" << comment);
        commUnsetConnTimeout(conn);
        theIdleConns->push(conn);
    } else {
        debugs(93, 3, HERE << (sendReset ? "RST" : "FIN") << "-closing " <<
               comment);
        // comm_close called from Connection::close will clear timeout
        // TODO: add "bool sendReset = false" to Connection::close()?
        if (sendReset)
            comm_reset_close(conn);
        else
            conn->close();
    }

    Must(theBusyConns > 0);
    --theBusyConns;
    // a connection slot released. Check if there are waiters....
    busyCheckpoint();
}

// a wrapper to avoid exposing theIdleConns
void Adaptation::Icap::ServiceRep::noteConnectionUse(const Comm::ConnectionPointer &conn)
{
    Must(Comm::IsConnOpen(conn));
    fd_table[conn->fd].noteUse(); // pconn re-use, albeit not via PconnPool API
}

void Adaptation::Icap::ServiceRep::noteConnectionFailed(const char *comment)
{
    debugs(93, 3, HERE << "Connection failed: " << comment);
    --theBusyConns;
}

void Adaptation::Icap::ServiceRep::setMaxConnections()
{
    if (cfg().maxConn >= 0)
        theMaxConnections = cfg().maxConn;
    else if (theOptions && theOptions->max_connections >= 0)
        theMaxConnections = theOptions->max_connections;
    else {
        theMaxConnections = -1;
        return;
    }

    if (::Config.workers > 1 )
        theMaxConnections /= ::Config.workers;
}

int Adaptation::Icap::ServiceRep::availableConnections() const
{
    if (theMaxConnections < 0)
        return -1;

    // we are available if we can open or reuse connections
    // in other words, if we will not create debt
    int available = max(0, theMaxConnections - theBusyConns);

    if (!available && !connOverloadReported) {
        debugs(93, DBG_IMPORTANT, "WARNING: ICAP Max-Connections limit " <<
               "exceeded for service " << cfg().uri << ". Open connections now: " <<
               theBusyConns + theIdleConns->count() << ", including " <<
               theIdleConns->count() << " idle persistent connections.");
        connOverloadReported = true;
    }

    if (cfg().onOverload == srvForce)
        return -1;

    return available;
}

// The number of connections which excess the Max-Connections limit
int Adaptation::Icap::ServiceRep::excessConnections() const
{
    if (theMaxConnections < 0)
        return 0;

    // Waiters affect the number of needed connections but a needed
    // connection may still be excessive from Max-Connections p.o.v.
    // so we should not account for waiting transaction needs here.
    const int debt =  theBusyConns + theIdleConns->count() - theMaxConnections;
    if (debt > 0)
        return debt;
    else
        return 0;
}

void Adaptation::Icap::ServiceRep::noteGoneWaiter()
{
    --theAllWaiters;

    // in case the notified transaction did not take the connection slot
    busyCheckpoint();
}

// called when a connection slot may become available
void Adaptation::Icap::ServiceRep::busyCheckpoint()
{
    if (theNotificationWaiters.empty()) // nobody is waiting for a slot
        return;

    int freed = 0;
    int available = availableConnections();

    if (available < 0) {
        // It is possible to have waiters when no limit on connections exist in
        // case of reconfigure or because new Options received.
        // In this case, notify all waiting transactions.
        freed  = theNotificationWaiters.size();
    } else {
        // avoid notifying more waiters than there will be available slots
        const int notifiedWaiters = theAllWaiters - theNotificationWaiters.size();
        freed = available - notifiedWaiters;
    }

    debugs(93,7, HERE << "Available connections: " << available <<
           " freed slots: " << freed <<
           " waiting in queue: " << theNotificationWaiters.size());

    while (freed > 0 && !theNotificationWaiters.empty()) {
        Client i = theNotificationWaiters.front();
        theNotificationWaiters.pop_front();
        ScheduleCallHere(i.callback);
        i.callback = NULL;
        --freed;
    }
}

void Adaptation::Icap::ServiceRep::suspend(const char *reason)
{
    if (isSuspended) {
        debugs(93,4, HERE << "keeping suspended, also for " << reason);
    } else {
        isSuspended = reason;
        debugs(93, DBG_IMPORTANT, "suspending ICAP service for " << reason);
        scheduleUpdate(squid_curtime + TheConfig.service_revival_delay);
        announceStatusChange("suspended", true);
    }
}

bool Adaptation::Icap::ServiceRep::probed() const
{
    return theLastUpdate != 0;
}

bool Adaptation::Icap::ServiceRep::hasOptions() const
{
    return theOptions && theOptions->valid() && theOptions->fresh();
}

bool Adaptation::Icap::ServiceRep::up() const
{
    return !isSuspended && hasOptions();
}

bool Adaptation::Icap::ServiceRep::availableForNew() const
{
    Must(up());
    int available = availableConnections();
    if (available < 0)
        return true;
    else
        return (available - theAllWaiters > 0);
}

bool Adaptation::Icap::ServiceRep::availableForOld() const
{
    Must(up());

    int available = availableConnections();
    return (available != 0); // it is -1 (no limit) or has available slots
}

bool Adaptation::Icap::ServiceRep::wantsUrl(const SBuf &urlPath) const
{
    Must(hasOptions());
    return theOptions->transferKind(urlPath) != Adaptation::Icap::Options::xferIgnore;
}

bool Adaptation::Icap::ServiceRep::wantsPreview(const SBuf &urlPath, size_t &wantedSize) const
{
    Must(hasOptions());

    if (theOptions->preview < 0)
        return false;

    if (theOptions->transferKind(urlPath) != Adaptation::Icap::Options::xferPreview)
        return false;

    wantedSize = theOptions->preview;

    return true;
}

bool Adaptation::Icap::ServiceRep::allows204() const
{
    Must(hasOptions());
    return true; // in the future, we may have ACLs to prevent 204s
}

bool Adaptation::Icap::ServiceRep::allows206() const
{
    Must(hasOptions());
    if (theOptions->allow206)
        return true; // in the future, we may have ACLs to prevent 206s
    return false;
}

static
void ServiceRep_noteTimeToUpdate(void *data)
{
    Adaptation::Icap::ServiceRep *service = static_cast<Adaptation::Icap::ServiceRep*>(data);
    Must(service);
    service->noteTimeToUpdate();
}

void Adaptation::Icap::ServiceRep::noteTimeToUpdate()
{
    if (!detached())
        updateScheduled = false;

    if (detached() || theOptionsFetcher.set()) {
        debugs(93,5, HERE << "ignores options update " << status());
        return;
    }

    debugs(93,5, HERE << "performs a regular options update " << status());
    startGettingOptions();
}

#if 0
static
void Adaptation::Icap::ServiceRep_noteTimeToNotify(void *data)
{
    Adaptation::Icap::ServiceRep *service = static_cast<Adaptation::Icap::ServiceRep*>(data);
    Must(service);
    service->noteTimeToNotify();
}
#endif

void Adaptation::Icap::ServiceRep::noteTimeToNotify()
{
    Must(!notifying);
    notifying = true;
    debugs(93,7, HERE << "notifies " << theClients.size() << " clients " <<
           status());

    // note: we must notify even if we are invalidated

    Pointer us = NULL;

    while (!theClients.empty()) {
        Client i = theClients.back();
        theClients.pop_back();
        ScheduleCallHere(i.callback);
        i.callback = 0;
    }

    notifying = false;
}

void Adaptation::Icap::ServiceRep::callWhenAvailable(AsyncCall::Pointer &cb, bool priority)
{
    debugs(93,8, "ICAPServiceRep::callWhenAvailable");
    Must(cb!=NULL);
    Must(up());
    Must(!theIdleConns->count()); // or we should not be waiting

    Client i;
    i.service = Pointer(this);
    i.callback = cb;
    if (priority)
        theNotificationWaiters.push_front(i);
    else
        theNotificationWaiters.push_back(i);

    busyCheckpoint();
}

void Adaptation::Icap::ServiceRep::callWhenReady(AsyncCall::Pointer &cb)
{
    Must(cb!=NULL);

    debugs(93,5, HERE << "Adaptation::Icap::Service is asked to call " << *cb <<
           " when ready " << status());

    Must(!broken()); // we do not wait for a broken service

    Client i;
    i.service = Pointer(this); // TODO: is this really needed?
    i.callback = cb;
    theClients.push_back(i);

    if (theOptionsFetcher.set() || notifying)
        return; // do nothing, we will be picked up in noteTimeToNotify()

    if (needNewOptions())
        startGettingOptions();
    else
        scheduleNotification();
}

void Adaptation::Icap::ServiceRep::scheduleNotification()
{
    debugs(93,7, HERE << "will notify " << theClients.size() << " clients");
    CallJobHere(93, 5, this, Adaptation::Icap::ServiceRep, noteTimeToNotify);
}

bool Adaptation::Icap::ServiceRep::needNewOptions() const
{
    return !detached() && !up();
}

void Adaptation::Icap::ServiceRep::changeOptions(Adaptation::Icap::Options *newOptions)
{
    debugs(93,8, HERE << "changes options from " << theOptions << " to " <<
           newOptions << ' ' << status());

    delete theOptions;
    theOptions = newOptions;
    theSessionFailures.clear();
    isSuspended = 0;
    theLastUpdate = squid_curtime;

    checkOptions();
    announceStatusChange("down after an options fetch failure", true);
}

void Adaptation::Icap::ServiceRep::checkOptions()
{
    if (theOptions == NULL)
        return;

    if (!theOptions->valid()) {
        debugs(93, DBG_IMPORTANT, "WARNING: Squid got an invalid ICAP OPTIONS response " <<
               "from service " << cfg().uri << "; error: " << theOptions->error);
        return;
    }

    /*
     * Issue a warning if the ICAP server returned methods in the
     * options response that don't match the method from squid.conf.
     */

    if (!theOptions->methods.empty()) {
        bool method_found = false;
        String method_list;
        std::vector <ICAP::Method>::iterator iter = theOptions->methods.begin();

        while (iter != theOptions->methods.end()) {

            if (*iter == cfg().method) {
                method_found = true;
                break;
            }

            method_list.append(ICAP::methodStr(*iter));
            method_list.append(" ", 1);
            ++iter;
        }

        if (!method_found) {
            debugs(93, DBG_IMPORTANT, "WARNING: Squid is configured to use ICAP method " <<
                   cfg().methodStr() <<
                   " for service " << cfg().uri <<
                   " but OPTIONS response declares the methods are " << method_list);
        }
    }

    /*
     *  Check the ICAP server's date header for clock skew
     */
    const int skew = (int)(theOptions->timestamp() - squid_curtime);
    if (abs(skew) > theOptions->ttl()) {
        // TODO: If skew is negative, the option will be considered down
        // because of stale options. We should probably change this.
        debugs(93, DBG_IMPORTANT, "ICAP service's clock is skewed by " << skew <<
               " seconds: " << cfg().uri);
    }
}

void Adaptation::Icap::ServiceRep::announceStatusChange(const char *downPhrase, bool important) const
{
    if (wasAnnouncedUp == up()) // no significant changes to announce
        return;

    const char *what = cfg().bypass ? "optional" : "essential";
    const char *state = wasAnnouncedUp ? downPhrase : "up";
    const int level = important ? 1 :2;
    debugs(93,level, what << " ICAP service is " << state << ": " <<
           cfg().uri << ' ' << status());

    wasAnnouncedUp = !wasAnnouncedUp;
}

// we are receiving ICAP OPTIONS response headers here or NULL on failures
void Adaptation::Icap::ServiceRep::noteAdaptationAnswer(const Answer &answer)
{
    Must(initiated(theOptionsFetcher));
    clearAdaptation(theOptionsFetcher);

    if (answer.kind == Answer::akError) {
        debugs(93,3, HERE << "failed to fetch options " << status());
        handleNewOptions(0);
        return;
    }

    Must(answer.kind == Answer::akForward); // no akBlock for OPTIONS requests
    const HttpMsg *msg = answer.message.getRaw();
    Must(msg);

    debugs(93,5, HERE << "is interpreting new options " << status());

    Adaptation::Icap::Options *newOptions = NULL;
    if (const HttpReply *r = dynamic_cast<const HttpReply*>(msg)) {
        newOptions = new Adaptation::Icap::Options;
        newOptions->configure(r);
    } else {
        debugs(93, DBG_IMPORTANT, "ICAP service got wrong options message " << status());
    }

    handleNewOptions(newOptions);
}

// we (a) must keep trying to get OPTIONS and (b) are RefCounted so we
// must keep our job alive (XXX: until nobody needs us)
void Adaptation::Icap::ServiceRep::callException(const std::exception &e)
{
    clearAdaptation(theOptionsFetcher);
    debugs(93,2, "ICAP probably failed to fetch options (" << e.what() <<
           ")" << status());
    handleNewOptions(0);
}

void Adaptation::Icap::ServiceRep::handleNewOptions(Adaptation::Icap::Options *newOptions)
{
    // new options may be NULL
    changeOptions(newOptions);

    debugs(93,3, HERE << "got new options and is now " << status());

    scheduleUpdate(optionsFetchTime());

    // XXX: this whole feature bases on the false assumption a service only has one IP
    setMaxConnections();
    const int excess = excessConnections();
    // if we owe connections and have idle pconns, close the latter
    if (excess && theIdleConns->count() > 0) {
        const int n = min(excess, theIdleConns->count());
        debugs(93,5, HERE << "closing " << n << " pconns to relief debt");
        theIdleConns->closeN(n);
    }

    scheduleNotification();
}

void Adaptation::Icap::ServiceRep::startGettingOptions()
{
    Must(!theOptionsFetcher);
    debugs(93,6, HERE << "will get new options " << status());

    // XXX: "this" here is "self"; works until refcounting API changes
    theOptionsFetcher = initiateAdaptation(
                            new Adaptation::Icap::OptXactLauncher(this));
    // TODO: timeout in case Adaptation::Icap::OptXact never calls us back?
    // Such a timeout should probably be a generic AsyncStart feature.
}

void Adaptation::Icap::ServiceRep::scheduleUpdate(time_t when)
{
    if (updateScheduled) {
        debugs(93,7, HERE << "reschedules update");
        // XXX: check whether the event is there because AR saw
        // an unreproducible eventDelete assertion on 2007/06/18
        if (eventFind(&ServiceRep_noteTimeToUpdate, this))
            eventDelete(&ServiceRep_noteTimeToUpdate, this);
        else
            debugs(93, DBG_IMPORTANT, "XXX: ICAP service lost an update event.");
        updateScheduled = false;
    }

    debugs(93,7, HERE << "raw OPTIONS fetch at " << when << " or in " <<
           (when - squid_curtime) << " sec");
    debugs(93,9, HERE << "last fetched at " << theLastUpdate << " or " <<
           (squid_curtime - theLastUpdate) << " sec ago");

    /* adjust update time to prevent too-frequent updates */

    if (when < squid_curtime)
        when = squid_curtime;

    // XXX: move hard-coded constants from here to Adaptation::Icap::TheConfig
    const int minUpdateGap = 30; // seconds
    if (when < theLastUpdate + minUpdateGap)
        when = theLastUpdate + minUpdateGap;

    const int delay = when - squid_curtime;
    debugs(93,5, HERE << "will fetch OPTIONS in " << delay << " sec");

    eventAdd("Adaptation::Icap::ServiceRep::noteTimeToUpdate",
             &ServiceRep_noteTimeToUpdate, this, delay, 0, true);
    updateScheduled = true;
}

// returns absolute time when OPTIONS should be fetched
time_t
Adaptation::Icap::ServiceRep::optionsFetchTime() const
{
    if (theOptions && theOptions->valid()) {
        const time_t expire = theOptions->expire();
        debugs(93,7, HERE << "options expire on " << expire << " >= " << squid_curtime);

        // conservative estimate of how long the OPTIONS transaction will take
        // XXX: move hard-coded constants from here to Adaptation::Icap::TheConfig
        const int expectedWait = 20; // seconds

        // Unknown or invalid (too small) expiration times should not happen.
        // Adaptation::Icap::Options should use the default TTL, and ICAP servers should not
        // send invalid TTLs, but bugs and attacks happen.
        if (expire < expectedWait)
            return squid_curtime;
        else
            return expire - expectedWait; // before the current options expire
    }

    // use revival delay as "expiration" time for a service w/o valid options
    return squid_curtime + TheConfig.service_revival_delay;
}

Adaptation::Initiate *
Adaptation::Icap::ServiceRep::makeXactLauncher(HttpMsg *virgin,
        HttpRequest *cause, AccessLogEntry::Pointer &alp)
{
    return new Adaptation::Icap::ModXactLauncher(virgin, cause, alp, this);
}

// returns a temporary string depicting service status, for debugging
const char *Adaptation::Icap::ServiceRep::status() const
{
    static MemBuf buf;

    buf.reset();
    buf.append("[", 1);

    if (up())
        buf.append("up", 2);
    else {
        buf.append("down", 4);
        if (isSuspended)
            buf.append(",susp", 5);

        if (!theOptions)
            buf.append(",!opt", 5);
        else if (!theOptions->valid())
            buf.append(",!valid", 7);
        else if (!theOptions->fresh())
            buf.append(",stale", 6);
    }

    if (detached())
        buf.append(",detached", 9);

    if (theOptionsFetcher.set())
        buf.append(",fetch", 6);

    if (notifying)
        buf.append(",notif", 6);

    if (const int failures = theSessionFailures.remembered())
        buf.appendf(",fail%d", failures);

    buf.append("]", 1);
    buf.terminate();

    return buf.content();
}

void Adaptation::Icap::ServiceRep::detach()
{
    debugs(93,3, HERE << "detaching ICAP service: " << cfg().uri <<
           ' ' << status());
    isDetached = true;
}

bool Adaptation::Icap::ServiceRep::detached() const
{
    return isDetached;
}

Adaptation::Icap::ConnWaiterDialer::ConnWaiterDialer(const CbcPointer<Adaptation::Icap::ModXact> &xact,
        Adaptation::Icap::ConnWaiterDialer::Parent::Method aHandler):
    Parent(xact, aHandler)
{
    theService = &xact->service();
    theService->noteNewWaiter();
}

Adaptation::Icap::ConnWaiterDialer::ConnWaiterDialer(const Adaptation::Icap::ConnWaiterDialer &aConnWaiter): Parent(aConnWaiter)
{
    theService = aConnWaiter.theService;
    theService->noteNewWaiter();
}

Adaptation::Icap::ConnWaiterDialer::~ConnWaiterDialer()
{
    theService->noteGoneWaiter();
}

