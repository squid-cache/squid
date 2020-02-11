/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ICAPSERVICEREP_H
#define SQUID_ICAPSERVICEREP_H

#include "adaptation/forward.h"
#include "adaptation/icap/Elements.h"
#include "adaptation/Initiator.h"
#include "adaptation/Service.h"
#include "base/AsyncJobCalls.h"
#include "cbdata.h"
#include "comm.h"
#include "FadingCounter.h"
#include "pconn.h"
#include <deque>

namespace Adaptation
{
namespace Icap
{

class Options;
class OptXact;

/* The ICAP service representative maintains information about a single ICAP
   service that Squid communicates with. The representative initiates OPTIONS
   requests to the service to keep cached options fresh. One ICAP server may
   host many ICAP services. */

/*
 * A service with a fresh cached OPTIONS response and without many failures
 * is an "up" service. All other services are "down". A service is "probed"
 * if we tried to get an OPTIONS response from it and succeeded or failed.
 * A probed down service is called "broken".
 *
 * The number of failures required to bring an up service down is determined
 * by icap_service_failure_limit in squid.conf.
 *
 * As a bootstrapping mechanism, ICAP transactions wait for an unprobed
 * service to get a fresh OPTIONS response (see the callWhenReady method).
 * The waiting callback is called when the OPTIONS transaction completes,
 * even if the service is now broken.
 *
 * We do not initiate ICAP transactions with a broken service, but will
 * eventually retry to fetch its options in hope to bring the service up.
 *
 * A service that should no longer be used after Squid reconfiguration is
 * treated as if it does not have a fresh cached OPTIONS response. We do
 * not try to fetch fresh options for such a service. It should be
 * auto-destroyed by refcounting when no longer used.
 */

class ServiceRep : public RefCountable, public Adaptation::Service,
    public Adaptation::Initiator
{
    CBDATA_CLASS(ServiceRep);

public:
    typedef RefCount<ServiceRep> Pointer;

public:
    explicit ServiceRep(const ServiceConfigPointer &aConfig);
    virtual ~ServiceRep();

    virtual void finalize();

    virtual bool probed() const; // see comments above
    virtual bool up() const; // see comments above
    bool availableForNew() const; ///< a new transaction may start communicating with the service
    bool availableForOld() const; ///< a transaction notified about connection slot availability may start communicating with the service

    virtual Initiate *makeXactLauncher(HttpMsg *virginHeader, HttpRequest *virginCause, AccessLogEntry::Pointer &alp);

    void callWhenAvailable(AsyncCall::Pointer &cb, bool priority = false);
    void callWhenReady(AsyncCall::Pointer &cb);

    // the methods below can only be called on an up() service
    bool wantsUrl(const SBuf &urlPath) const;
    bool wantsPreview(const SBuf &urlPath, size_t &wantedSize) const;
    bool allows204() const;
    bool allows206() const;
    Comm::ConnectionPointer getConnection(bool isRetriable, bool &isReused);
    void putConnection(const Comm::ConnectionPointer &conn, bool isReusable, bool sendReset, const char *comment);
    void noteConnectionUse(const Comm::ConnectionPointer &conn);
    void noteConnectionFailed(const char *comment);

    void noteFailure(); // called by transactions to report service failure

    void noteNewWaiter() {theAllWaiters++;} ///< New xaction waiting for service to be up or available
    void noteGoneWaiter(); ///< An xaction is not waiting any more for service to be available
    bool existWaiters() const {return (theAllWaiters > 0);} ///< if there are xactions waiting for the service to be available

    //AsyncJob virtual methods
    virtual bool doneAll() const { return Adaptation::Initiator::doneAll() && false;}
    virtual void callException(const std::exception &e);

    virtual void detach();
    virtual bool detached() const;

public: // treat these as private, they are for callbacks only
    void noteTimeToUpdate();
    void noteTimeToNotify();

    // receive either an ICAP OPTIONS response header or an abort message
    virtual void noteAdaptationAnswer(const Answer &answer);

    Security::ContextPointer sslContext;
    Security::SessionStatePointer sslSession;

private:
    // stores Prepare() callback info

    struct Client {
        Pointer service; // one for each client to preserve service
        AsyncCall::Pointer callback;
    };

    typedef std::vector<Client> Clients;
    // TODO: rename to theUpWaiters
    Clients theClients; // all clients waiting for a call back

    Options *theOptions;
    CbcPointer<Adaptation::Initiate> theOptionsFetcher; // pending ICAP OPTIONS transaction
    time_t theLastUpdate; // time the options were last updated

    /// FIFO queue of xactions waiting for a connection slot and not yet notified
    /// about it; xaction is removed when notification is scheduled
    std::deque<Client> theNotificationWaiters;
    int theBusyConns;   ///< number of connections given to active transactions
    /// number of xactions waiting for a connection slot (notified and not)
    /// the number is decreased after the xaction receives notification
    int theAllWaiters;
    int theMaxConnections; ///< the maximum allowed connections to the service
    // TODO: use a better type like the FadingCounter for connOverloadReported
    mutable bool connOverloadReported; ///< whether we reported exceeding theMaxConnections
    IdleConnList *theIdleConns; ///< idle persistent connection pool

    FadingCounter theSessionFailures;
    const char *isSuspended; // also stores suspension reason for debugging

    bool notifying; // may be true in any state except for the initial
    bool updateScheduled; // time-based options update has been scheduled

private:
    ICAP::Method parseMethod(const char *) const;
    ICAP::VectPoint parseVectPoint(const char *) const;

    void suspend(const char *reason);

    bool hasOptions() const;
    bool needNewOptions() const;
    time_t optionsFetchTime() const;

    void scheduleUpdate(time_t when);
    void scheduleNotification();

    void startGettingOptions();
    void handleNewOptions(Options *newOptions);
    void changeOptions(Options *newOptions);
    void checkOptions();

    void announceStatusChange(const char *downPhrase, bool important) const;

    /// Set the maximum allowed connections for the service
    void setMaxConnections();
    /// The number of connections which excess the Max-Connections limit
    int excessConnections() const;
    /**
     * The available connections slots to the ICAP server
     \return the available slots, or -1 if there is no limit on allowed connections
     */
    int availableConnections() const;
    /**
     * If there are xactions waiting for the service to be available, notify
     * as many xactions as the available connections slots.
     */
    void busyCheckpoint();

    const char *status() const;

    mutable bool wasAnnouncedUp; // prevent sequential same-state announcements
    bool isDetached;
};

class ModXact;
/// Custom dialer to call Service::noteNewWaiter and noteGoneWaiter
/// to maintain Service idea of waiting and being-notified transactions.
class ConnWaiterDialer: public NullaryMemFunT<ModXact>
{
public:
    typedef NullaryMemFunT<ModXact> Parent;
    ServiceRep::Pointer theService;
    ConnWaiterDialer(const CbcPointer<Adaptation::Icap::ModXact> &xact, Adaptation::Icap::ConnWaiterDialer::Parent::Method aHandler);
    ConnWaiterDialer(const Adaptation::Icap::ConnWaiterDialer &aConnWaiter);
    ~ConnWaiterDialer();
};

} // namespace Icap
} // namespace Adaptation

#endif /* SQUID_ICAPSERVICEREP_H */

