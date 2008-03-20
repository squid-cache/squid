
/*
 * $Id$
 *
 */

#ifndef SQUID_ECAP_SERVICEREP_H
#define SQUID_ECAP_SERVICEREP_H

#include "cbdata.h"
#include "event.h"
#include "ICAP/ICAPInitiator.h"
#include "ICAP/ICAPElements.h"

#if USE_ECAP_AS_ICAP_HACK
#define EcapServiceRep ICAPServiceRep
#endif

class ICAPOptions;
class ICAPOptXact;

class EcapServiceRep : public RefCountable
{

public:
    typedef RefCount<EcapServiceRep> Pointer;

public:
    EcapServiceRep();
    virtual ~EcapServiceRep();

    bool configure(Pointer &aSelf); // needs self pointer for ICAPOptXact
    void invalidate(); // call when the service is no longer needed or valid

    const char *methodStr() const;
    const char *vectPointStr() const;

    bool probed() const; // see comments above
    bool broken() const; // see comments above
    bool up() const; // see comments above

    typedef void Callback(void *data, Pointer &service);
    void callWhenReady(Callback *cb, void *data);

    // the methods below can only be called on an up() service
    bool wantsUrl(const String &urlPath) const;
    bool wantsPreview(const String &urlPath, size_t &wantedSize) const;
    bool allows204() const;

    void noteFailure(); // called by transactions to report service failure

public:
    String key;
    ICAP::Method method;
    ICAP::VectPoint point;
    String uri;    // service URI

    // URI components
    String host;
    int port;
    String resource;

    // XXX: use it when selecting a service and handling ICAP errors!
    bool bypass;

public: // treat these as private, they are for callbacks only
    void noteTimeToUpdate();
    void noteTimeToNotify();
    void noteGenerateOptions();

private:
    // stores Prepare() callback info

    struct Client
    {
        Pointer service; // one for each client to preserve service
        Callback *callback;
        void *data;
    };

    typedef Vector<Client> Clients;
    Clients theClients; // all clients waiting for a call back

    ICAPOptions *theOptions;
    EVH *theOptionsFetcher; // pending ICAP OPTIONS transaction
    time_t theLastUpdate; // time the options were last updated

    static const int TheSessionFailureLimit;
    int theSessionFailures;
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
    void handleNewOptions(ICAPOptions *newOptions);
    void changeOptions(ICAPOptions *newOptions);
    void checkOptions();

    void announceStatusChange(const char *downPhrase, bool important) const;

    const char *status() const;

    Pointer self;
    mutable bool wasAnnouncedUp; // prevent sequential same-state announcements
    CBDATA_CLASS2(EcapServiceRep);
};

#endif /* SQUID_ECAP_SERVICEREP_H */
