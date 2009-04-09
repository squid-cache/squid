/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "TextException.h"
#include "HttpReply.h"
#include "adaptation/icap/ServiceRep.h"
#include "adaptation/icap/Options.h"
#include "adaptation/icap/OptXact.h"
#include "ConfigParser.h"
#include "adaptation/icap/Config.h"
#include "adaptation/icap/ModXact.h"
#include "SquidTime.h"

CBDATA_NAMESPACED_CLASS_INIT(Adaptation::Icap, ServiceRep);

Adaptation::Icap::ServiceRep::ServiceRep(const Adaptation::ServiceConfig &cfg):
        AsyncJob("Adaptation::Icap::ServiceRep"), Adaptation::Service(cfg),
        theOptions(NULL), theOptionsFetcher(0), theLastUpdate(0),
        theSessionFailures(0), isSuspended(0), notifying(false),
        updateScheduled(false), self(NULL),
        wasAnnouncedUp(true) // do not announce an "up" service at startup
{}

Adaptation::Icap::ServiceRep::~ServiceRep()
{
    Must(!theOptionsFetcher);
    changeOptions(0);
}

void
Adaptation::Icap::ServiceRep::setSelf(Pointer &aSelf)
{
    assert(!self && aSelf != NULL);
    self = aSelf;
}

void
Adaptation::Icap::ServiceRep::finalize()
{
    Adaptation::Service::finalize();
    assert(self != NULL);

    // use /etc/services or default port if needed
    const bool have_port = cfg().port >= 0;
    if (!have_port) {
        struct servent *serv = getservbyname("icap", "tcp");

        if (serv) {
            writeableCfg().port = htons(serv->s_port);
        } else {
            writeableCfg().port = 1344;
        }
    }
}

void Adaptation::Icap::ServiceRep::invalidate()
{
    assert(self != NULL);
    Pointer savedSelf = self; // to prevent destruction when we nullify self
    self = NULL;

    announceStatusChange("invalidated by reconfigure", false);

    savedSelf = NULL; // may destroy us and, hence, invalidate cbdata(this)
    // TODO: it would be nice to invalidate cbdata(this) when not destroyed
}

void Adaptation::Icap::ServiceRep::noteFailure()
{
    ++theSessionFailures;
    debugs(93,4, HERE << " failure " << theSessionFailures << " out of " <<
           TheConfig.service_failure_limit << " allowed " << status());

    if (isSuspended)
        return;

    if (TheConfig.service_failure_limit >= 0 &&
            theSessionFailures > TheConfig.service_failure_limit)
        suspend("too many failures");

    // TODO: Should bypass setting affect how much Squid tries to talk to
    // the ICAP service that is currently unusable and is likely to remain
    // so for some time? The current code says "no". Perhaps the answer
    // should be configurable.
}

void Adaptation::Icap::ServiceRep::suspend(const char *reason)
{
    if (isSuspended) {
        debugs(93,4, HERE << "keeping suspended, also for " << reason);
    } else {
        isSuspended = reason;
        debugs(93,1, "suspending ICAP service for " << reason);
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
    return self != NULL && !isSuspended && hasOptions();
}

bool Adaptation::Icap::ServiceRep::wantsUrl(const String &urlPath) const
{
    Must(hasOptions());
    return theOptions->transferKind(urlPath) != Adaptation::Icap::Options::xferIgnore;
}

bool Adaptation::Icap::ServiceRep::wantsPreview(const String &urlPath, size_t &wantedSize) const
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


static
void ServiceRep_noteTimeToUpdate(void *data)
{
    Adaptation::Icap::ServiceRep *service = static_cast<Adaptation::Icap::ServiceRep*>(data);
    Must(service);
    service->noteTimeToUpdate();
}

void Adaptation::Icap::ServiceRep::noteTimeToUpdate()
{
    if (self != NULL)
        updateScheduled = false;

    if (!self || theOptionsFetcher) {
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
        Client i = theClients.pop_back();
        ScheduleCallHere(i.callback);
        i.callback = 0;
    }

    notifying = false;
}

void Adaptation::Icap::ServiceRep::callWhenReady(AsyncCall::Pointer &cb)
{
    Must(cb!=NULL);

    debugs(93,5, HERE << "Adaptation::Icap::Service is asked to call " << *cb <<
           " when ready " << status());

    Must(self != NULL);
    Must(!broken()); // we do not wait for a broken service

    Client i;
    i.service = self; // TODO: is this really needed?
    i.callback = cb;
    theClients.push_back(i);

    if (theOptionsFetcher || notifying)
        return; // do nothing, we will be picked up in noteTimeToNotify()

    if (needNewOptions())
        startGettingOptions();
    else
        scheduleNotification();
}

void Adaptation::Icap::ServiceRep::scheduleNotification()
{
    debugs(93,7, HERE << "will notify " << theClients.size() << " clients");
    CallJobHere(93, 5, this, Adaptation::Icap::ServiceRep::noteTimeToNotify);
}

bool Adaptation::Icap::ServiceRep::needNewOptions() const
{
    return self != NULL && !up();
}

void Adaptation::Icap::ServiceRep::changeOptions(Adaptation::Icap::Options *newOptions)
{
    debugs(93,8, HERE << "changes options from " << theOptions << " to " <<
           newOptions << ' ' << status());

    delete theOptions;
    theOptions = newOptions;
    theSessionFailures = 0;
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
        debugs(93,1, "WARNING: Squid got an invalid ICAP OPTIONS response " <<
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
        Vector <ICAP::Method>::iterator iter = theOptions->methods.begin();

        while (iter != theOptions->methods.end()) {

            if (*iter == cfg().method) {
                method_found = true;
                break;
            }

            method_list.append(ICAP::methodStr(*iter));
            method_list.append(" ", 1);
            iter++;
        }

        if (!method_found) {
            debugs(93,1, "WARNING: Squid is configured to use ICAP method " <<
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
        debugs(93, 1, "ICAP service's clock is skewed by " << skew <<
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
void Adaptation::Icap::ServiceRep::noteAdaptationAnswer(HttpMsg *msg)
{
    Must(theOptionsFetcher);
    clearAdaptation(theOptionsFetcher);

    Must(msg);

    debugs(93,5, HERE << "is interpreting new options " << status());

    Adaptation::Icap::Options *newOptions = NULL;
    if (HttpReply *r = dynamic_cast<HttpReply*>(msg)) {
        newOptions = new Adaptation::Icap::Options;
        newOptions->configure(r);
    } else {
        debugs(93,1, "ICAP service got wrong options message " << status());
    }

    handleNewOptions(newOptions);
}

void Adaptation::Icap::ServiceRep::noteAdaptationQueryAbort(bool)
{
    Must(theOptionsFetcher);
    clearAdaptation(theOptionsFetcher);

    debugs(93,3, HERE << "failed to fetch options " << status());
    handleNewOptions(0);
}

void Adaptation::Icap::ServiceRep::handleNewOptions(Adaptation::Icap::Options *newOptions)
{
    // new options may be NULL
    changeOptions(newOptions);

    debugs(93,3, HERE << "got new options and is now " << status());

    scheduleUpdate(optionsFetchTime());
    scheduleNotification();
}

void Adaptation::Icap::ServiceRep::startGettingOptions()
{
    Must(!theOptionsFetcher);
    debugs(93,6, HERE << "will get new options " << status());

    // XXX: second "this" is "self"; this works but may stop if API changes
    theOptionsFetcher = initiateAdaptation(new Adaptation::Icap::OptXactLauncher(this, this));
    Must(theOptionsFetcher);
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
            debugs(93,1, "XXX: ICAP service lost an update event.");
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
Adaptation::Icap::ServiceRep::makeXactLauncher(Adaptation::Initiator *initiator,
        HttpMsg *virgin, HttpRequest *cause)
{
    return new Adaptation::Icap::ModXactLauncher(initiator, virgin, cause, this);
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
        if (!self)
            buf.append(",gone", 5);
        if (isSuspended)
            buf.append(",susp", 5);

        if (!theOptions)
            buf.append(",!opt", 5);
        else
            if (!theOptions->valid())
                buf.append(",!valid", 7);
            else
                if (!theOptions->fresh())
                    buf.append(",stale", 6);
    }

    if (theOptionsFetcher)
        buf.append(",fetch", 6);

    if (notifying)
        buf.append(",notif", 6);

    if (theSessionFailures > 0)
        buf.Printf(",fail%d", theSessionFailures);

    buf.append("]", 1);
    buf.terminate();

    return buf.content();
}
