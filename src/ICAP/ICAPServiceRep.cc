/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "TextException.h"
#include "HttpReply.h"
#include "ICAPServiceRep.h"
#include "ICAPOptions.h"
#include "ICAPOptXact.h"
#include "ConfigParser.h"
#include "ICAPConfig.h"
#include "ICAPModXact.h"
#include "SquidTime.h"

CBDATA_CLASS_INIT(ICAPServiceRep);

ICAPServiceRep::ICAPServiceRep(const Adaptation::ServiceConfig &cfg):
        AsyncJob("ICAPServiceRep"), Adaptation::Service(cfg),
        theOptions(NULL), theOptionsFetcher(0), theLastUpdate(0),
        theSessionFailures(0), isSuspended(0), notifying(false),
        updateScheduled(false), self(NULL),
        wasAnnouncedUp(true) // do not announce an "up" service at startup
{}

ICAPServiceRep::~ICAPServiceRep()
{
    Must(!theOptionsFetcher);
    changeOptions(0);
}

void
ICAPServiceRep::setSelf(Pointer &aSelf)
{
    assert(!self && aSelf != NULL);
    self = aSelf;
}

void
ICAPServiceRep::finalize()
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

void ICAPServiceRep::invalidate()
{
    assert(self != NULL);
    Pointer savedSelf = self; // to prevent destruction when we nullify self
    self = NULL;

    announceStatusChange("invalidated by reconfigure", false);

    savedSelf = NULL; // may destroy us and, hence, invalidate cbdata(this)
    // TODO: it would be nice to invalidate cbdata(this) when not destroyed
}

void ICAPServiceRep::noteFailure()
{
    ++theSessionFailures;
    debugs(93,4, theSessionFailures << " ICAPService failures, out of " <<
           TheICAPConfig.service_failure_limit << " allowed " << status());

    if (isSuspended)
        return;

    if (TheICAPConfig.service_failure_limit >= 0 &&
            theSessionFailures > TheICAPConfig.service_failure_limit)
        suspend("too many failures");

    // TODO: Should bypass setting affect how much Squid tries to talk to
    // the ICAP service that is currently unusable and is likely to remain
    // so for some time? The current code says "no". Perhaps the answer
    // should be configurable.
}

void ICAPServiceRep::suspend(const char *reason)
{
    if (isSuspended) {
        debugs(93,4, "keeping ICAPService suspended, also for " << reason);
    } else {
        isSuspended = reason;
        debugs(93,1, "suspending ICAPService for " << reason);
        scheduleUpdate(squid_curtime + TheICAPConfig.service_revival_delay);
        announceStatusChange("suspended", true);
    }
}

bool ICAPServiceRep::probed() const
{
    return theLastUpdate != 0;
}

bool ICAPServiceRep::hasOptions() const
{
    return theOptions && theOptions->valid() && theOptions->fresh();
}

bool ICAPServiceRep::up() const
{
    return self != NULL && !isSuspended && hasOptions();
}

bool ICAPServiceRep::wantsUrl(const String &urlPath) const
{
    Must(hasOptions());
    return theOptions->transferKind(urlPath) != ICAPOptions::xferIgnore;
}

bool ICAPServiceRep::wantsPreview(const String &urlPath, size_t &wantedSize) const
{
    Must(hasOptions());

    if (theOptions->preview < 0)
        return false;

    if (theOptions->transferKind(urlPath) != ICAPOptions::xferPreview)
        return false;

    wantedSize = theOptions->preview;

    return true;
}

bool ICAPServiceRep::allows204() const
{
    Must(hasOptions());
    return true; // in the future, we may have ACLs to prevent 204s
}


static
void ICAPServiceRep_noteTimeToUpdate(void *data)
{
    ICAPServiceRep *service = static_cast<ICAPServiceRep*>(data);
    Must(service);
    service->noteTimeToUpdate();
}

void ICAPServiceRep::noteTimeToUpdate()
{
    if (self != NULL)
        updateScheduled = false;

    if (!self || theOptionsFetcher) {
        debugs(93,5, "ICAPService ignores options update " << status());
        return;
    }

    debugs(93,5, "ICAPService performs a regular options update " << status());
    startGettingOptions();
}

#if 0
static
void ICAPServiceRep_noteTimeToNotify(void *data)
{
    ICAPServiceRep *service = static_cast<ICAPServiceRep*>(data);
    Must(service);
    service->noteTimeToNotify();
}
#endif

void ICAPServiceRep::noteTimeToNotify()
{
    Must(!notifying);
    notifying = true;
    debugs(93,7, "ICAPService notifies " << theClients.size() << " clients " <<
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

void ICAPServiceRep::callWhenReady(AsyncCall::Pointer &cb)
{
    Must(cb!=NULL);

    debugs(93,5, HERE << "ICAPService is asked to call " << *cb <<
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

void ICAPServiceRep::scheduleNotification()
{
    debugs(93,7, "ICAPService will notify " << theClients.size() << " clients");
    CallJobHere(93, 5, this, ICAPServiceRep::noteTimeToNotify);
}

bool ICAPServiceRep::needNewOptions() const
{
    return self != NULL && !up();
}

void ICAPServiceRep::changeOptions(ICAPOptions *newOptions)
{
    debugs(93,8, "ICAPService changes options from " << theOptions << " to " <<
           newOptions << ' ' << status());

    delete theOptions;
    theOptions = newOptions;
    theSessionFailures = 0;
    isSuspended = 0;
    theLastUpdate = squid_curtime;

    checkOptions();
    announceStatusChange("down after an options fetch failure", true);
}

void ICAPServiceRep::checkOptions()
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
                   " for service " << cfg().uri.buf() <<
                   " but OPTIONS response declares the methods are " << method_list.buf());
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
               " seconds: " << cfg().uri.buf());
    }
}

void ICAPServiceRep::announceStatusChange(const char *downPhrase, bool important) const
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
void ICAPServiceRep::noteAdaptationAnswer(HttpMsg *msg)
{
    Must(theOptionsFetcher);
    clearAdaptation(theOptionsFetcher);

    Must(msg);

    debugs(93,5, "ICAPService is interpreting new options " << status());

    ICAPOptions *newOptions = NULL;
    if (HttpReply *r = dynamic_cast<HttpReply*>(msg)) {
        newOptions = new ICAPOptions;
        newOptions->configure(r);
    } else {
        debugs(93,1, "ICAPService got wrong options message " << status());
    }

    handleNewOptions(newOptions);
}

void ICAPServiceRep::noteAdaptationQueryAbort(bool)
{
    Must(theOptionsFetcher);
    clearAdaptation(theOptionsFetcher);

    debugs(93,3, "ICAPService failed to fetch options " << status());
    handleNewOptions(0);
}

void ICAPServiceRep::handleNewOptions(ICAPOptions *newOptions)
{
    // new options may be NULL
    changeOptions(newOptions);

    debugs(93,3, "ICAPService got new options and is now " << status());

    scheduleUpdate(optionsFetchTime());
    scheduleNotification();
}

void ICAPServiceRep::startGettingOptions()
{
    Must(!theOptionsFetcher);
    debugs(93,6, "ICAPService will get new options " << status());

    // XXX: second "this" is "self"; this works but may stop if API changes
    theOptionsFetcher = initiateAdaptation(new ICAPOptXactLauncher(this, this));
    Must(theOptionsFetcher);
    // TODO: timeout in case ICAPOptXact never calls us back?
    // Such a timeout should probably be a generic AsyncStart feature.
}

void ICAPServiceRep::scheduleUpdate(time_t when)
{
    if (updateScheduled) {
        debugs(93,7, "ICAPService reschedules update");
        // XXX: check whether the event is there because AR saw
        // an unreproducible eventDelete assertion on 2007/06/18
        if (eventFind(&ICAPServiceRep_noteTimeToUpdate, this))
            eventDelete(&ICAPServiceRep_noteTimeToUpdate, this);
        else
            debugs(93,1, "XXX: ICAPService lost an update event.");
        updateScheduled = false;
    }

    debugs(93,7, HERE << "raw OPTIONS fetch at " << when << " or in " <<
           (when - squid_curtime) << " sec");
    debugs(93,9, HERE << "last fetched at " << theLastUpdate << " or " <<
           (squid_curtime - theLastUpdate) << " sec ago");

    /* adjust update time to prevent too-frequent updates */

    if (when < squid_curtime)
        when = squid_curtime;

    // XXX: move hard-coded constants from here to TheICAPConfig
    const int minUpdateGap = 30; // seconds
    if (when < theLastUpdate + minUpdateGap)
        when = theLastUpdate + minUpdateGap;

    const int delay = when - squid_curtime;
    debugs(93,5, "ICAPService will fetch OPTIONS in " << delay << " sec");

    eventAdd("ICAPServiceRep::noteTimeToUpdate",
             &ICAPServiceRep_noteTimeToUpdate, this, delay, 0, true);
    updateScheduled = true;
}

// returns absolute time when OPTIONS should be fetched
time_t
ICAPServiceRep::optionsFetchTime() const
{
    if (theOptions && theOptions->valid()) {
        const time_t expire = theOptions->expire();
        debugs(93,7, "ICAPService options expire on " << expire << " >= " << squid_curtime);

        // conservative estimate of how long the OPTIONS transaction will take
        // XXX: move hard-coded constants from here to TheICAPConfig
        const int expectedWait = 20; // seconds

        // Unknown or invalid (too small) expiration times should not happen.
        // ICAPOptions should use the default TTL, and ICAP servers should not
        // send invalid TTLs, but bugs and attacks happen.
        if (expire < expectedWait)
            return squid_curtime;
        else
            return expire - expectedWait; // before the current options expire
    }

    // use revival delay as "expiration" time for a service w/o valid options
    return squid_curtime + TheICAPConfig.service_revival_delay;
}

Adaptation::Initiate *
ICAPServiceRep::makeXactLauncher(Adaptation::Initiator *initiator,
                                 HttpMsg *virgin, HttpRequest *cause)
{
    return new ICAPModXactLauncher(initiator, virgin, cause, this);
}

// returns a temporary string depicting service status, for debugging
const char *ICAPServiceRep::status() const
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
