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
#include "SquidTime.h"

CBDATA_CLASS_INIT(ICAPServiceRep);

ICAPServiceRep::ICAPServiceRep(): method(ICAP::methodNone),
        point(ICAP::pointNone), port(-1), bypass(false),
        theOptions(NULL), theLastUpdate(0),
        theSessionFailures(0), isSuspended(0),
        waiting(false), notifying(false),
        updateScheduled(false), self(NULL),
        wasAnnouncedUp(true) // do not announce an "up" service at startup
{}

ICAPServiceRep::~ICAPServiceRep()
{
    Must(!waiting);
    changeOptions(0);
}

const char *
ICAPServiceRep::methodStr() const
{
    return ICAP::methodStr(method);
}

ICAP::Method
ICAPServiceRep::parseMethod(const char *str) const
{
    if (!strncasecmp(str, "REQMOD", 6))
        return ICAP::methodReqmod;

    if (!strncasecmp(str, "RESPMOD", 7))
        return ICAP::methodRespmod;

    return ICAP::methodNone;
}


const char *
ICAPServiceRep::vectPointStr() const
{
    return ICAP::vectPointStr(point);
}

ICAP::VectPoint
ICAPServiceRep::parseVectPoint(const char *service) const
{
    const char *t = service;
    const char *q = strchr(t, '_');

    if (q)
        t = q + 1;

    if (!strcasecmp(t, "precache"))
        return ICAP::pointPreCache;

    if (!strcasecmp(t, "postcache"))
        return ICAP::pointPostCache;

    return ICAP::pointNone;
}

bool
ICAPServiceRep::configure(Pointer &aSelf)
{
    assert(!self && aSelf != NULL);
    self = aSelf;

    char *service_type = NULL;

    ConfigParser::ParseString(&key);
    ConfigParser::ParseString(&service_type);
    ConfigParser::ParseBool(&bypass);
    ConfigParser::ParseString(&uri);

    debugs(3, 5, "ICAPService::parseConfigLine (line " << config_lineno << "): " << key.buf() << " " << service_type << " " << bypass);

    method = parseMethod(service_type);
    point = parseVectPoint(service_type);

    debugs(3, 5, "ICAPService::parseConfigLine (line " << config_lineno << "): service is " << methodStr() << "_" << vectPointStr());

    if (uri.cmp("icap://", 7) != 0) {
        debugs(3, 0, "ICAPService::parseConfigLine (line " << config_lineno << "): wrong uri: " << uri.buf());
        return false;
    }

    const char *s = uri.buf() + 7;

    const char *e;

    bool have_port = false;

    if ((e = strchr(s, ':')) != NULL) {
        have_port = true;
    } else if ((e = strchr(s, '/')) != NULL) {
        have_port = false;
    } else {
        return false;
    }

    int len = e - s;
    host.limitInit(s, len);
    s = e;

    if (have_port) {
        s++;

        if ((e = strchr(s, '/')) != NULL) {
            char *t;
            port = strtoul(s, &t, 0) % 65536;

            if (t != e) {
                return false;
            }

            s = e;

            if (s[0] != '/') {
                return false;
            }
        }
    } else {

        struct servent *serv = getservbyname("icap", "tcp");

        if (serv) {
            port = htons(serv->s_port);
        } else {
            port = 1344;
        }
    }

    s++;
    e = strchr(s, '\0');
    len = e - s;

    if (len > 1024) {
        debugs(3, 0, "icap_service_process (line " << config_lineno << "): long resource name (>1024), probably wrong");
    }

    resource.limitInit(s, len + 1);

    if ((bypass != 0) && (bypass != 1)) {
        return false;
    }

    return true;

};

void ICAPServiceRep::invalidate()
{
    assert(self != NULL);
    Pointer savedSelf = self; // to prevent destruction when we nullify self
    self = NULL;

    announceStatusChange("invalidated by reconfigure", false);

    savedSelf = NULL; // may destroy us and, hence, invalidate cbdata(this)
    // TODO: it would be nice to invalidate cbdata(this) when not destroyed
}

void ICAPServiceRep::noteFailure() {
    ++theSessionFailures;
    debugs(93,4, "ICAPService failure " << theSessionFailures <<
        ", out of " << TheICAPConfig.service_failure_limit << " allowed");

    if (TheICAPConfig.service_failure_limit >= 0 &&
        theSessionFailures > TheICAPConfig.service_failure_limit)
        suspend("too many failures");

    // TODO: Should bypass setting affect how much Squid tries to talk to
    // the ICAP service that is currently unusable and is likely to remain 
    // so for some time? The current code says "no". Perhaps the answer 
    // should be configurable.
}

void ICAPServiceRep::suspend(const char *reason) {
    if (isSuspended) {
        debugs(93,4, "keeping ICAPService suspended, also for " << reason);
    } else {
        isSuspended = reason;
        debugs(93,1, "suspending ICAPService for " << reason);
        announceStatusChange("suspended", true);
    }
}

bool ICAPServiceRep::probed() const
{
    return theLastUpdate != 0;
}

bool ICAPServiceRep::hasOptions() const {
    return theOptions && theOptions->valid() && theOptions->fresh();
}

bool ICAPServiceRep::up() const
{
    return self != NULL && !isSuspended && hasOptions();
}

bool ICAPServiceRep::broken() const
{
    return probed() && !up();
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

    if (!self || waiting) {
        debugs(93,5, "ICAPService ignores options update " << status());
        return;
    }

    debugs(93,5, "ICAPService performs a regular options update " << status());
    startGettingOptions();
}

static
void ICAPServiceRep_noteTimeToNotify(void *data)
{
    ICAPServiceRep *service = static_cast<ICAPServiceRep*>(data);
    Must(service);
    service->noteTimeToNotify();
}

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
        us = i.service; // prevent callbacks from destroying us while we loop

        if (cbdataReferenceValid(i.data))
            (*i.callback)(i.data, us);

        cbdataReferenceDone(i.data);
    }

    notifying = false;
}

void ICAPServiceRep::callWhenReady(Callback *cb, void *data)
{
    debugs(93,5, HERE << "ICAPService is asked to call " << data <<
        " when ready " << status());

    Must(cb);
    Must(self != NULL);
    Must(!broken()); // we do not wait for a broken service

    Client i;
    i.service = self;
    i.callback = cb;
    i.data = cbdataReference(data);
    theClients.push_back(i);

    if (waiting || notifying)
        return; // do nothing, we will be picked up in noteTimeToNotify()

    if (needNewOptions())
        startGettingOptions();
    else
        scheduleNotification();
}

void ICAPServiceRep::scheduleNotification()
{
    debugs(93,7, "ICAPService will notify " << theClients.size() << " clients");
    eventAdd("ICAPServiceRep::noteTimeToNotify", &ICAPServiceRep_noteTimeToNotify, this, 0, 0, true);
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

    /*
     * Issue a warning if the ICAP server returned methods in the
     * options response that don't match the method from squid.conf.
     */

    if (!theOptions->methods.empty()) {
        bool method_found = false;
        String method_list;
        Vector <ICAP::Method>::iterator iter = theOptions->methods.begin();

        while (iter != theOptions->methods.end()) {

            if (*iter == method) {
                method_found = true;
                break;
            }

            method_list.append(ICAP::methodStr(*iter));
            method_list.append(" ", 1);
            iter++;
        }

        if (!method_found) {
            debugs(93,1, "WARNING: Squid is configured to use ICAP method " <<
                   ICAP::methodStr(method) <<
                   " for service " << uri.buf() <<
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
            " seconds: " << uri.buf());
    }
}

void ICAPServiceRep::announceStatusChange(const char *downPhrase, bool important) const
{
    if (wasAnnouncedUp == up()) // no significant changes to announce
        return;

    const char *what = bypass ? "optional" : "essential";
    const char *state = wasAnnouncedUp ? downPhrase : "up";
    const int level = important ? 1 : 2;
    debugs(93,level, what << " ICAP service is " << state << ": " << uri <<
        ' ' << status());

    wasAnnouncedUp = !wasAnnouncedUp;
}

// we are receiving ICAP OPTIONS response headers here or NULL on failures
void ICAPServiceRep::noteIcapAnswer(HttpMsg *msg)
{
    Must(waiting);
    waiting = false;

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

void ICAPServiceRep::noteIcapQueryAbort(bool) {
    Must(waiting);
    waiting = false;

    debugs(93,3, "ICAPService failed to fetch options " << status());
    handleNewOptions(0);
}

void ICAPServiceRep::handleNewOptions(ICAPOptions *newOptions)
{
    // new options may be NULL
    changeOptions(newOptions);

    debugs(93,3, "ICAPService got new options and is now " << status());

    scheduleUpdate();
    scheduleNotification();
}

void ICAPServiceRep::startGettingOptions()
{
    Must(!waiting);
    debugs(93,6, "ICAPService will get new options " << status());
    waiting = true;

    initiateIcap(new ICAPOptXactLauncher(this, self));
    // TODO: timeout in case ICAPOptXact never calls us back?
    // Such a timeout should probably be a generic AsyncStart feature.
}

void ICAPServiceRep::scheduleUpdate()
{
    if (updateScheduled)
        return; // already scheduled

    // XXX: move hard-coded constants from here to TheICAPConfig

    // conservative estimate of how long the OPTIONS transaction will take
    const int expectedWait = 20; // seconds

    time_t when = 0;

    if (theOptions && theOptions->valid()) {
        const time_t expire = theOptions->expire();
        debugs(93,7, "ICAPService options expire on " << expire << " >= " << squid_curtime);

        // Unknown or invalid (too small) expiration times should not happen.
        // ICAPOptions should use the default TTL, and ICAP servers should not
        // send invalid TTLs, but bugs and attacks happen.
        if (expire < expectedWait)
            when = squid_curtime + 60*60;
        else
            when = expire - expectedWait; // before the current options expire
    } else {
        // delay for a down service
        when = squid_curtime + TheICAPConfig.service_revival_delay;
    }

    debugs(93,7, "ICAPService options raw update at " << when << " or in " <<
        (when - squid_curtime) << " sec");

    /* adjust update time to prevent too-frequent updates */

    if (when < squid_curtime)
        when = squid_curtime;

    const int minUpdateGap = expectedWait + 10; // seconds
    if (when < theLastUpdate + minUpdateGap)
        when = theLastUpdate + minUpdateGap;

    const int delay = when - squid_curtime;
    debugs(93,5, "ICAPService will update options in " << delay << " sec");
    eventAdd("ICAPServiceRep::noteTimeToUpdate",
             &ICAPServiceRep_noteTimeToUpdate, this, delay, 0, true);
    updateScheduled = true;
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

    if (waiting)
        buf.append(",wait", 5);

    if (notifying)
        buf.append(",notif", 6);

    if (theSessionFailures > 0)
        buf.Printf(",fail%d", theSessionFailures);

    buf.append("]", 1);
    buf.terminate();

    return buf.content();
}
