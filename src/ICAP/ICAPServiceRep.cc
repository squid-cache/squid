/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "TextException.h"
#include "ICAPServiceRep.h"
#include "ICAPOptions.h"
#include "ICAPOptXact.h"
#include "ConfigParser.h"

CBDATA_CLASS_INIT(ICAPServiceRep);

ICAPServiceRep::ICAPServiceRep(): method(ICAP::methodNone),
        point(ICAP::pointNone), port(-1), bypass(false), unreachable(false),
        theOptions(NULL), theState(stateInit), notifying(false), self(NULL)
{}

ICAPServiceRep::~ICAPServiceRep()
{
    Must(!waiting());
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

    debug(3, 5) ("ICAPService::parseConfigLine (line %d): %s %s %d\n", config_lineno, key.buf(), service_type, bypass);

    method = parseMethod(service_type);
    point = parseVectPoint(service_type);

    debug(3, 5) ("ICAPService::parseConfigLine (line %d): service is %s_%s\n", config_lineno, methodStr(), vectPointStr());

    if (uri.cmp("icap://", 7) != 0) {
        debug(3, 0) ("ICAPService::parseConfigLine (line %d): wrong uri: %s\n", config_lineno, uri.buf());
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
        debug(3, 0) ("icap_service_process (line %d): long resource name (>1024), probably wrong\n", config_lineno);
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
    self = NULL; // may destroy us and, hence, invalidate cbdata(this)
    // TODO: it would be nice to invalidate cbdata(this) when not destroyed
}

bool ICAPServiceRep::up() const
{
    return self != NULL && theState == stateUp;
}

bool ICAPServiceRep::wantsPreview(size_t &wantedSize) const
{
    Must(up());

    if (theOptions->preview < 0)
        return false;

    wantedSize = theOptions->preview;

    return true;
}

bool ICAPServiceRep::allows204() const
{
    Must(up());
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
    if (!self || waiting()) {
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
    Must(cb);
    Must(self != NULL);

    Client i;
    i.service = self;
    i.callback = cb;
    i.data = cbdataReference(data);
    theClients.push_back(i);

    if (waiting() || notifying)
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

bool ICAPServiceRep::waiting() const
{
    return theState == stateWait;
}

bool ICAPServiceRep::needNewOptions() const
{
    return !theOptions || !theOptions->fresh();
}

void ICAPServiceRep::changeOptions(ICAPOptions *newOptions)
{
    debugs(93,9, "ICAPService changes options from " << theOptions << " to " <<
           newOptions);
    delete theOptions;
    theOptions = newOptions;

    if (theOptions == NULL)
        return;

    /*
     * Maybe it would be better if squid.conf just listed the URI and
     * then discovered the method via OPTIONS
     */

    if (theOptions->method != method)
        debugs(93,1, "WARNING: Squid is configured to use ICAP method " << ICAP::methodStr(method) <<
               " for service " << uri.buf() <<
               " but OPTIONS response declares the method is " << ICAP::methodStr(theOptions->method));


    /*
     *  Check the ICAP server's date header for clock skew
     */
    int skew = abs((int)(theOptions->timestamp() - squid_curtime));

    if (skew > theOptions->ttl())
        debugs(93, 1, host.buf() << "'s clock is skewed by " << skew << " seconds!");

#if 0

    List<String> *tmp;

    for (tmp = theOptions->transfers.preview; tmp; tmp=tmp->next)
        debugs(93,1,"Transfer-Preview: " << tmp->element.buf());

    for (tmp = theOptions->transfers.ignore; tmp; tmp=tmp->next)
        debugs(93,1,"Transfer-Ignore: " << tmp->element.buf());

    for (tmp = theOptions->transfers.complete; tmp; tmp=tmp->next)
        debugs(93,1,"Transfer-Complete: " << tmp->element.buf());

#endif
}

static
void ICAPServiceRep_noteNewOptions(ICAPOptXact *x, void *data)
{
    ICAPServiceRep *service = static_cast<ICAPServiceRep*>(data);
    Must(service);
    service->noteNewOptions(x);
}

void ICAPServiceRep::noteNewOptions(ICAPOptXact *x)
{
    Must(x);
    Must(waiting());

    theState = stateDown; // default in case we fail to set new options

    changeOptions(x->options);
    x->options = NULL;
    delete x;

    if (theOptions && theOptions->valid())
        theState = stateUp;

    debugs(93,6, "ICAPService got new options and is now " <<
           (up() ? "up" : "down"));

    scheduleUpdate();

    scheduleNotification();
}

void ICAPServiceRep::startGettingOptions()
{
    debugs(93,6, "ICAPService will get new options " << status());
    theState = stateWait;

    ICAPOptXact *x = new ICAPOptXact;
    x->start(self, &ICAPServiceRep_noteNewOptions, this);
    // TODO: timeout incase ICAPOptXact never calls us back?
}

void ICAPServiceRep::scheduleUpdate()
{
    int delay = -1;

    if (theOptions && theOptions->valid()) {
        const time_t expire = theOptions->expire();

        if (expire > squid_curtime)
            delay = expire - squid_curtime;
        else
            if (expire >= 0)
                delay = 1; // delay for expired or 'expiring now' options
            else
                delay = 60*60; // default for options w/o known expiration time
    } else {
        delay = 5*60; // delay for a down service
    }

    if (delay <= 0) {
        debugs(93,0, "internal error: ICAPServiceRep failed to compute options update schedule");
        delay = 5*60; // delay for an internal error
    }

    // with zero delay, the state changes to stateWait before
    // notifications are sent out to clients
    assert(delay > 0);

    debugs(93,7, "ICAPService will update options in " << delay << " sec");

    eventAdd("ICAPServiceRep::noteTimeToUpdate",
             &ICAPServiceRep_noteTimeToUpdate, this, delay, 0, true);

    // XXX: prompt updates of valid options should not disable concurrent ICAP
    // xactions. 'Wait' state should not mark the service 'down'! This will
    // also remove 'delay == 0' as a special case above.
}

const char *ICAPServiceRep::status() const
{
    if (!self)
        return "[invalidated]";

    switch (theState) {

    case stateInit:
        return "[init]";

    case stateWait:
        return "[wait]";

    case stateUp:
        return "[up]";

    case stateDown:
        return "[down]";
    }

    return "[unknown]";
}
