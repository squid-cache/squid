#include "squid.h"
#include "structs.h"

#include "ConfigParser.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "acl/FilledChecklist.h"
#include "adaptation/Service.h"
#include "adaptation/ServiceGroups.h"
#include "adaptation/AccessRule.h"
#include "adaptation/Config.h"
#include "adaptation/AccessCheck.h"


/** \cond AUTODOCS-IGNORE */
cbdata_type Adaptation::AccessCheck::CBDATA_AccessCheck = CBDATA_UNKNOWN;
/** \endcond */

bool
Adaptation::AccessCheck::Start(Method method, VectPoint vp,
                               HttpRequest *req, HttpReply *rep, AccessCheckCallback *cb, void *cbdata)
{

    if (Config::Enabled) {
        // the new check will call the callback and delete self, eventually
        AccessCheck *check = new AccessCheck(method, vp, req, rep, cb, cbdata);
        check->check();
        return true;
    }

    debugs(83, 3, HERE << "adaptation off, skipping");
    return false;
}

Adaptation::AccessCheck::AccessCheck(Method aMethod,
                                     VectPoint aPoint,
                                     HttpRequest *aReq,
                                     HttpReply *aRep,
                                     AccessCheckCallback *aCallback,
                                     void *aCallbackData): AsyncJob("AccessCheck"), done(FALSE)
{
    // TODO: assign these at creation time

    method = aMethod;
    point = aPoint;

    req = HTTPMSGLOCK(aReq);
    rep = aRep ? HTTPMSGLOCK(aRep) : NULL;

    callback = aCallback;

    callback_data = cbdataReference(aCallbackData);

    acl_checklist = NULL;

    debugs(93, 5, HERE << "AccessCheck constructed for " << methodStr(method) << " " << vectPointStr(point));
}

Adaptation::AccessCheck::~AccessCheck()
{
    HTTPMSGUNLOCK(req);
    HTTPMSGUNLOCK(rep);
    if (callback_data)
        cbdataReferenceDone(callback_data);
}

/*
 * Walk the access rules list and find all classes that have at least
 * one service with matching method and vectoring point.
 */
void
Adaptation::AccessCheck::check()
{
    debugs(93, 4, HERE << "start checking");

    typedef AccessRules::iterator ARI;
    for (ARI i = AllRules().begin(); i != AllRules().end(); ++i) {

        /*
         * We only find the first matching service because we only need
         * one matching service to justify ACL-checking a class.  We might
         * use other services belonging to the class if the first service
         * turns out to be unusable for some reason.
         */
        AccessRule *r = *i;
        ServicePointer service = findBestService(*r, false);
        if (service != NULL) {
            debugs(93, 5, HERE << "check: rule '" << r->id << "' has candidate service '" << service->cfg().key << "'");
            candidates += r->id;
        }
    }

    checkCandidates();
}

// XXX: Here and everywhere we call FindRule(topCandidate()):
// Once we identified the candidate, we should not just ignore it
// if reconfigure changes rules. We should either lock the rule to
// prevent reconfigure from stealing it or restart the check with
// new rules. Throwing an exception may also be appropriate.
void
Adaptation::AccessCheck::checkCandidates()
{
    debugs(93, 4, HERE << "has " << candidates.size() << " rules");

    while (!candidates.empty()) {
        if (AccessRule *r = FindRule(topCandidate())) {
            /* BUG 2526: what to do when r->acl is empty?? */
            // XXX: we do not have access to conn->rfc931 here.
            acl_checklist = new ACLFilledChecklist(r->acl, req, dash_str);
            acl_checklist->reply = rep ? HTTPMSGLOCK(rep) : NULL;
            acl_checklist->nonBlockingCheck(AccessCheckCallbackWrapper, this);
            return;
        }

        candidates.shift(); // the rule apparently went away (reconfigure)
    }

    // when there are no canidates, fake answer 1
    debugs(93, 4, HERE << "NO candidates left");
    noteAnswer(1);
}

void
Adaptation::AccessCheck::AccessCheckCallbackWrapper(int answer, void *data)
{
    debugs(93, 8, HERE << "callback answer=" << answer);
    AccessCheck *ac = (AccessCheck*)data;

    /** \todo AYJ 2008-06-12: If answer == ACCESS_REQ_PROXY_AUTH
     * we should be kicking off an authentication before continuing
     * with this request. see bug 2400 for details.
     */
    ac->noteAnswer(answer==ACCESS_ALLOWED);
}

void
Adaptation::AccessCheck::noteAnswer(int answer)
{
    debugs(93, 5, HERE << "AccessCheck::noteAnswer " << answer);
    if (candidates.size())
        debugs(93, 5, HERE << "was checking rule" << topCandidate());

    if (!answer) {
        candidates.shift(); // the rule did not match
        checkCandidates();
        return;
    }

    /*
     * We use an event here to break deep function call sequences
     */
    // XXX: use AsyncCall for callback and remove
    CallJobHere(93, 5, this, Adaptation::AccessCheck::do_callback);
}

void
Adaptation::AccessCheck::do_callback()
{
    debugs(93, 3, HERE);

    if (candidates.size())
        debugs(93, 3, HERE << "was checking rule" << topCandidate());

    void *validated_cbdata;
    if (!cbdataReferenceValidDone(callback_data, &validated_cbdata)) {
        debugs(93,3,HERE << "do_callback: callback_data became invalid, skipping");
        return;
    }

    ServicePointer service = NULL;
    if (candidates.size()) {
        if (AccessRule *r = FindRule(topCandidate())) {
            service = findBestService(*r, true);
            if (service != NULL)
                debugs(93,3,HERE << "do_callback: with service " << service->cfg().uri);
            else
                debugs(93,3,HERE << "do_callback: no service for rule" << r->id);
        } else {
            debugs(93,3,HERE << "do_callback: no rule" << topCandidate());
        }
        candidates.shift(); // done with topCandidate()
    } else {
        debugs(93,3,HERE << "do_callback: no candidate rules");
    }

    callback(service, validated_cbdata);
    done = TRUE;
}

Adaptation::ServicePointer
Adaptation::AccessCheck::findBestService(AccessRule &r, bool preferUp)
{

    const char *what = preferUp ? "up " : "";
    debugs(93,7,HERE << "looking for the first matching " <<
           what << "service in group " << r.groupId);

    ServicePointer secondBest;

    ServiceGroup *g = FindGroup(r.groupId);

    if (!g) {
        debugs(93,5,HERE << "lost " << r.groupId << " group in rule" << r.id);
        return ServicePointer();
    }

    ServiceGroup::Loop loop(g->initialServices());
    typedef ServiceGroup::iterator SGI;
    for (SGI i = loop.begin; i != loop.end; ++i) {

        ServicePointer service = FindService(*i);

        if (!service)
            continue;

        if (method != service->cfg().method)
            continue;

        if (point != service->cfg().point)
            continue;

        // sending a message to a broken service is likely to cause errors
        if (service->cfg().bypass && service->broken())
            continue;

        if (service->up()) {
            // sending a message to a service that does not want it is useless
            // note that we cannot check wantsUrl for service that is not "up"
            // note that even essential services are skipped on unwanted URLs!
            if (!service->wantsUrl(req->urlpath))
                continue;
        } else {
            if (!secondBest)
                secondBest = service;
            if (preferUp) {
                // the caller asked for an "up" service and we can bypass this one
                if (service->cfg().bypass)
                    continue;
                debugs(93,5,HERE << "cannot skip an essential down service");
                what = "down-but-essential ";
            }
        }

        debugs(93,5,HERE << "found first matching " <<
               what << "service for " << r.groupId << " group in rule" << r.id <<
               ": " << service->cfg().key);

        return service;
    }

    if (secondBest != NULL) {
        what = "down ";
        debugs(93,5,HERE << "found first matching " <<
               what << "service for " << r.groupId << " group in rule" << r.id <<
               ": " << secondBest->cfg().key);
        return secondBest;
    }

    debugs(93,5,HERE << "found no matching " <<
           what << "services for " << r.groupId << " group in rule" << r.id);
    return ServicePointer();
}
