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
        return AsyncStart(new AccessCheck(
                              ServiceFilter(method, vp, req, rep), cb, cbdata));
    }

    debugs(83, 3, HERE << "adaptation off, skipping");
    return false;
}

Adaptation::AccessCheck::AccessCheck(const ServiceFilter &aFilter,
                                     AccessCheckCallback *aCallback,
                                     void *aCallbackData):
        AsyncJob("AccessCheck"), filter(aFilter),
        callback(aCallback),
        callback_data(cbdataReference(aCallbackData)),
        acl_checklist(NULL)
{
#if ICAP_CLIENT
    Adaptation::Icap::History::Pointer h = filter.request->icapHistory();
    if (h != NULL)
        h->start("ACL");
#endif

    debugs(93, 5, HERE << "AccessCheck constructed for " <<
           methodStr(filter.method) << " " << vectPointStr(filter.point));
}

Adaptation::AccessCheck::~AccessCheck()
{
#if ICAP_CLIENT
    Adaptation::Icap::History::Pointer h = filter.request->icapHistory();
    if (h != NULL)
        h->stop("ACL");
#endif
    if (callback_data)
        cbdataReferenceDone(callback_data);
}

void
Adaptation::AccessCheck::start()
{
    AsyncJob::start();
    check();
}

/// Walk the access rules list to find rules with applicable service groups
void
Adaptation::AccessCheck::check()
{
    debugs(93, 4, HERE << "start checking");

    typedef AccessRules::iterator ARI;
    for (ARI i = AllRules().begin(); i != AllRules().end(); ++i) {
        AccessRule *r = *i;
        if (isCandidate(*r)) {
            debugs(93, 5, HERE << "check: rule '" << r->id << "' is a candidate");
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
            acl_checklist = new ACLFilledChecklist(r->acl, filter.request, dash_str);
            acl_checklist->reply = filter.reply ? HTTPMSGLOCK(filter.reply) : NULL;
            acl_checklist->nonBlockingCheck(AccessCheckCallbackWrapper, this);
            return;
        }

        candidates.shift(); // the rule apparently went away (reconfigure)
    }

    debugs(93, 4, HERE << "NO candidates left");
    callBack(NULL);
    Must(done());
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

/// process the results of the ACL check
void
Adaptation::AccessCheck::noteAnswer(int answer)
{
    Must(!candidates.empty()); // the candidate we were checking must be there
    debugs(93,5, HERE << topCandidate() << " answer=" << answer);

    if (answer) { // the rule matched
        ServiceGroupPointer g = topGroup();
        if (g != NULL) { // the corresponding group found
            callBack(g);
            Must(done());
            return;
        }
    }

    // no match or the group disappeared during reconfiguration
    candidates.shift();
    checkCandidates();
}

/// call back with a possibly nil group; the job ends here because all failures
/// at this point are fatal to the access check process
void
Adaptation::AccessCheck::callBack(const ServiceGroupPointer &g)
{
    debugs(93,3, HERE << g);

    void *validated_cbdata;
    if (cbdataReferenceValidDone(callback_data, &validated_cbdata)) {
        callback(g, validated_cbdata);
    }
    mustStop("done"); // called back or will never be able to call back
}

Adaptation::ServiceGroupPointer
Adaptation::AccessCheck::topGroup() const
{
    ServiceGroupPointer g;
    if (candidates.size()) {
        if (AccessRule *r = FindRule(topCandidate())) {
            g = FindGroup(r->groupId);
            debugs(93,5, HERE << "top group for " << r->id << " is " << g);
        } else {
            debugs(93,5, HERE << "no rule for " << topCandidate());
        }
    } else {
        debugs(93,5, HERE << "no candidates"); // should not happen
    }

    return g;
}

/** Returns true iff the rule's service group will be used after ACL matches.
    Used to detect rules worth ACl-checking. */
bool
Adaptation::AccessCheck::isCandidate(AccessRule &r)
{
    debugs(93,7,HERE << "checking candidacy of " << r.id << ", group " <<
           r.groupId);

    ServiceGroupPointer g = FindGroup(r.groupId);

    if (!g) {
        debugs(93,7,HERE << "lost " << r.groupId << " group in rule" << r.id);
        return false;
    }

    const bool wants = g->wants(filter);
    debugs(93,7,HERE << r.groupId << (wants ? " wants" : " ignores"));
    return wants;
}
