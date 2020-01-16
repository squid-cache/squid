/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "acl/FilledChecklist.h"
#include "adaptation/AccessCheck.h"
#include "adaptation/AccessRule.h"
#include "adaptation/Config.h"
#include "adaptation/Initiator.h"
#include "adaptation/Service.h"
#include "adaptation/ServiceGroups.h"
#include "base/AsyncJobCalls.h"
#include "base/TextException.h"
#include "ConfigParser.h"
#include "globals.h"
#include "HttpReply.h"
#include "HttpRequest.h"

/** \cond AUTODOCS_IGNORE */
cbdata_type Adaptation::AccessCheck::CBDATA_AccessCheck = CBDATA_UNKNOWN;
/** \endcond */

bool
Adaptation::AccessCheck::Start(Method method, VectPoint vp,
                               HttpRequest *req, HttpReply *rep,
                               AccessLogEntry::Pointer &al, Adaptation::Initiator *initiator)
{

    if (Config::Enabled) {
        // the new check will call the callback and delete self, eventually
        AsyncJob::Start(new AccessCheck( // we do not store so not a CbcPointer
                            ServiceFilter(method, vp, req, rep, al), initiator));
        return true;
    }

    debugs(83, 3, HERE << "adaptation off, skipping");
    return false;
}

Adaptation::AccessCheck::AccessCheck(const ServiceFilter &aFilter,
                                     Adaptation::Initiator *initiator):
    AsyncJob("AccessCheck"), filter(aFilter),
    theInitiator(initiator),
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
}

void
Adaptation::AccessCheck::start()
{
    AsyncJob::start();

    if (!usedDynamicRules())
        check();
}

/// returns true if previous services configured dynamic chaining "rules"
bool
Adaptation::AccessCheck::usedDynamicRules()
{
    Adaptation::History::Pointer ah = filter.request->adaptHistory();
    if (!ah)
        return false; // dynamic rules not enabled or not triggered

    DynamicGroupCfg services;
    if (!ah->extractFutureServices(services)) { // clears history
        debugs(85,9, HERE << "no service-proposed rules stored");
        return false; // earlier service did not plan for the future
    }

    debugs(85,3, HERE << "using stored service-proposed rules: " << services);

    ServiceGroupPointer g = new DynamicServiceChain(services, filter);
    callBack(g);
    Must(done());
    return true;
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
            candidates.push_back(r->id);
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
            if ((acl_checklist->reply = filter.reply))
                HTTPMSGLOCK(acl_checklist->reply);
            acl_checklist->al = filter.al;
            acl_checklist->syncAle(filter.request, nullptr);
            acl_checklist->nonBlockingCheck(AccessCheckCallbackWrapper, this);
            return;
        }

        candidates.erase(candidates.begin()); // the rule apparently went away (reconfigure)
    }

    debugs(93, 4, HERE << "NO candidates left");
    callBack(NULL);
    Must(done());
}

void
Adaptation::AccessCheck::AccessCheckCallbackWrapper(allow_t answer, void *data)
{
    debugs(93, 8, HERE << "callback answer=" << answer);
    AccessCheck *ac = (AccessCheck*)data;

    /** \todo AYJ 2008-06-12: If answer == ACCESS_AUTH_REQUIRED
     * we should be kicking off an authentication before continuing
     * with this request. see bug 2400 for details.
     */

    // convert to async call to get async call protections and features
    typedef UnaryMemFunT<AccessCheck, allow_t> MyDialer;
    AsyncCall::Pointer call =
        asyncCall(93,7, "Adaptation::AccessCheck::noteAnswer",
                  MyDialer(ac, &Adaptation::AccessCheck::noteAnswer, answer));
    ScheduleCallHere(call);

}

/// process the results of the ACL check
void
Adaptation::AccessCheck::noteAnswer(allow_t answer)
{
    Must(!candidates.empty()); // the candidate we were checking must be there
    debugs(93,5, HERE << topCandidate() << " answer=" << answer);

    if (answer.allowed()) { // the rule matched
        ServiceGroupPointer g = topGroup();
        if (g != NULL) { // the corresponding group found
            callBack(g);
            Must(done());
            return;
        }
    }

    // no match or the group disappeared during reconfiguration
    candidates.erase(candidates.begin());
    checkCandidates();
}

/// call back with a possibly nil group; the job ends here because all failures
/// at this point are fatal to the access check process
void
Adaptation::AccessCheck::callBack(const ServiceGroupPointer &g)
{
    debugs(93,3, HERE << g);
    CallJobHere1(93, 5, theInitiator, Adaptation::Initiator,
                 noteAdaptationAclCheckDone, g);
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

