#ifndef SQUID_ADAPTATION__ACCESS_CHECK_H
#define SQUID_ADAPTATION__ACCESS_CHECK_H

#include "acl/Acl.h"
#include "base/AsyncJob.h"
#include "adaptation/Elements.h"
#include "adaptation/forward.h"
#include "adaptation/Initiator.h"
#include "adaptation/ServiceFilter.h"

class HttpRequest;
class HttpReply;
class ACLFilledChecklist;

namespace Adaptation
{

class AccessRule;

// checks adaptation_access rules to find a matching adaptation service
class AccessCheck: public virtual AsyncJob
{
public:
    typedef void AccessCheckCallback(ServiceGroupPointer group, void *data);

    // use this to start async ACL checks; returns true if started
    static bool Start(Method method, VectPoint vp, HttpRequest *req,
                      HttpReply *rep, Adaptation::Initiator *initiator);

protected:
    // use Start to start adaptation checks
    AccessCheck(const ServiceFilter &aFilter, Adaptation::Initiator *);
    ~AccessCheck();

private:
    const ServiceFilter filter;
    CbcPointer<Adaptation::Initiator> theInitiator; ///< the job which ordered this access check
    ACLFilledChecklist *acl_checklist;

    typedef int Candidate;
    typedef Vector<Candidate> Candidates;
    Candidates candidates;
    Candidate topCandidate() const { return *candidates.begin(); }
    ServiceGroupPointer topGroup() const; // may return nil

    void callBack(const ServiceGroupPointer &g);
    bool isCandidate(AccessRule &r);

public:
    void checkCandidates();
    static void AccessCheckCallbackWrapper(allow_t, void*);
    void noteAnswer(allow_t answer);

protected:
    // AsyncJob API
    virtual void start();
    virtual bool doneAll() const { return false; } /// not done until mustStop

    bool usedDynamicRules();
    void check();

private:
    CBDATA_CLASS2(AccessCheck);
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__ACCESS_CHECK_H */
