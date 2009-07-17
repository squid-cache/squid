#ifndef SQUID_ADAPTATION__ACCESS_CHECK_H
#define SQUID_ADAPTATION__ACCESS_CHECK_H

#include "base/AsyncJob.h"
#include "adaptation/Elements.h"
#include "adaptation/forward.h"
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
                      HttpReply *rep, AccessCheckCallback *cb, void *cbdata);

protected:
    // use Start to start adaptation checks
    AccessCheck(const ServiceFilter &aFilter, AccessCheckCallback *, void *);
    ~AccessCheck();

private:
    const ServiceFilter filter;
    AccessCheckCallback *callback;
    void *callback_data;
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
    static void AccessCheckCallbackWrapper(int, void*);
    void noteAnswer(int answer);

protected:
    // AsyncJob API
    virtual void start();
    virtual bool doneAll() const { return false; } /// not done until mustStop

    void check();

private:
    CBDATA_CLASS2(AccessCheck);
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__ACCESS_CHECK_H */
