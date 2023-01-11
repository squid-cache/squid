/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ADAPTATION__ACCESS_CHECK_H
#define SQUID_ADAPTATION__ACCESS_CHECK_H

#include "AccessLogEntry.h"
#include "acl/Acl.h"
#include "adaptation/Elements.h"
#include "adaptation/forward.h"
#include "adaptation/Initiator.h"
#include "adaptation/ServiceFilter.h"
#include "base/AsyncJob.h"

class HttpRequest;
class HttpReply;
class ACLFilledChecklist;

namespace Adaptation
{

class AccessRule;

// checks adaptation_access rules to find a matching adaptation service
class AccessCheck: public virtual AsyncJob
{
    CBDATA_CLASS(AccessCheck);

public:
    typedef void AccessCheckCallback(ServiceGroupPointer group, void *data);

    // use this to start async ACL checks; returns true if started
    static bool Start(Method method, VectPoint vp, HttpRequest *req,
                      HttpReply *rep, AccessLogEntry::Pointer &al, Adaptation::Initiator *initiator);

protected:
    // use Start to start adaptation checks
    AccessCheck(const ServiceFilter &aFilter, Adaptation::Initiator *);
    ~AccessCheck();

private:
    const ServiceFilter filter;
    CbcPointer<Adaptation::Initiator> theInitiator; ///< the job which ordered this access check
    ACLFilledChecklist *acl_checklist;

    typedef int Candidate;
    typedef std::vector<Candidate> Candidates;
    Candidates candidates;
    Candidate topCandidate() const { return *candidates.begin(); }
    ServiceGroupPointer topGroup() const; // may return nil

    void callBack(const ServiceGroupPointer &g);
    bool isCandidate(AccessRule &r);

public:
    void checkCandidates();
    static void AccessCheckCallbackWrapper(Acl::Answer, void*);
    void noteAnswer(Acl::Answer answer);

protected:
    // AsyncJob API
    virtual void start();
    virtual bool doneAll() const { return false; } /// not done until mustStop

    bool usedDynamicRules();
    void check();
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__ACCESS_CHECK_H */

