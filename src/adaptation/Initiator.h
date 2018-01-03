/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ADAPTATION__INITIATOR_H
#define SQUID_ADAPTATION__INITIATOR_H

#include "adaptation/forward.h"
#include "base/AsyncJob.h"
#include "base/CbcPointer.h"

/*
 * The ICAP Initiator is an ICAP vectoring point that initates ICAP
 * transactions. This interface exists to allow ICAP transactions to
 * signal their initiators that they have the answer from the ICAP server
 * or that the ICAP query has aborted and there will be no answer. It
 * is also handy for implementing common initiator actions such as starting
 * or aborting an ICAP transaction.
 */

namespace Adaptation
{

class Initiator: virtual public AsyncJob
{
public:
    Initiator(): AsyncJob("Initiator") {}
    virtual ~Initiator() {}

    /// AccessCheck calls this back with a possibly nil service group
    /// to signal whether adaptation is needed and where it should start.
    virtual void noteAdaptationAclCheckDone(Adaptation::ServiceGroupPointer group);
    /// called with the initial adaptation decision (adapt, block, error);
    /// virgin and/or adapted body transmission may continue after this
    virtual void noteAdaptationAnswer(const Answer &answer) = 0;

protected:
    ///< starts freshly created initiate and returns a safe pointer to it
    CbcPointer<Initiate> initiateAdaptation(Initiate *x);

    /// clears the pointer (does not call announceInitiatorAbort)
    void clearAdaptation(CbcPointer<Initiate> &x);

    /// inform the transaction about abnormal termination and clear the pointer
    void announceInitiatorAbort(CbcPointer<Initiate> &x);

    /// Must(initiated(initiate)) instead of Must(initiate.set()), for clarity
    bool initiated(const CbcPointer<AsyncJob> &job) const { return job.set(); }
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__INITIATOR_H */

