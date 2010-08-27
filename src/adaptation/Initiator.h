#ifndef SQUID_ADAPTATION__INITIATOR_H
#define SQUID_ADAPTATION__INITIATOR_H

#include "base/AsyncJob.h"
#include "base/CbcPointer.h"
#include "adaptation/forward.h"

/*
 * The ICAP Initiator is an ICAP vectoring point that initates ICAP
 * transactions. This interface exists to allow ICAP transactions to
 * signal their initiators that they have the answer from the ICAP server
 * or that the ICAP query has aborted and there will be no answer. It
 * is also handy for implementing common initiator actions such as starting
 * or aborting an ICAP transaction.
 */

class HttpMsg;

namespace Adaptation
{

class Initiator: virtual public AsyncJob
{
public:
    Initiator(): AsyncJob("Initiator") {}
    virtual ~Initiator() {}

    // called when ICAP response headers are successfully interpreted
    virtual void noteAdaptationAnswer(HttpMsg *message) = 0;

    // called when valid ICAP response headers are no longer expected
    // the final parameter is set to disable bypass or retries
    virtual void noteAdaptationQueryAbort(bool final) = 0;

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
