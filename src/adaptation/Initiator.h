#ifndef SQUID_ADAPTATION__INITIATOR_H
#define SQUID_ADAPTATION__INITIATOR_H

#include "base/AsyncJob.h"
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
    Initiate *initiateAdaptation(Initiate *x); // locks and returns x

    // done with x (and not calling announceInitiatorAbort)
    void clearAdaptation(Initiate *&x); // unlocks x

    // inform the transaction about abnormal termination and clear it
    void announceInitiatorAbort(Initiate *&x); // unlocks x
};

} // namespace Adaptation

#endif /* SQUID_ADAPTATION__INITIATOR_H */
