/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "adaptation/Initiate.h"
#include "adaptation/Initiator.h"

Adaptation::Initiate *
Adaptation::Initiator::initiateAdaptation(Adaptation::Initiate *x)
{
    if ((x = dynamic_cast<Initiate*>(Initiate::AsyncStart(x))))
        x = cbdataReference(x);
    return x;
}

void
Adaptation::Initiator::clearAdaptation(Initiate *&x)
{
    assert(x);
    cbdataReferenceDone(x);
}

void
Adaptation::Initiator::announceInitiatorAbort(Initiate *&x)
{
    if (x) {
        CallJobHere(93, 5, x, Initiate::noteInitiatorAborted);
        clearAdaptation(x);
    }
}
