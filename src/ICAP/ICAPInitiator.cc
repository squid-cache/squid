/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "ICAPXaction.h"
#include "ICAPInitiator.h"

ICAPInitiate *ICAPInitiator::initiateIcap(ICAPInitiate *x) {
    if ((x = dynamic_cast<ICAPInitiate*>(ICAPInitiate::AsyncStart(x))))
        x = cbdataReference(x);
    return x;    
}

void ICAPInitiator::clearIcap(ICAPInitiate *&x) {
    assert(x);
    cbdataReferenceDone(x);
}

void ICAPInitiator::announceInitiatorAbort(ICAPInitiate *&x)
{
    if (x) {
	CallJobHere(93, 5, x, ICAPInitiate::noteInitiatorAborted);
        clearIcap(x);
    }
}
