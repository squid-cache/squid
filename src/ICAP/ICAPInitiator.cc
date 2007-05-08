/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "ICAPXaction.h"
#include "ICAPInitiator.h"

ICAPInitiate *ICAPInitiator::initiateIcap(ICAPInitiate *x) {
    x = cbdataReference(x);
    return dynamic_cast<ICAPInitiate*>(ICAPInitiate::AsyncStart(x));
}

void ICAPInitiator::clearIcap(ICAPInitiate *&x) {
    assert(x);
    cbdataReferenceDone(x);
}

void ICAPInitiator::announceInitiatorAbort(ICAPInitiate *&x)
{
    if (x) {
        AsyncCall(93,5, x, ICAPInitiate::noteInitiatorAborted);
        clearIcap(x);
    }
}
