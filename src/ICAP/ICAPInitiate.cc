/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "HttpMsg.h"
#include "ICAPInitiator.h"
#include "ICAPInitiate.h"

// ICAPInitiator::noteIcapAnswer Dialer locks/unlocks the message in transit
// TODO: replace HTTPMSGLOCK with general RefCounting and delete this class
class IcapAnswerDialer: public UnaryMemFunT<ICAPInitiator, HttpMsg*>
{
public:
    typedef UnaryMemFunT<ICAPInitiator, HttpMsg*> Parent;

    IcapAnswerDialer(ICAPInitiator *obj, Parent::Method meth, HttpMsg *msg):
        Parent(obj, meth, msg) { HTTPMSGLOCK(arg1); }
    IcapAnswerDialer(const IcapAnswerDialer &d):
        Parent(d) { HTTPMSGLOCK(arg1); }
    virtual ~IcapAnswerDialer() { HTTPMSGUNLOCK(arg1); }
};


/* ICAPInitiate */

ICAPInitiate::ICAPInitiate(const char *aTypeName,
    ICAPInitiator *anInitiator, ICAPServiceRep::Pointer &aService):
    AsyncJob(aTypeName), theInitiator(anInitiator), theService(aService)
{
    assert(theService != NULL);
    assert(theInitiator);
}

ICAPInitiate::~ICAPInitiate()
{
    assert(!theInitiator);
}

// internal cleanup
void ICAPInitiate::swanSong()
{
    debugs(93, 5, HERE << "swan sings" << status());

    if (theInitiator) {
        debugs(93, 3, HERE << "fatal failure; sending abort notification");
        tellQueryAborted(true); // final by default
    }

    debugs(93, 5, HERE << "swan sang" << status());
}

void ICAPInitiate::clearInitiator()
{
    if (theInitiator)
        theInitiator.clear();
}

void ICAPInitiate::sendAnswer(HttpMsg *msg)
{
    assert(msg);
    CallJob(93, 5, __FILE__, __LINE__, "ICAPInitiator::noteIcapAnswer",
        IcapAnswerDialer(theInitiator.ptr, &ICAPInitiator::noteIcapAnswer, msg));
    clearInitiator();
}


void ICAPInitiate::tellQueryAborted(bool final)
{
    CallJobHere1(93, 5, theInitiator.ptr, ICAPInitiator::noteIcapQueryAbort, final);
    clearInitiator();
}

ICAPServiceRep &ICAPInitiate::service()
{
    assert(theService != NULL);
    return *theService;
}

const char *ICAPInitiate::status() const {
    return ""; // for now
}


/* ICAPInitiatorHolder */

ICAPInitiatorHolder::ICAPInitiatorHolder(ICAPInitiator *anInitiator):
    ptr(0), cbdata(0)
{
    if (anInitiator) {
        cbdata = cbdataReference(anInitiator->toCbdata());
        ptr = anInitiator;
    }
}

ICAPInitiatorHolder::ICAPInitiatorHolder(const ICAPInitiatorHolder &anInitiator):
    ptr(0), cbdata(0)
{
    if (anInitiator != NULL && cbdataReferenceValid(anInitiator.cbdata)) {
        cbdata = cbdataReference(anInitiator.cbdata);
        ptr = anInitiator.ptr;
    }
}

ICAPInitiatorHolder::~ICAPInitiatorHolder()
{
    clear();
}

void ICAPInitiatorHolder::clear() {
    if (ptr) {
        ptr = NULL;
        cbdataReferenceDone(cbdata);
    }
}

// should not be used
ICAPInitiatorHolder &ICAPInitiatorHolder::operator =(const ICAPInitiatorHolder &anInitiator)
{
    assert(false);
    return *this;
}
