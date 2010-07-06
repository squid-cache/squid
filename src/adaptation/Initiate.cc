/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "HttpMsg.h"
#include "adaptation/Initiator.h"
#include "adaptation/Initiate.h"

namespace Adaptation
{

// AdaptInitiator::noteAdaptionAnswer Dialer locks/unlocks the message in transit
// TODO: replace HTTPMSGLOCK with general RefCounting and delete this class
class AnswerDialer: public UnaryMemFunT<Initiator, HttpMsg*>
{
public:
    typedef UnaryMemFunT<Initiator, HttpMsg*> Parent;

    AnswerDialer(Initiator *obj, Parent::Method meth, HttpMsg *msg):
            Parent(obj, meth, msg) { HTTPMSGLOCK(arg1); }
    AnswerDialer(const AnswerDialer &d):
            Parent(d) { HTTPMSGLOCK(arg1); }
    virtual ~AnswerDialer() { HTTPMSGUNLOCK(arg1); }
};

} // namespace Adaptation


/* Initiate */

Adaptation::Initiate::Initiate(const char *aTypeName, Initiator *anInitiator):
        AsyncJob(aTypeName), theInitiator(anInitiator)
{
    assert(theInitiator);
}

Adaptation::Initiate::~Initiate()
{
    // TODO: we cannot assert(!theInitiator) because that fails if a child
    // constructor fails. AsyncJob should have wasStarted flag so that we
    // can assert(!(wasStarted && theInitiator)).
}

// internal cleanup
void Adaptation::Initiate::swanSong()
{
    debugs(93, 5, HERE << "swan sings" << status());

    if (theInitiator) {
        debugs(93, 3, HERE << "fatal failure; sending abort notification");
        tellQueryAborted(true); // final by default
    }

    debugs(93, 5, HERE << "swan sang" << status());
}

void Adaptation::Initiate::clearInitiator()
{
    if (theInitiator)
        theInitiator.clear();
}

void Adaptation::Initiate::sendAnswer(HttpMsg *msg)
{
    assert(msg);
    if (theInitiator.isThere()) {
        CallJob(93, 5, __FILE__, __LINE__, "Initiator::noteAdaptAnswer",
                AnswerDialer(theInitiator.ptr(), &Initiator::noteAdaptationAnswer, msg));
    }
    clearInitiator();
}


void Adaptation::Initiate::tellQueryAborted(bool final)
{
    if (theInitiator.isThere()) {
        CallJobHere1(93, 5, theInitiator.ptr(),
                     Initiator::noteAdaptationQueryAbort, final);
    }
    clearInitiator();
}

const char *Adaptation::Initiate::status() const
{
    return AsyncJob::status(); // for now
}


/* InitiatorHolder */

Adaptation::InitiatorHolder::InitiatorHolder(Initiator *anInitiator):
        prime(0), cbdata(0)
{
    if (anInitiator) {
        cbdata = cbdataReference(anInitiator->toCbdata());
        prime = anInitiator;
    }
}

Adaptation::InitiatorHolder::InitiatorHolder(const InitiatorHolder &anInitiator):
        prime(0), cbdata(0)
{
    if (anInitiator != NULL && cbdataReferenceValid(anInitiator.cbdata)) {
        cbdata = cbdataReference(anInitiator.cbdata);
        prime = anInitiator.prime;
    }
}

Adaptation::InitiatorHolder::~InitiatorHolder()
{
    clear();
}

void Adaptation::InitiatorHolder::clear()
{
    if (prime) {
        prime = NULL;
        cbdataReferenceDone(cbdata);
    }
}

Adaptation::Initiator *Adaptation::InitiatorHolder::ptr()
{
    assert(isThere());
    return prime;
}

bool
Adaptation::InitiatorHolder::isThere()
{
    return prime && cbdataReferenceValid(cbdata);
}

// should not be used
Adaptation::InitiatorHolder &
Adaptation::InitiatorHolder::operator =(const InitiatorHolder &anInitiator)
{
    assert(false);
    return *this;
}
