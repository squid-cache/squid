/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "HttpMsg.h"
#include "ICAPInitiator.h"
#include "ICAPInitiate.h"

/* The call objects below are not cbdata-protected or refcounted because 
 * nobody holds a pointer to them except for the event queue. 
 *
 * The calls do check the Initiator pointer to see if that is still valid.
 *
 * TODO: convert this to a generic AsyncCall1 class 
 * TODO: mempool kids of this class.
 */

/* Event data and callback wrapper to call noteIcapAnswer with
 * the answer message as a parameter. 
 */
class ICAPAnswerCall {
public:
    // use this function to make an asynchronous call
    static void Schedule(const ICAPInitiatorHolder &anInitiator, HttpMsg *aMessage);

    static void Wrapper(void *data);

protected:
    ICAPAnswerCall(const ICAPInitiatorHolder &anInitiator, HttpMsg *aMessage);
    ~ICAPAnswerCall();

    void schedule();
    void call();

    ICAPInitiatorHolder theInitiator;
    HttpMsg *theMessage;
};


/* Event data and callback wrapper to call noteIcapQueryAbort with
 * the termination status as a parameter. 
 *
 * XXX: This class is a clone of ICAPAnswerCall.
 */
class ICAPQueryAbortCall {
public:
    // use this function to make an asynchronous call
    static void Schedule(const ICAPInitiatorHolder &anInitiator, bool beFinal);

    static void Wrapper(void *data);

protected:
    ICAPQueryAbortCall(const ICAPInitiatorHolder &anInitiator, bool beFinal);

    void schedule();
    void call();

    ICAPInitiatorHolder theInitiator;
    bool isFinal;
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
    ICAPAnswerCall::Schedule(theInitiator, msg);
    clearInitiator();
}

void ICAPInitiate::tellQueryAborted(bool final)
{
    ICAPQueryAbortCall::Schedule(theInitiator, final);
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

/* ICAPAnswerCall */

ICAPAnswerCall::ICAPAnswerCall(const ICAPInitiatorHolder &anInitiator, HttpMsg *aMessage):
    theInitiator(anInitiator), theMessage(0)
{
    if (theInitiator) {
        assert(aMessage);
        theMessage = HTTPMSGLOCK(aMessage);
    }
}

void ICAPAnswerCall::schedule()
{
    if (theInitiator) {
        debugs(93,3, __FILE__ << "(" << __LINE__ << ") will call " << 
            theInitiator << "->ICAPInitiator::noteIcapAnswer(" <<
            theMessage << ")");
        eventAdd("ICAPInitiator::noteIcapAnswer",
            &ICAPAnswerCall::Wrapper, this, 0.0, 0, false);
    } else {
        debugs(93,3, __FILE__ << "(" << __LINE__ << ") will not call " <<
            theInitiator << "->ICAPInitiator::noteIcapAnswer(" <<
            theMessage << ")");
    }
}

ICAPAnswerCall::~ICAPAnswerCall()
{
    if (theInitiator)
        HTTPMSGUNLOCK(theMessage);
}

void ICAPAnswerCall::Wrapper(void *data)
{
    assert(data);
    ICAPAnswerCall *c = static_cast<ICAPAnswerCall*>(data);
    c->call();
    delete c;
}

void ICAPAnswerCall::call() {
    assert(theInitiator);
    if (cbdataReferenceValid(theInitiator.cbdata)) {
        debugs(93, 3, "entering " <<
            theInitiator << "->ICAPInitiator::noteIcapAnswer(" <<
            theMessage << ")");
        theInitiator.ptr->noteIcapAnswer(theMessage);
        debugs(93, 3, "exiting " <<
            theInitiator << "->ICAPInitiator::noteIcapAnswer(" <<
            theMessage << ")");
    } else {
        debugs(93, 3, "ignoring " <<
            theInitiator << "->ICAPInitiator::noteIcapAnswer(" <<
            theMessage << ")");
    }
}

void ICAPAnswerCall::Schedule(const ICAPInitiatorHolder &anInitiator, HttpMsg *aMessage)
{
    ICAPAnswerCall *call = new ICAPAnswerCall(anInitiator, aMessage);
    call->schedule();
	// The call object is deleted in ICAPAnswerCall::Wrapper
}


/* ICAPQueryAbortCall */

ICAPQueryAbortCall::ICAPQueryAbortCall(const ICAPInitiatorHolder &anInitiator, bool beFinal):
    theInitiator(anInitiator), isFinal(beFinal)
{
}

void ICAPQueryAbortCall::schedule()
{
    if (theInitiator) {
        debugs(93,3, __FILE__ << "(" << __LINE__ << ") will call " << 
            theInitiator << "->ICAPInitiator::noteIcapQueryAbort(" <<
            isFinal << ")");
        eventAdd("ICAPInitiator::noteIcapQueryAbort",
            &ICAPQueryAbortCall::Wrapper, this, 0.0, 0, false);
    } else {
        debugs(93,3, __FILE__ << "(" << __LINE__ << ") will not call " <<
            theInitiator << "->ICAPInitiator::noteIcapQueryAbort(" <<
            isFinal << ")");
    }
}

void ICAPQueryAbortCall::Wrapper(void *data)
{
    assert(data);
    ICAPQueryAbortCall *c = static_cast<ICAPQueryAbortCall*>(data);
    c->call();
    delete c;
}

void ICAPQueryAbortCall::call() {
    assert(theInitiator);
    if (cbdataReferenceValid(theInitiator.cbdata)) {
        debugs(93, 3, "entering " <<
            theInitiator << "->ICAPInitiator::noteIcapQueryAbort(" <<
            isFinal << ")");
        theInitiator.ptr->noteIcapQueryAbort(isFinal);
        debugs(93, 3, "exiting " <<
            theInitiator << "->ICAPInitiator::noteIcapQueryAbort(" <<
            isFinal << ")");
    } else {
        debugs(93, 3, "ignoring " <<
            theInitiator << "->ICAPInitiator::noteIcapQueryAbort(" <<
            isFinal << ")");
    }
}

void ICAPQueryAbortCall::Schedule(const ICAPInitiatorHolder &anInitiator, bool beFinal)
{
    ICAPQueryAbortCall *call = new ICAPQueryAbortCall(anInitiator, beFinal);
    call->schedule();
    // The call object is deleted in ICAPQueryAbortCall::Wrapper
}
