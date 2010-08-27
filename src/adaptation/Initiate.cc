/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "HttpMsg.h"
#include "adaptation/Initiator.h"
#include "adaptation/Initiate.h"
#include "base/AsyncJobCalls.h"

namespace Adaptation
{

// AdaptInitiator::noteAdaptionAnswer Dialer locks/unlocks the message in transit
// TODO: replace HTTPMSGLOCK with general RefCounting and delete this class
class AnswerDialer: public UnaryMemFunT<Initiator, HttpMsg*>
{
public:
    typedef UnaryMemFunT<Initiator, HttpMsg*> Parent;

    AnswerDialer(const Parent::JobPointer &job, Parent::Method meth,
                 HttpMsg *msg): Parent(job, meth, msg) { HTTPMSGLOCK(arg1); }
    AnswerDialer(const AnswerDialer &d): Parent(d) { HTTPMSGLOCK(arg1); }
    virtual ~AnswerDialer() { HTTPMSGUNLOCK(arg1); }

private:
    AnswerDialer &operator =(const AnswerDialer &); // not implemented
};

} // namespace Adaptation


/* Initiate */

Adaptation::Initiate::Initiate(const char *aTypeName): AsyncJob(aTypeName)
{
}

Adaptation::Initiate::~Initiate()
{
    // TODO: we cannot assert(!theInitiator) because that fails if a child
    // constructor fails. AsyncJob should have wasStarted flag so that we
    // can assert(!(wasStarted && theInitiator)).
}

void
Adaptation::Initiate::initiator(const CbcPointer<Initiator> &i)
{
    Must(!theInitiator);
    Must(i.valid());
    theInitiator = i;
}


// internal cleanup
void Adaptation::Initiate::swanSong()
{
    debugs(93, 5, HERE << "swan sings" << status());

    if (theInitiator.set()) {
        debugs(93, 3, HERE << "fatal failure; sending abort notification");
        tellQueryAborted(true); // final by default
    }

    debugs(93, 5, HERE << "swan sang" << status());
}

void Adaptation::Initiate::clearInitiator()
{
    theInitiator.clear();
}

void Adaptation::Initiate::sendAnswer(HttpMsg *msg)
{
    assert(msg);
    CallJob(93, 5, __FILE__, __LINE__, "Initiator::noteAdaptationAnswer",
            AnswerDialer(theInitiator, &Initiator::noteAdaptationAnswer, msg));
    clearInitiator();
}


void Adaptation::Initiate::tellQueryAborted(bool final)
{
    CallJobHere1(93, 5, theInitiator,
                 Initiator, noteAdaptationQueryAbort, final);
    clearInitiator();
}

const char *Adaptation::Initiate::status() const
{
    return AsyncJob::status(); // for now
}
