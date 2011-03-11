/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "HttpMsg.h"
#include "adaptation/Answer.h"
#include "adaptation/Initiator.h"
#include "adaptation/Initiate.h"
#include "base/AsyncJobCalls.h"


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

void Adaptation::Initiate::sendAnswer(const Answer &answer)
{
    typedef UnaryMemFunT<Initiator, Answer, const Answer &> MyDialer;
    CallJob(93, 5, __FILE__, __LINE__, "Initiator::noteAdaptationAnswer",
            MyDialer(theInitiator, &Initiator::noteAdaptationAnswer, answer));
    clearInitiator();
}


void Adaptation::Initiate::tellQueryAborted(bool final)
{
    sendAnswer(Answer::Error(final));
}

const char *Adaptation::Initiate::status() const
{
    return AsyncJob::status(); // for now
}
