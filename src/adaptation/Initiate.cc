/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    ICAP (RFC 3507) Client */

#include "squid.h"
#include "adaptation/Answer.h"
#include "adaptation/Initiate.h"
#include "adaptation/Initiator.h"
#include "base/AsyncJobCalls.h"
#include "http/Message.h"

namespace Adaptation
{
typedef UnaryMemFunT<Initiator, Answer, const Answer &> AnswerDialer;
/// Calls expectNoConsumption() if noteAdaptationAnswer async call is
/// scheduled but never fired (e.g., because the HTTP transaction aborts).
class AnswerCall: public AsyncCallT<AnswerDialer>
{
public:
    AnswerCall(const char *aName, const AnswerDialer &aDialer) :
        AsyncCallT<AnswerDialer>(93, 5, aName, aDialer), fired(false) {}
    void fire() override {
        fired = true;
        AsyncCallT<AnswerDialer>::fire();
    }
    ~AnswerCall() override {
        if (!fired && dialer.arg1.message != nullptr && dialer.arg1.message->body_pipe != nullptr)
            dialer.arg1.message->body_pipe->expectNoConsumption();
    }

private:
    bool fired; ///< whether we fired the call
};
}

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
    debugs(93, 5, "swan sings" << status());

    if (theInitiator.set()) {
        debugs(93, 3, "fatal failure; sending abort notification");
        tellQueryAborted(true); // final by default
    }

    debugs(93, 5, "swan sang" << status());
}

void Adaptation::Initiate::clearInitiator()
{
    theInitiator.clear();
}

void Adaptation::Initiate::sendAnswer(const Answer &answer)
{
    AsyncCall::Pointer call = new AnswerCall("Initiator::noteAdaptationAnswer",
            AnswerDialer(theInitiator, &Initiator::noteAdaptationAnswer, answer));
    ScheduleCallHere(call);
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

