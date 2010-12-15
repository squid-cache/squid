/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "adaptation/Initiate.h"
#include "adaptation/Initiator.h"
#include "base/AsyncJobCalls.h"

CbcPointer<Adaptation::Initiate>
Adaptation::Initiator::initiateAdaptation(Initiate *x)
{
    CbcPointer<Initiate> i(x);
    x->initiator(this);
    Start(x);
    return i;
}

void
Adaptation::Initiator::clearAdaptation(CbcPointer<Initiate> &x)
{
    x.clear();
}

void
Adaptation::Initiator::announceInitiatorAbort(CbcPointer<Initiate> &x)
{
    CallJobHere(93, 5, x, Initiate, noteInitiatorAborted);
    clearAdaptation(x);
}


/* Adaptation::Answer */

// TODO: Move to src/adaptation/Answer.*

Adaptation::Answer
Adaptation::Answer::Error(bool final)
{
    Answer answer(akError);
    answer.final = final;
    debugs(93, 4, HERE << "error: " << final);
    return answer;
}

Adaptation::Answer
Adaptation::Answer::Forward(HttpMsg *aMsg)
{
    Answer answer(akForward);
    answer.message = aMsg;
    debugs(93, 4, HERE << "forwarding: " << (void*)aMsg);
    return answer;
}


Adaptation::Answer
Adaptation::Answer::Block(const String &aRule)
{
    Answer answer(akBlock);
    answer.ruleId = aRule;
    debugs(93, 4, HERE << "blocking rule: " << aRule);
    return answer;
}

std::ostream &
Adaptation::Answer::print(std::ostream &os) const
{
    return os << kind; // TODO: add more details
}

Adaptation::Answer::Answer(Kind aKind): final(true), kind(aKind)
{
}
