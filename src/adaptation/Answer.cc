/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    ICAP (RFC 3507) Client */

#include "squid.h"
#include "adaptation/Answer.h"
#include "base/AsyncJobCalls.h"

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

