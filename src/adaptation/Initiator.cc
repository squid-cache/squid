/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    ICAP (RFC 3507) Client */

#include "squid.h"
#include "adaptation/Initiate.h"
#include "adaptation/Initiator.h"
#include "base/AsyncJobCalls.h"

void
Adaptation::Initiator::noteAdaptationAclCheckDone(Adaptation::ServiceGroupPointer)
{
    Must(false);
}

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

