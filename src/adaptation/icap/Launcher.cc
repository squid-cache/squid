/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    ICAP (RFC 3507) Client */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "adaptation/Answer.h"
#include "adaptation/icap/Config.h"
#include "adaptation/icap/Launcher.h"
#include "adaptation/icap/ServiceRep.h"
#include "adaptation/icap/Xaction.h"
#include "base/TextException.h"
#include "globals.h"
#include "HttpMsg.h"
#include "HttpReply.h"
#include "HttpRequest.h"

Adaptation::Icap::Launcher::Launcher(const char *aTypeName,
                                     Adaptation::ServicePointer &aService):
    AsyncJob(aTypeName),
    Adaptation::Initiate(aTypeName),
    theService(aService), theXaction(0), theLaunches(0)
{
}

Adaptation::Icap::Launcher::~Launcher()
{
    assert(!theXaction);
}

void Adaptation::Icap::Launcher::start()
{
    Adaptation::Initiate::start();

    Must(theInitiator.set());
    launchXaction("first");
}

void Adaptation::Icap::Launcher::launchXaction(const char *xkind)
{
    Must(!theXaction);
    ++theLaunches;
    debugs(93,4, HERE << "launching " << xkind << " xaction #" << theLaunches);
    Adaptation::Icap::Xaction *x = createXaction();
    x->attempts = theLaunches;
    if (theLaunches > 1) {
        x->clearError();
        x->disableRetries();
    }
    if (theLaunches >= TheConfig.repeat_limit)
        x->disableRepeats("over icap_retry_limit");
    theXaction = initiateAdaptation(x);
    Must(initiated(theXaction));
}

void Adaptation::Icap::Launcher::noteAdaptationAnswer(const Answer &answer)
{
    debugs(93,5, HERE << "launches: " << theLaunches << " answer: " << answer);

    // XXX: akError is unused by ICAPXaction in favor of noteXactAbort()
    Must(answer.kind != Answer::akError);

    sendAnswer(answer);
    clearAdaptation(theXaction);
    Must(done());
}

void Adaptation::Icap::Launcher::noteInitiatorAborted()
{

    announceInitiatorAbort(theXaction); // propogate to the transaction
    clearInitiator();
    Must(done()); // should be nothing else to do

}

void Adaptation::Icap::Launcher::noteXactAbort(XactAbortInfo info)
{
    debugs(93,5, HERE << "theXaction:" << theXaction << " launches: " << theLaunches);

    // TODO: add more checks from FwdState::checkRetry()?
    if (canRetry(info)) {
        clearAdaptation(theXaction);
        launchXaction("retry");
    } else if (canRepeat(info)) {
        clearAdaptation(theXaction);
        launchXaction("repeat");
    } else {
        debugs(93,3, HERE << "cannot retry or repeat a failed transaction");
        clearAdaptation(theXaction);
        tellQueryAborted(false); // caller decides based on bypass, consumption
        Must(done());
    }
}

bool Adaptation::Icap::Launcher::doneAll() const
{
    return (!theInitiator || !theXaction) && Adaptation::Initiate::doneAll();
}

void Adaptation::Icap::Launcher::swanSong()
{
    if (theInitiator.set())
        tellQueryAborted(true); // always final here because abnormal

    if (theXaction.set())
        clearAdaptation(theXaction);

    Adaptation::Initiate::swanSong();
}

bool Adaptation::Icap::Launcher::canRetry(Adaptation::Icap::XactAbortInfo &info) const
{
    // We do not check and can exceed zero repeat limit when retrying.
    // This is by design as the limit does not apply to pconn retrying.
    return !shutting_down && info.isRetriable;
}

bool Adaptation::Icap::Launcher::canRepeat(Adaptation::Icap::XactAbortInfo &info) const
{
    debugs(93,9, HERE << shutting_down);
    if (theLaunches >= TheConfig.repeat_limit || shutting_down)
        return false;

    debugs(93,9, HERE << info.isRepeatable); // TODO: update and use status()
    if (!info.isRepeatable)
        return false;

    debugs(93,9, HERE << info.icapReply);
    if (!info.icapReply) // did not get to read an ICAP reply; a timeout?
        return true;

    debugs(93,9, info.icapReply->sline.status());
    // XXX: Http::scNone is not the only sign of parse error
    // XXX: if there is a specific HTTP error code describing the problem, that may be set
    if (info.icapReply->sline.status() == Http::scNone) // failed to parse the reply; I/O err
        return true;

    ACLFilledChecklist *cl =
        new ACLFilledChecklist(TheConfig.repeat, info.icapRequest, dash_str);
    cl->reply = info.icapReply;
    HTTPMSGLOCK(cl->reply);

    bool result = cl->fastCheck() == ACCESS_ALLOWED;
    delete cl;
    return result;
}

/* ICAPXactAbortInfo */

Adaptation::Icap::XactAbortInfo::XactAbortInfo(HttpRequest *anIcapRequest,
        HttpReply *anIcapReply, bool beRetriable, bool beRepeatable):
    icapRequest(anIcapRequest),
    icapReply(anIcapReply),
    isRetriable(beRetriable),
    isRepeatable(beRepeatable)
{
    if (icapRequest)
        HTTPMSGLOCK(icapRequest);
    if (icapReply)
        HTTPMSGLOCK(icapReply);
}

Adaptation::Icap::XactAbortInfo::XactAbortInfo(const Adaptation::Icap::XactAbortInfo &i):
    icapRequest(i.icapRequest),
    icapReply(i.icapReply),
    isRetriable(i.isRetriable),
    isRepeatable(i.isRepeatable)
{
    if (icapRequest)
        HTTPMSGLOCK(icapRequest);
    if (icapReply)
        HTTPMSGLOCK(icapReply);
}

Adaptation::Icap::XactAbortInfo::~XactAbortInfo()
{
    HTTPMSGUNLOCK(icapRequest);
    HTTPMSGUNLOCK(icapReply);
}

