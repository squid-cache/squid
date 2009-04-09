/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "TextException.h"
#include "HttpMsg.h"
#include "adaptation/icap/Launcher.h"
#include "adaptation/icap/Xaction.h"
#include "adaptation/icap/ServiceRep.h"


Adaptation::Icap::Launcher::Launcher(const char *aTypeName,
                                     Adaptation::Initiator *anInitiator, Adaptation::ServicePointer &aService):
        AsyncJob(aTypeName),
        Adaptation::Initiate(aTypeName, anInitiator, aService),
        theXaction(0), theLaunches(0)
{
}

Adaptation::Icap::Launcher::~Launcher()
{
    assert(!theXaction);
}

void Adaptation::Icap::Launcher::start()
{
    Adaptation::Initiate::start();

    Must(theInitiator);
    launchXaction(false);
}

void Adaptation::Icap::Launcher::launchXaction(bool final)
{
    Must(!theXaction);
    ++theLaunches;
    debugs(93,4, HERE << "launching xaction #" << theLaunches);
    Adaptation::Icap::Xaction *x = createXaction();
    if (final)
        x->disableRetries();
    theXaction = initiateAdaptation(x);
    Must(theXaction);
}

void Adaptation::Icap::Launcher::noteAdaptationAnswer(HttpMsg *message)
{
    sendAnswer(message);
    clearAdaptation(theXaction);
    Must(done());
    debugs(93,3, HERE << "Adaptation::Icap::Launcher::noteAdaptationAnswer exiting ");
}

void Adaptation::Icap::Launcher::noteInitiatorAborted()
{

    announceInitiatorAbort(theXaction); // propogate to the transaction
    clearInitiator();
    Must(done()); // should be nothing else to do

}

void Adaptation::Icap::Launcher::noteAdaptationQueryAbort(bool final)
{
    clearAdaptation(theXaction);

    // TODO: add more checks from FwdState::checkRetry()?
    if (!final && theLaunches < 2 && !shutting_down) {
        launchXaction(true);
    } else {
        debugs(93,3, HERE << "cannot retry the failed ICAP xaction; tries: " <<
               theLaunches << "; final: " << final);
        Must(done()); // swanSong will notify the initiator
    }

}

bool Adaptation::Icap::Launcher::doneAll() const
{
    return (!theInitiator || !theXaction) && Adaptation::Initiate::doneAll();
}

void Adaptation::Icap::Launcher::swanSong()
{
    if (theInitiator)
        tellQueryAborted(!service().cfg().bypass);

    if (theXaction)
        clearAdaptation(theXaction);

    Adaptation::Initiate::swanSong();
}
