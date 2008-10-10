/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "TextException.h"
#include "HttpMsg.h"
#include "ICAPLauncher.h"
#include "ICAPXaction.h"
#include "ICAPServiceRep.h"


ICAPLauncher::ICAPLauncher(const char *aTypeName,
                           Adaptation::Initiator *anInitiator, Adaptation::ServicePointer &aService):
        AsyncJob(aTypeName),
        Adaptation::Initiate(aTypeName, anInitiator, aService),
        theXaction(0), theLaunches(0)
{
}

ICAPLauncher::~ICAPLauncher()
{
    assert(!theXaction);
}

void ICAPLauncher::start()
{
    Adaptation::Initiate::start();

    Must(theInitiator);
    launchXaction(false);
}

void ICAPLauncher::launchXaction(bool final)
{
    Must(!theXaction);
    ++theLaunches;
    debugs(93,4, HERE << "launching xaction #" << theLaunches);
    ICAPXaction *x = createXaction();
    if (final)
        x->disableRetries();
    theXaction = initiateAdaptation(x);
    Must(theXaction);
}

void ICAPLauncher::noteAdaptationAnswer(HttpMsg *message)
{
    sendAnswer(message);
    clearAdaptation(theXaction);
    Must(done());
    debugs(93,3, HERE << "ICAPLauncher::noteAdaptationAnswer exiting ");
}

void ICAPLauncher::noteInitiatorAborted()
{

    announceInitiatorAbort(theXaction); // propogate to the transaction
    clearInitiator();
    Must(done()); // should be nothing else to do

}

void ICAPLauncher::noteAdaptationQueryAbort(bool final)
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

bool ICAPLauncher::doneAll() const
{
    return (!theInitiator || !theXaction) && Adaptation::Initiate::doneAll();
}

void ICAPLauncher::swanSong()
{
    if (theInitiator)
        tellQueryAborted(!service().cfg().bypass);

    if (theXaction)
        clearAdaptation(theXaction);

    Adaptation::Initiate::swanSong();
}
