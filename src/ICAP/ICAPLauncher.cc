/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "TextException.h"
#include "HttpMsg.h"
#include "ICAPLauncher.h"
#include "ICAPXaction.h"


ICAPLauncher::ICAPLauncher(const char *aTypeName, ICAPInitiator *anInitiator, ICAPServiceRep::Pointer &aService):AsyncJob(aTypeName),
    ICAPInitiate(aTypeName, anInitiator, aService),
    theXaction(0), theLaunches(0)
{
}

ICAPLauncher::~ICAPLauncher()
{
    assert(!theXaction);
}

void ICAPLauncher::start()
{
    ICAPInitiate::start();

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
    theXaction = initiateIcap(x);
    Must(theXaction);
}

void ICAPLauncher::noteIcapAnswer(HttpMsg *message)
{
    sendAnswer(message);
    clearIcap(theXaction);
    Must(done());
    debugs(93,3, HERE << "ICAPLauncher::noteIcapAnswer exiting "); 
}

void ICAPLauncher::noteInitiatorAborted()
{

    announceInitiatorAbort(theXaction); // propogate to the transaction
    clearInitiator();
    Must(done()); // should be nothing else to do

}

void ICAPLauncher::noteIcapQueryAbort(bool final)
{
    clearIcap(theXaction);

    // TODO: add more checks from FwdState::checkRetry()?
    if (!final && theLaunches < 2 && !shutting_down) {
        launchXaction(true);
    } else {
        debugs(93,3, HERE << "cannot retry the failed ICAP xaction; tries: " <<
            theLaunches << "; final: " << final);
        Must(done()); // swanSong will notify the initiator
    }

}

bool ICAPLauncher::doneAll() const {
    return (!theInitiator || !theXaction) && ICAPInitiate::doneAll();
}

void ICAPLauncher::swanSong()
{
    if (theInitiator)
        tellQueryAborted(!service().bypass);

    if (theXaction)
        clearIcap(theXaction);

    ICAPInitiate::swanSong();
}
