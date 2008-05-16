#include "squid.h"
#include <libecap/adapter/xaction.h>
#include "TextException.h"
#include "assert.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "eCAP/XactionRep.h"

// CBDATA_CLASS_INIT(Ecap::XactionRep);
// TODO: add CBDATA_NAMESPACED_CLASS_INIT(namespace, classname)
cbdata_type Ecap::XactionRep::CBDATA_XactionRep = CBDATA_UNKNOWN;


Ecap::XactionRep::XactionRep(Adaptation::Initiator *anInitiator,
    HttpMsg *virginHeader, HttpRequest *virginCause,
    const Adaptation::ServicePointer &aService):
    AsyncJob("Ecap::XactionRep"),
    Adaptation::Initiate("Ecap::XactionRep", anInitiator, aService),
    theVirgin(virginHeader), theCause(virginCause),
    theVirginRep(theVirgin, NULL), theCauseRep(NULL),
    theAnswerRep(NULL)
{
    if (virginCause)
        theCauseRep = new MessageRep(theCause, NULL);
}

Ecap::XactionRep::~XactionRep()
{
    assert(!theMaster);
    delete theCauseRep;
    delete theAnswerRep;
}

void
Ecap::XactionRep::master(const AdapterXaction &x)
{
    Must(!theMaster);
    Must(x != NULL);
    theMaster = x;
}

void
Ecap::XactionRep::start()
{
    Must(theMaster);
    theMaster->start();
}

void
Ecap::XactionRep::swangSong()
{
    terminateMaster();
    Adaptation::Initiate::swanSong();
}

void
Ecap::XactionRep::terminateMaster()
{
    if (theMaster) {
        AdapterXaction x = theMaster;
        theMaster.reset();
        x->stop();
	}
}

libecap::Message &
Ecap::XactionRep::virgin()
{
    return theVirginRep;
}

const libecap::Message *
Ecap::XactionRep::cause()
{
    return theCauseRep;
}

void 
Ecap::XactionRep::useVirgin()
{
    theMaster.reset();
    Adaptation::Message::ShortCircuit(theVirgin, theAnswer);
    Must(!theVirgin.body_pipe == !theAnswer.body_pipe);
    sendAnswer(theAnswer.header);
}

void 
Ecap::XactionRep::adaptVirgin()
{
    // XXX: check state everywhere
    Must(!theAnswerRep);
    Must(!theAnswer.header);
    Must(!theAnswer.body_pipe);
    theAnswer.set(theVirgin.header->clone());
	theAnswerRep = new MessageRep(theAnswer, this);
    Must(!theAnswer.body_pipe);
}

void 
Ecap::XactionRep::adaptNewRequest()
{
    theAnswer.set(new HttpRequest);
	theAnswerRep = new MessageRep(theAnswer, this);
}

void 
Ecap::XactionRep::adaptNewResponse()
{
    theAnswer.set(new HttpReply);
	theAnswerRep = new MessageRep(theAnswer, this);
}

libecap::Message *
Ecap::XactionRep::adapted()
{
    return theAnswerRep;
}

void 
Ecap::XactionRep::useAdapted()
{
    theMaster.reset();
    sendAnswer(theAnswer.header);
}

void 
Ecap::XactionRep::useNone()
{
    theMaster.reset();
    tellQueryAborted(true); // should eCAP support retries?
}

void 
Ecap::XactionRep::noteMoreBodySpaceAvailable(RefCount<BodyPipe> bp)
{
    Must(theMaster);
    theMaster->noteAdaptedSpaceAvailable();
}

void 
Ecap::XactionRep::noteBodyConsumerAborted(RefCount<BodyPipe> bp)
{
    Must(theMaster);
    theMaster->noteAdaptedAborted();
}

void
Ecap::XactionRep::noteMoreBodyDataAvailable(RefCount<BodyPipe> bp)
{
    Must(theMaster);
    theMaster->noteVirginDataAvailable();
}

void
Ecap::XactionRep::noteBodyProductionEnded(RefCount<BodyPipe> bp)
{
    Must(theMaster);
    theMaster->noteVirginDataEnded();
}

void
Ecap::XactionRep::noteBodyProducerAborted(RefCount<BodyPipe> bp)
{
    Must(theMaster);
    theMaster->noteVirginAborted();
}

void
Ecap::XactionRep::noteInitiatorAborted()
{
    mustStop("initiator aborted");
}

const char *Ecap::XactionRep::status() const
{
	return Adaptation::Initiate::status();
}
