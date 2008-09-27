#include "squid.h"
#include <libecap/common/area.h>
#include <libecap/common/delay.h>
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
    theVirginRep(virginHeader), theCauseRep(NULL)
{
    if (virginCause)
        theCauseRep = new MessageRep(virginCause);
}

Ecap::XactionRep::~XactionRep()
{
    assert(!theMaster);
    delete theCauseRep;
    theAnswerRep.reset();
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

    // register as a consumer if there is a body
    // we do not actually consume unless the adapter tells us to
    BodyPipePointer &p = theVirginRep.raw().body_pipe;
    Must(!p || p->setConsumerIfNotLate(this));

    theMaster->start();
}

void
Ecap::XactionRep::swanSong()
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

const libecap::Message &
Ecap::XactionRep::cause()
{
    Must(theCauseRep != NULL);
    return *theCauseRep;
}

libecap::Message &
Ecap::XactionRep::adapted()
{
    Must(theAnswerRep != NULL);
    return *theAnswerRep;
}

Adaptation::Message &
Ecap::XactionRep::answer()
{
	MessageRep *rep = dynamic_cast<MessageRep*>(theAnswerRep.get());
	Must(rep);
    return rep->raw();
}

bool
Ecap::XactionRep::doneAll() const
{
    if (theMaster) {
        if (!doneWithAdapted() || sendingVirgin())
            return false;
	}   

    return Adaptation::Initiate::doneAll();
}

// are we still sending virgin body to theMaster?
bool
Ecap::XactionRep::doneWithAdapted() const
{
    if (!theAnswerRep)
        return false;

    // we are not done if we are producing
    MessageRep *answer = dynamic_cast<MessageRep*>(theAnswerRep.get());
	Must(answer);
    const BodyPipePointer &ap = answer->raw().body_pipe;
    return !ap || !ap->stillProducing(this);
}

// are we still sending virgin body to theMaster?
bool
Ecap::XactionRep::sendingVirgin() const
{
    // we are sending if we are consuming
    const BodyPipePointer &vp = theVirginRep.raw().body_pipe;
    return vp != NULL && vp->stillConsuming(this);
}

// stops sending virgin to theMaster and enables auto-consumption
void
Ecap::XactionRep::dropVirgin(const char *reason)
{
    debugs(93,4, HERE << "because " << reason);

    BodyPipePointer &p = theVirginRep.raw().body_pipe;
    Must(p != NULL);
    Must(p->stillConsuming(this));
    stopConsumingFrom(p);
    p->enableAutoConsumption();
    if (doneWithAdapted())
        theMaster.reset();
}

void 
Ecap::XactionRep::useVirgin()
{
    debugs(93,3, HERE << status());

    // XXX: check state everywhere
    Must(!theAnswerRep);
    theMaster.reset();

	HttpMsg *answer = theVirginRep.raw().header->clone();
	Must(!theVirginRep.raw().body_pipe == !answer->body_pipe); // check clone()

	if (answer->body_pipe != NULL) {
        // if libecap consumed, we cannot shortcircuit
        Must(!answer->body_pipe->consumedSize());
        Must(answer->body_pipe->stillConsuming(this));
		stopConsumingFrom(answer->body_pipe);
    }

	sendAnswer(answer);
    Must(done());
}

void 
Ecap::XactionRep::useAdapted(const libecap::shared_ptr<libecap::Message> &m)
{
    debugs(93,3, HERE << status());
    theAnswerRep = m;
	MessageRep *rep = dynamic_cast<MessageRep*>(theAnswerRep.get());
	Must(rep);
	HttpMsg *answer = rep->raw().header;
    if (!theAnswerRep->body()) {
        if (!sendingVirgin())
            theMaster.reset();
        sendAnswer(answer);
	} else {
		Must(!answer->body_pipe); // only host can set body pipes
		rep->tieBody(this);
        debugs(93,4, HERE << "adapter will produce body" << status());
        // libecap will produce
        sendAnswer(answer);
    }
}

// if adapter does not want to consume, we should not either
void
Ecap::XactionRep::adapterWontConsume()
{
    if (sendingVirgin())
        dropVirgin("adapterWontConsume");
}

void
Ecap::XactionRep::adapterWillConsume()
{
    Must(sendingVirgin());
    theMaster->noteVirginDataAvailable(); // XXX: async
}

void
Ecap::XactionRep::adapterDoneConsuming()
{
    if (sendingVirgin())
        dropVirgin("adapterDoneConsuming");
}

void
Ecap::XactionRep::consumeVirgin(size_type n)
{
    BodyPipePointer &p = theVirginRep.raw().body_pipe;
    Must(p != NULL);
    const size_t size = static_cast<size_t>(n); // XXX: check for overflow
    const size_t sizeMax = static_cast<size_t>(p->buf().contentSize()); // TODO: make MemBuf use size_t?
    p->consume(min(size, sizeMax));
}

void
Ecap::XactionRep::pauseVirginProduction()
{
    // TODO: support production pauses
}

void
Ecap::XactionRep::resumeVirginProduction()
{
    // TODO: support production pauses
}

void
Ecap::XactionRep::setAdaptedBodySize(const libecap::BodySize &size)
{
    Must(answer().body_pipe != NULL);
    if (size.known())
        answer().body_pipe->setBodySize(size.value());
    // else the piped body size is unknown by default
}

void
Ecap::XactionRep::appendAdapted(const libecap::Area &area)
{
    BodyPipe *p = answer().body_pipe.getRaw();
    Must(p);
    Must(p->putMoreData(area.start, area.size) == area.size);
}

bool
Ecap::XactionRep::callable() const
{
    return !done();
}

void
Ecap::XactionRep::noteAdaptedBodyEnd()
{
    Must(answer().body_pipe != NULL);
    answer().body_pipe->clearProducer(true);
    if (!sendingVirgin())
        theMaster.reset();
}

void
Ecap::XactionRep::adaptationDelayed(const libecap::Delay &d)
{
    debugs(93,3, HERE << "adapter needs time: " <<
       d.state << '/' << d.progress);
    // XXX: set timeout?
}

void 
Ecap::XactionRep::adaptationAborted()
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
    terminateMaster();
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
    terminateMaster();
}

void
Ecap::XactionRep::noteInitiatorAborted()
{
    mustStop("initiator aborted");
}

const char *Ecap::XactionRep::status() const
{
    static MemBuf buf;
    buf.reset();

    buf.append(" [", 2);

    if (theAnswerRep != NULL) {
		MessageRep *answer = dynamic_cast<MessageRep*>(theAnswerRep.get());
		Must(answer);
		const BodyPipePointer &ap = answer->raw().body_pipe;
		if (ap != NULL && ap->stillProducing(this))
			buf.append("Ab ", 3);
        else
			buf.append("A. ", 3);
	}

    const BodyPipePointer &vp = theVirginRep.raw().body_pipe;
    if (vp != NULL && vp->stillConsuming(this))
		buf.append("Vb ", 3);
    else
		buf.append("V. ", 3);

    buf.Printf(" ecapx%d]", id);

    buf.terminate();

    return buf.content();
}
