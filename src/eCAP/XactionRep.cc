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
    // clear body_pipes, if any

    if (theAnswerRep != NULL) {
		BodyPipe::Pointer body_pipe = answer().body_pipe;
		if (body_pipe != NULL && body_pipe->stillProducing(this))
			stopProducingFor(body_pipe, false);
	}

    {
		BodyPipe::Pointer body_pipe = theVirginRep.raw().body_pipe;
		if (body_pipe != NULL && body_pipe->stillConsuming(this))
			stopConsumingFrom(body_pipe);
	}

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
        theMaster->abMake(); // libecap will produce
        sendAnswer(answer);
    }
}

void
Ecap::XactionRep::vbIgnore()
{
    // if adapter does not need vb, we do not need to send it
    if (sendingVirgin())
        dropVirgin("vbIgnore");
}

void
Ecap::XactionRep::vbMake()
{
    Must(sendingVirgin());
    theMaster->noteVbContentAvailable(); // XXX: async
}

void
Ecap::XactionRep::vbStopMaking()
{
    // if adapter does not need vb, we do not need to send it
    if (sendingVirgin())
        dropVirgin("vbIgnore");
}

void
Ecap::XactionRep::vbMakeMore()
{
    Must(sendingVirgin() && !theVirginRep.raw().body_pipe->exhausted());
}

libecap::Area
Ecap::XactionRep::vbContent(libecap::off_type o, libecap::size_type s)
{
    const BodyPipePointer &p = theVirginRep.raw().body_pipe;
    const size_t haveSize = static_cast<size_t>(p->buf().contentSize()); // TODO: make MemBuf use size_t?

    // convert to Squid types; XXX: check for overflow
    const uint64_t offset = static_cast<uint64_t>(o);
    Must(offset <= haveSize); // equal iff at the end of content

    // nsize means no size limit: all content starting from offset
    const size_t size = s == libecap::nsize ?
		haveSize - offset : static_cast<size_t>(s);

    if (!size)
        return libecap::Area();

    // XXX: optimize by making theBody a shared_ptr (see Area::FromTemp*() src)
    return libecap::Area::FromTempBuffer(p->buf().content() + offset,
		min(static_cast<size_t>(haveSize - offset), size));
}

void
Ecap::XactionRep::vbContentShift(libecap::size_type n)
{
    BodyPipePointer &p = theVirginRep.raw().body_pipe;
    Must(p != NULL);
    const size_t size = static_cast<size_t>(n); // XXX: check for overflow
    const size_t haveSize = static_cast<size_t>(p->buf().contentSize()); // TODO: make MemBuf use size_t?
    p->consume(min(size, haveSize));
}

void
Ecap::XactionRep::noteAbContentDone(bool atEnd)
{
    Must(!doneWithAdapted());
    answer().body_pipe->clearProducer(atEnd);
    if (!sendingVirgin())
        theMaster.reset();
}

void
Ecap::XactionRep::noteAbContentAvailable()
{
    moveAbContent();
}

#if 0
void
Ecap::XactionRep::setAdaptedBodySize(const libecap::BodySize &size)
{
    Must(answer().body_pipe != NULL);
    if (size.known())
        answer().body_pipe->setBodySize(size.value());
    // else the piped body size is unknown by default
}
#endif

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

bool
Ecap::XactionRep::callable() const
{
    return !done();
}

void 
Ecap::XactionRep::noteMoreBodySpaceAvailable(RefCount<BodyPipe> bp)
{
    if (!doneWithAdapted())
        moveAbContent();
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
    theMaster->noteVbContentAvailable();
}

void
Ecap::XactionRep::noteBodyProductionEnded(RefCount<BodyPipe> bp)
{
    Must(theMaster);
    theMaster->noteVbContentDone(true);
    if (doneWithAdapted())
        theMaster.reset();
}

void
Ecap::XactionRep::noteBodyProducerAborted(RefCount<BodyPipe> bp)
{
    Must(theMaster);
    theMaster->noteVbContentDone(false);
    if (doneWithAdapted())
        theMaster.reset();
}

void
Ecap::XactionRep::noteInitiatorAborted()
{
    mustStop("initiator aborted");
}

// get content from the adapter and put it into the adapted pipe
void
Ecap::XactionRep::moveAbContent()
{
    Must(!doneWithAdapted());
    const libecap::Area c = theMaster->abContent(0, libecap::nsize);
    debugs(93,5, HERE << " up to " << c.size << " bytes");
    if (const size_t used = answer().body_pipe->putMoreData(c.start, c.size))
		theMaster->abContentShift(used);
}

const char *
Ecap::XactionRep::status() const
{
    static MemBuf buf;
    buf.reset();

    buf.append(" [", 2);

    const BodyPipePointer &vp = theVirginRep.raw().body_pipe;
    if (vp != NULL && vp->stillConsuming(this)) {
		buf.append("Vb", 2);
		buf.append(vp->status(), strlen(vp->status())); // XXX
	}
    else
		buf.append("V.", 2);

    if (theAnswerRep != NULL) {
		MessageRep *answer = dynamic_cast<MessageRep*>(theAnswerRep.get());
		Must(answer);
		const BodyPipePointer &ap = answer->raw().body_pipe;
		if (ap != NULL && ap->stillProducing(this)) {
			buf.append(" Ab", 3);
			buf.append(ap->status(), strlen(ap->status())); // XXX
		}
        else
			buf.append(" A.", 3);
	}

    buf.Printf(" ecapx%d]", id);

    buf.terminate();

    return buf.content();
}
