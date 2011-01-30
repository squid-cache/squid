/*
 * DEBUG: section 93    eCAP Interface
 */
#include "squid.h"
#include <libecap/common/area.h>
#include <libecap/common/delay.h>
#include <libecap/adapter/xaction.h>
#include "TextException.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "SquidTime.h"
#include "adaptation/ecap/XactionRep.h"

CBDATA_NAMESPACED_CLASS_INIT(Adaptation::Ecap::XactionRep, XactionRep);


Adaptation::Ecap::XactionRep::XactionRep(
    HttpMsg *virginHeader, HttpRequest *virginCause,
    const Adaptation::ServicePointer &aService):
        AsyncJob("Adaptation::Ecap::XactionRep"),
        Adaptation::Initiate("Adaptation::Ecap::XactionRep"),
        theService(aService),
        theVirginRep(virginHeader), theCauseRep(NULL),
        proxyingVb(opUndecided), proxyingAb(opUndecided),
        adaptHistoryId(-1),
        canAccessVb(false),
        abProductionFinished(false), abProductionAtEnd(false)
{
    if (virginCause)
        theCauseRep = new MessageRep(virginCause);
}

Adaptation::Ecap::XactionRep::~XactionRep()
{
    assert(!theMaster);
    delete theCauseRep;
    theAnswerRep.reset();
}

void
Adaptation::Ecap::XactionRep::master(const AdapterXaction &x)
{
    Must(!theMaster);
    Must(x != NULL);
    theMaster = x;
}

Adaptation::Service &
Adaptation::Ecap::XactionRep::service()
{
    Must(theService != NULL);
    return *theService;
}

void
Adaptation::Ecap::XactionRep::start()
{
    Must(theMaster);

    if (theVirginRep.raw().body_pipe != NULL)
        canAccessVb = true; /// assumes nobody is consuming; \todo check
    else
        proxyingVb = opNever;

    const HttpRequest *request = dynamic_cast<const HttpRequest*> (theCauseRep ?
                                 theCauseRep->raw().header : theVirginRep.raw().header);
    Must(request);
    Adaptation::History::Pointer ah = request->adaptLogHistory();
    if (ah != NULL) {
        // retrying=false because ecap never retries transactions
        adaptHistoryId = ah->recordXactStart(service().cfg().key, current_time, false);
    }

    theMaster->start();
}

void
Adaptation::Ecap::XactionRep::swanSong()
{
    // clear body_pipes, if any
    // this code does not maintain proxying* and canAccessVb states; should it?

    if (theAnswerRep != NULL) {
        BodyPipe::Pointer body_pipe = answer().body_pipe;
        if (body_pipe != NULL) {
            Must(body_pipe->stillProducing(this));
            stopProducingFor(body_pipe, false);
        }
    }

    if (proxyingVb == opOn) {
        BodyPipe::Pointer body_pipe = theVirginRep.raw().body_pipe;
        if (body_pipe != NULL) {
            Must(body_pipe->stillConsuming(this));
            stopConsumingFrom(body_pipe);
        }
    }

    terminateMaster();

    const HttpRequest *request = dynamic_cast<const HttpRequest*>(theCauseRep ?
                                 theCauseRep->raw().header : theVirginRep.raw().header);
    Must(request);
    Adaptation::History::Pointer ah = request->adaptLogHistory();
    if (ah != NULL && adaptHistoryId >= 0)
        ah->recordXactFinish(adaptHistoryId);

    Adaptation::Initiate::swanSong();
}

libecap::Message &
Adaptation::Ecap::XactionRep::virgin()
{
    return theVirginRep;
}

const libecap::Message &
Adaptation::Ecap::XactionRep::cause()
{
    Must(theCauseRep != NULL);
    return *theCauseRep;
}

libecap::Message &
Adaptation::Ecap::XactionRep::adapted()
{
    Must(theAnswerRep != NULL);
    return *theAnswerRep;
}

Adaptation::Message &
Adaptation::Ecap::XactionRep::answer()
{
    MessageRep *rep = dynamic_cast<MessageRep*>(theAnswerRep.get());
    Must(rep);
    return rep->raw();
}

void
Adaptation::Ecap::XactionRep::terminateMaster()
{
    if (theMaster) {
        AdapterXaction x = theMaster;
        theMaster.reset();
        x->stop();
    }
}

bool
Adaptation::Ecap::XactionRep::doneAll() const
{
    return proxyingVb >= opComplete && proxyingAb >= opComplete &&
           Adaptation::Initiate::doneAll();
}

// stops receiving virgin and enables auto-consumption
void
Adaptation::Ecap::XactionRep::dropVirgin(const char *reason)
{
    debugs(93,4, HERE << "because " << reason << "; status:" << status());
    Must(proxyingVb = opOn);

    BodyPipePointer &p = theVirginRep.raw().body_pipe;
    Must(p != NULL);
    Must(p->stillConsuming(this));
    stopConsumingFrom(p);
    p->enableAutoConsumption();
    proxyingVb = opComplete;
    canAccessVb = false;

    // called from adapter handler so does not inform adapter
}

void
Adaptation::Ecap::XactionRep::useVirgin()
{
    debugs(93,3, HERE << status());
    Must(proxyingAb == opUndecided);
    proxyingAb = opNever;

    BodyPipePointer &vbody_pipe = theVirginRep.raw().body_pipe;

    HttpMsg *clone = theVirginRep.raw().header->clone();
    // check that clone() copies the pipe so that we do not have to
    Must(!vbody_pipe == !clone->body_pipe);

    if (proxyingVb == opOn) {
        Must(vbody_pipe->stillConsuming(this));
        // if libecap consumed, we cannot shortcircuit
        Must(!vbody_pipe->consumedSize());
        stopConsumingFrom(vbody_pipe);
        canAccessVb = false;
        proxyingVb = opComplete;
    } else if (proxyingVb == opUndecided) {
        vbody_pipe = NULL; // it is not our pipe anymore
        proxyingVb = opNever;
    }

    sendAnswer(clone);
    Must(done());
}

void
Adaptation::Ecap::XactionRep::useAdapted(const libecap::shared_ptr<libecap::Message> &m)
{
    debugs(93,3, HERE << status());
    Must(m);
    theAnswerRep = m;
    Must(proxyingAb == opUndecided);

    HttpMsg *msg = answer().header;
    if (!theAnswerRep->body()) { // final, bodyless answer
        proxyingAb = opNever;
        sendAnswer(msg);
    } else { // got answer headers but need to handle body
        proxyingAb = opOn;
        Must(!msg->body_pipe); // only host can set body pipes
        MessageRep *rep = dynamic_cast<MessageRep*>(theAnswerRep.get());
        Must(rep);
        rep->tieBody(this); // sets us as a producer
        Must(msg->body_pipe != NULL); // check tieBody

        sendAnswer(msg);

        debugs(93,4, HERE << "adapter will produce body" << status());
        theMaster->abMake(); // libecap will produce
    }
}

void
Adaptation::Ecap::XactionRep::vbDiscard()
{
    Must(proxyingVb == opUndecided);
    // if adapter does not need vb, we do not need to send it
    dropVirgin("vbDiscard");
    Must(proxyingVb == opNever);
}

void
Adaptation::Ecap::XactionRep::vbMake()
{
    Must(proxyingVb == opUndecided);
    BodyPipePointer &p = theVirginRep.raw().body_pipe;
    Must(p != NULL);
    Must(p->setConsumerIfNotLate(this)); // to make vb, we must receive vb
    proxyingVb = opOn;
}

void
Adaptation::Ecap::XactionRep::vbStopMaking()
{
    // if adapter does not need vb, we do not need to receive it
    if (proxyingVb == opOn)
        dropVirgin("vbStopMaking");
    Must(proxyingVb == opComplete);
}

void
Adaptation::Ecap::XactionRep::vbMakeMore()
{
    Must(proxyingVb == opOn); // cannot make more if done proxying
    // we cannot guarantee more vb, but we can check that there is a chance
    Must(!theVirginRep.raw().body_pipe->exhausted());
}

libecap::Area
Adaptation::Ecap::XactionRep::vbContent(libecap::size_type o, libecap::size_type s)
{
    Must(canAccessVb);
    // We may not be proxyingVb yet. It should be OK, but see vbContentShift().

    const BodyPipePointer &p = theVirginRep.raw().body_pipe;
    Must(p != NULL);

    // TODO: make MemBuf use size_t?
    const size_t haveSize = static_cast<size_t>(p->buf().contentSize());

    // convert to Squid types; XXX: check for overflow
    const uint64_t offset = static_cast<uint64_t>(o);
    Must(offset <= haveSize); // equal iff at the end of content

    // nsize means no size limit: all content starting from offset
    const size_t size = s == libecap::nsize ?
                        haveSize - offset : static_cast<size_t>(s);

    // XXX: optimize by making theBody a shared_ptr (see Area::FromTemp*() src)
    return libecap::Area::FromTempBuffer(p->buf().content() + offset,
                                         min(static_cast<size_t>(haveSize - offset), size));
}

void
Adaptation::Ecap::XactionRep::vbContentShift(libecap::size_type n)
{
    Must(canAccessVb);
    // We may not be proxyingVb yet. It should be OK now, but if BodyPipe
    // consume() requirements change, we would have to return empty vbContent
    // until the adapter registers as a consumer

    BodyPipePointer &p = theVirginRep.raw().body_pipe;
    Must(p != NULL);
    const size_t size = static_cast<size_t>(n); // XXX: check for overflow
    const size_t haveSize = static_cast<size_t>(p->buf().contentSize()); // TODO: make MemBuf use size_t?
    p->consume(min(size, haveSize));
}

void
Adaptation::Ecap::XactionRep::noteAbContentDone(bool atEnd)
{
    Must(proxyingAb == opOn && !abProductionFinished);
    abProductionFinished = true;
    abProductionAtEnd = atEnd; // store until ready to stop producing ourselves
    debugs(93,5, HERE << "adapted body production ended");
    moveAbContent();
}

void
Adaptation::Ecap::XactionRep::noteAbContentAvailable()
{
    Must(proxyingAb == opOn && !abProductionFinished);
    moveAbContent();
}

#if 0 /* XXX: implement */
void
Adaptation::Ecap::XactionRep::setAdaptedBodySize(const libecap::BodySize &size)
{
    Must(answer().body_pipe != NULL);
    if (size.known())
        answer().body_pipe->setBodySize(size.value());
    // else the piped body size is unknown by default
}
#endif

void
Adaptation::Ecap::XactionRep::adaptationDelayed(const libecap::Delay &d)
{
    debugs(93,3, HERE << "adapter needs time: " <<
           d.state << '/' << d.progress);
    // XXX: set timeout?
}

void
Adaptation::Ecap::XactionRep::adaptationAborted()
{
    tellQueryAborted(true); // should eCAP support retries?
    mustStop("adaptationAborted");
}

bool
Adaptation::Ecap::XactionRep::callable() const
{
    return !done();
}

void
Adaptation::Ecap::XactionRep::noteMoreBodySpaceAvailable(RefCount<BodyPipe> bp)
{
    Must(proxyingAb == opOn);
    moveAbContent();
}

void
Adaptation::Ecap::XactionRep::noteBodyConsumerAborted(RefCount<BodyPipe> bp)
{
    Must(proxyingAb == opOn);
    stopProducingFor(answer().body_pipe, false);
    Must(theMaster);
    theMaster->abStopMaking();
    proxyingAb = opComplete;
}

void
Adaptation::Ecap::XactionRep::noteMoreBodyDataAvailable(RefCount<BodyPipe> bp)
{
    Must(proxyingVb == opOn);
    Must(theMaster);
    theMaster->noteVbContentAvailable();
}

void
Adaptation::Ecap::XactionRep::noteBodyProductionEnded(RefCount<BodyPipe> bp)
{
    Must(proxyingVb == opOn);
    Must(theMaster);
    theMaster->noteVbContentDone(true);
    proxyingVb = opComplete;
}

void
Adaptation::Ecap::XactionRep::noteBodyProducerAborted(RefCount<BodyPipe> bp)
{
    Must(proxyingVb == opOn);
    Must(theMaster);
    theMaster->noteVbContentDone(false);
    proxyingVb = opComplete;
}

void
Adaptation::Ecap::XactionRep::noteInitiatorAborted()
{
    mustStop("initiator aborted");
}

// get content from the adapter and put it into the adapted pipe
void
Adaptation::Ecap::XactionRep::moveAbContent()
{
    Must(proxyingAb == opOn);
    const libecap::Area c = theMaster->abContent(0, libecap::nsize);
    debugs(93,5, HERE << "up to " << c.size << " bytes");
    if (c.size == 0 && abProductionFinished) { // no ab now and in the future
        stopProducingFor(answer().body_pipe, abProductionAtEnd);
        proxyingAb = opComplete;
        debugs(93,5, HERE << "last adapted body data retrieved");
    } else if (c.size > 0) {
        if (const size_t used = answer().body_pipe->putMoreData(c.start, c.size))
            theMaster->abContentShift(used);
    }
}

const char *
Adaptation::Ecap::XactionRep::status() const
{
    static MemBuf buf;
    buf.reset();

    buf.append(" [", 2);

    if (proxyingVb == opOn) {
        const BodyPipePointer &vp = theVirginRep.raw().body_pipe;
        if (!canAccessVb)
            buf.append("x", 1);
        if (vp != NULL) { // XXX: but may not be stillConsuming()
            buf.append("Vb", 2);
        } else
            buf.append("V.", 2);
    }

    if (proxyingAb == opOn) {
        MessageRep *rep = dynamic_cast<MessageRep*>(theAnswerRep.get());
        Must(rep);
        const BodyPipePointer &ap = rep->raw().body_pipe;
        if (ap != NULL) { // XXX: but may not be stillProducing()
            buf.append(" Ab", 3);
        } else
            buf.append(" A.", 3);
    }

    buf.Printf(" ecapx%d]", id);

    buf.terminate();

    return buf.content();
}
