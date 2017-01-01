/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 93    eCAP Interface */

#include "squid.h"
#include <libecap/common/area.h>
#include <libecap/common/delay.h>
#include <libecap/common/named_values.h>
#include <libecap/common/names.h>
#include <libecap/adapter/xaction.h>
#include "adaptation/Answer.h"
#include "adaptation/ecap/Config.h"
#include "adaptation/ecap/XactionRep.h"
#include "adaptation/Initiator.h"
#include "base/AsyncJobCalls.h"
#include "base/TextException.h"
#include "format/Format.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidTime.h"

CBDATA_NAMESPACED_CLASS_INIT(Adaptation::Ecap::XactionRep, XactionRep);

/// a libecap Visitor for converting adapter transaction options to HttpHeader
class OptionsExtractor: public libecap::NamedValueVisitor
{
public:
    typedef libecap::Name Name;
    typedef libecap::Area Area;

    OptionsExtractor(HttpHeader &aMeta): meta(aMeta) {}

    // libecap::NamedValueVisitor API
    virtual void visit(const Name &name, const Area &value) {
        meta.putExt(name.image().c_str(), value.toString().c_str());
    }

    HttpHeader &meta; ///< where to put extracted options
};

Adaptation::Ecap::XactionRep::XactionRep(
    HttpMsg *virginHeader, HttpRequest *virginCause, AccessLogEntry::Pointer &alp,
    const Adaptation::ServicePointer &aService):
    AsyncJob("Adaptation::Ecap::XactionRep"),
    Adaptation::Initiate("Adaptation::Ecap::XactionRep"),
    theService(aService),
    theVirginRep(virginHeader), theCauseRep(NULL),
    makingVb(opUndecided), proxyingAb(opUndecided),
    adaptHistoryId(-1),
    vbProductionFinished(false),
    abProductionFinished(false), abProductionAtEnd(false),
    al(alp)
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
    Must(x);
    theMaster = x;
}

Adaptation::Service &
Adaptation::Ecap::XactionRep::service()
{
    Must(theService != NULL);
    return *theService;
}

const libecap::Area
Adaptation::Ecap::XactionRep::option(const libecap::Name &name) const
{
    if (name == libecap::metaClientIp)
        return clientIpValue();
    if (name == libecap::metaUserName)
        return usernameValue();
    if (Adaptation::Config::masterx_shared_name && name == Adaptation::Config::masterx_shared_name)
        return masterxSharedValue(name);

    // TODO: metaServerIp, metaAuthenticatedUser, and metaAuthenticatedGroups

    // If the name is unknown, metaValue returns an emtpy area
    return metaValue(name);
}

void
Adaptation::Ecap::XactionRep::visitEachOption(libecap::NamedValueVisitor &visitor) const
{
    if (const libecap::Area value = clientIpValue())
        visitor.visit(libecap::metaClientIp, value);
    if (const libecap::Area value = usernameValue())
        visitor.visit(libecap::metaUserName, value);

    if (Adaptation::Config::masterx_shared_name) {
        const libecap::Name name(Adaptation::Config::masterx_shared_name);
        if (const libecap::Area value = masterxSharedValue(name))
            visitor.visit(name, value);
    }

    visitEachMetaHeader(visitor);

    // TODO: metaServerIp, metaAuthenticatedUser, and metaAuthenticatedGroups
}

const libecap::Area
Adaptation::Ecap::XactionRep::clientIpValue() const
{
    const HttpRequest *request = dynamic_cast<const HttpRequest*>(theCauseRep ?
                                 theCauseRep->raw().header : theVirginRep.raw().header);
    Must(request);
    // TODO: move this logic into HttpRequest::clientIp(bool) and
    // HttpRequest::clientIpString(bool) and reuse everywhere
    if (TheConfig.send_client_ip && request) {
        Ip::Address client_addr;
#if FOLLOW_X_FORWARDED_FOR
        if (TheConfig.use_indirect_client) {
            client_addr = request->indirect_client_addr;
        } else
#endif
            client_addr = request->client_addr;
        if (!client_addr.isAnyAddr() && !client_addr.isNoAddr()) {
            char ntoabuf[MAX_IPSTRLEN] = "";
            client_addr.toStr(ntoabuf,MAX_IPSTRLEN);
            return libecap::Area::FromTempBuffer(ntoabuf, strlen(ntoabuf));
        }
    }
    return libecap::Area();
}

const libecap::Area
Adaptation::Ecap::XactionRep::usernameValue() const
{
#if USE_AUTH
    const HttpRequest *request = dynamic_cast<const HttpRequest*>(theCauseRep ?
                                 theCauseRep->raw().header : theVirginRep.raw().header);
    Must(request);
    if (request->auth_user_request != NULL) {
        if (char const *name = request->auth_user_request->username())
            return libecap::Area::FromTempBuffer(name, strlen(name));
        else if (request->extacl_user.size() > 0)
            return libecap::Area::FromTempBuffer(request->extacl_user.rawBuf(),
                                                 request->extacl_user.size());
    }
#endif
    return libecap::Area();
}

const libecap::Area
Adaptation::Ecap::XactionRep::masterxSharedValue(const libecap::Name &name) const
{
    const HttpRequest *request = dynamic_cast<const HttpRequest*>(theCauseRep ?
                                 theCauseRep->raw().header : theVirginRep.raw().header);
    Must(request);
    if (name.known()) { // must check to avoid empty names matching unset cfg
        Adaptation::History::Pointer ah = request->adaptHistory(false);
        if (ah != NULL) {
            String name, value;
            if (ah->getXxRecord(name, value))
                return libecap::Area::FromTempBuffer(value.rawBuf(), value.size());
        }
    }
    return libecap::Area();
}

const libecap::Area
Adaptation::Ecap::XactionRep::metaValue(const libecap::Name &name) const
{
    HttpRequest *request = dynamic_cast<HttpRequest*>(theCauseRep ?
                           theCauseRep->raw().header : theVirginRep.raw().header);
    Must(request);
    HttpReply *reply = dynamic_cast<HttpReply*>(theVirginRep.raw().header);

    if (name.known()) { // must check to avoid empty names matching unset cfg
        typedef Notes::iterator ACAMLI;
        for (ACAMLI i = Adaptation::Config::metaHeaders.begin(); i != Adaptation::Config::metaHeaders.end(); ++i) {
            if (name == (*i)->key.termedBuf()) {
                if (const char *value = (*i)->match(request, reply, al))
                    return libecap::Area::FromTempString(value);
                else
                    return libecap::Area();
            }
        }
    }

    return libecap::Area();
}

void
Adaptation::Ecap::XactionRep::visitEachMetaHeader(libecap::NamedValueVisitor &visitor) const
{
    HttpRequest *request = dynamic_cast<HttpRequest*>(theCauseRep ?
                           theCauseRep->raw().header : theVirginRep.raw().header);
    Must(request);
    HttpReply *reply = dynamic_cast<HttpReply*>(theVirginRep.raw().header);

    typedef Notes::iterator ACAMLI;
    for (ACAMLI i = Adaptation::Config::metaHeaders.begin(); i != Adaptation::Config::metaHeaders.end(); ++i) {
        const char *v = (*i)->match(request, reply, al);
        if (v) {
            const libecap::Name name((*i)->key.termedBuf());
            const libecap::Area value = libecap::Area::FromTempString(v);
            visitor.visit(name, value);
        }
    }
}

void
Adaptation::Ecap::XactionRep::start()
{
    Must(theMaster);

    if (!theVirginRep.raw().body_pipe)
        makingVb = opNever; // there is nothing to deliver

    HttpRequest *request = dynamic_cast<HttpRequest*> (theCauseRep ?
                           theCauseRep->raw().header : theVirginRep.raw().header);
    Must(request);

    HttpReply *reply = dynamic_cast<HttpReply*>(theVirginRep.raw().header);

    Adaptation::History::Pointer ah = request->adaptLogHistory();
    if (ah != NULL) {
        // retrying=false because ecap never retries transactions
        adaptHistoryId = ah->recordXactStart(service().cfg().key, current_time, false);
        typedef Notes::iterator ACAMLI;
        for (ACAMLI i = Adaptation::Config::metaHeaders.begin(); i != Adaptation::Config::metaHeaders.end(); ++i) {
            const char *v = (*i)->match(request, reply, al);
            if (v) {
                if (ah->metaHeaders == NULL)
                    ah->metaHeaders = new NotePairs();
                if (!ah->metaHeaders->hasPair((*i)->key.termedBuf(), v))
                    ah->metaHeaders->add((*i)->key.termedBuf(), v);
            }
        }
    }

    theMaster->start();
}

void
Adaptation::Ecap::XactionRep::swanSong()
{
    // clear body_pipes, if any
    // this code does not maintain proxying* and canAccessVb states; should it?

    if (theAnswerRep) {
        BodyPipe::Pointer body_pipe = answer().body_pipe;
        if (body_pipe != NULL) {
            Must(body_pipe->stillProducing(this));
            stopProducingFor(body_pipe, false);
        }
    }

    BodyPipe::Pointer &body_pipe = theVirginRep.raw().body_pipe;
    if (body_pipe != NULL && body_pipe->stillConsuming(this))
        stopConsumingFrom(body_pipe);

    terminateMaster();

    const HttpRequest *request = dynamic_cast<const HttpRequest*>(theCauseRep ?
                                 theCauseRep->raw().header : theVirginRep.raw().header);
    Must(request);
    Adaptation::History::Pointer ah = request->adaptLogHistory();
    if (ah != NULL && adaptHistoryId >= 0)
        ah->recordXactFinish(adaptHistoryId);

    Adaptation::Initiate::swanSong();
}

void
Adaptation::Ecap::XactionRep::resume()
{
    // go async to gain exception protection and done()-based job destruction
    typedef NullaryMemFunT<Adaptation::Ecap::XactionRep> Dialer;
    AsyncCall::Pointer call = asyncCall(93, 5, "Adaptation::Ecap::XactionRep::doResume",
                                        Dialer(this, &Adaptation::Ecap::XactionRep::doResume));
    ScheduleCallHere(call);
}

/// the guts of libecap::host::Xaction::resume() API implementation
/// which just goes async in Adaptation::Ecap::XactionRep::resume().
void
Adaptation::Ecap::XactionRep::doResume()
{
    Must(theMaster);
    theMaster->resume();
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
    Must(theAnswerRep);
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
    return makingVb >= opComplete && proxyingAb >= opComplete &&
           Adaptation::Initiate::doneAll();
}

// stops receiving virgin and enables auto-consumption, dropping any vb bytes
void
Adaptation::Ecap::XactionRep::sinkVb(const char *reason)
{
    debugs(93,4, HERE << "sink for " << reason << "; status:" << status());

    // we reset raw().body_pipe when we are done, so use this one for checking
    const BodyPipePointer &permPipe = theVirginRep.raw().header->body_pipe;
    if (permPipe != NULL)
        permPipe->enableAutoConsumption();

    forgetVb(reason);
}

// stops receiving virgin but preserves it for others to use
void
Adaptation::Ecap::XactionRep::preserveVb(const char *reason)
{
    debugs(93,4, HERE << "preserve for " << reason << "; status:" << status());

    // we reset raw().body_pipe when we are done, so use this one for checking
    const BodyPipePointer &permPipe = theVirginRep.raw().header->body_pipe;
    if (permPipe != NULL) {
        // if libecap consumed, we cannot preserve
        Must(!permPipe->consumedSize());
    }

    forgetVb(reason);
}

// disassociates us from vb; the last step of sinking or preserving vb
void
Adaptation::Ecap::XactionRep::forgetVb(const char *reason)
{
    debugs(93,9, HERE << "forget vb " << reason << "; status:" << status());

    BodyPipePointer &p = theVirginRep.raw().body_pipe;
    if (p != NULL && p->stillConsuming(this))
        stopConsumingFrom(p);

    if (makingVb == opUndecided)
        makingVb = opNever;
    else if (makingVb == opOn)
        makingVb = opComplete;
}

void
Adaptation::Ecap::XactionRep::useVirgin()
{
    debugs(93,3, HERE << status());
    Must(proxyingAb == opUndecided);
    proxyingAb = opNever;

    preserveVb("useVirgin");

    HttpMsg *clone = theVirginRep.raw().header->clone();
    // check that clone() copies the pipe so that we do not have to
    Must(!theVirginRep.raw().header->body_pipe == !clone->body_pipe);

    updateHistory(clone);
    sendAnswer(Answer::Forward(clone));
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
    updateSources(msg);
    if (!theAnswerRep->body()) { // final, bodyless answer
        proxyingAb = opNever;
        updateHistory(msg);
        sendAnswer(Answer::Forward(msg));
    } else { // got answer headers but need to handle body
        proxyingAb = opOn;
        Must(!msg->body_pipe); // only host can set body pipes
        MessageRep *rep = dynamic_cast<MessageRep*>(theAnswerRep.get());
        Must(rep);
        rep->tieBody(this); // sets us as a producer
        Must(msg->body_pipe != NULL); // check tieBody

        updateHistory(msg);
        sendAnswer(Answer::Forward(msg));

        debugs(93,4, HERE << "adapter will produce body" << status());
        theMaster->abMake(); // libecap will produce
    }
}

void
Adaptation::Ecap::XactionRep::blockVirgin()
{
    debugs(93,3, HERE << status());
    Must(proxyingAb == opUndecided);
    proxyingAb = opNever;

    sinkVb("blockVirgin");

    updateHistory(NULL);
    sendAnswer(Answer::Block(service().cfg().key));
    Must(done());
}

/// Called just before sendAnswer() to record adapter meta-information
/// which may affect answer processing and may be needed for logging.
void
Adaptation::Ecap::XactionRep::updateHistory(HttpMsg *adapted)
{
    if (!theMaster) // all updates rely on being able to query the adapter
        return;

    const HttpRequest *request = dynamic_cast<const HttpRequest*>(theCauseRep ?
                                 theCauseRep->raw().header : theVirginRep.raw().header);
    Must(request);

    // TODO: move common ICAP/eCAP logic to Adaptation::Xaction or similar
    // TODO: optimize Area-to-String conversion

    // update the cross-transactional database if needed
    if (const char *xxNameStr = Adaptation::Config::masterx_shared_name) {
        Adaptation::History::Pointer ah = request->adaptHistory(true);
        if (ah != NULL) {
            libecap::Name xxName(xxNameStr); // TODO: optimize?
            if (const libecap::Area val = theMaster->option(xxName))
                ah->updateXxRecord(xxNameStr, val.toString().c_str());
        }
    }

    // update the adaptation plan if needed
    if (service().cfg().routing) {
        String services;
        if (const libecap::Area services = theMaster->option(libecap::metaNextServices)) {
            Adaptation::History::Pointer ah = request->adaptHistory(true);
            if (ah != NULL)
                ah->updateNextServices(services.toString().c_str());
        }
    } // TODO: else warn (occasionally!) if we got libecap::metaNextServices

    // Store received meta headers for adapt::<last_h logformat code use.
    // If we already have stored headers from a previous adaptation transaction
    // related to the same master transction, they will be replaced.
    Adaptation::History::Pointer ah = request->adaptLogHistory();
    if (ah != NULL) {
        HttpHeader meta(hoReply);
        OptionsExtractor extractor(meta);
        theMaster->visitEachOption(extractor);
        ah->recordMeta(&meta);
    }

    // Add just-created history to the adapted/cloned request that lacks it.
    if (HttpRequest *adaptedReq = dynamic_cast<HttpRequest*>(adapted))
        adaptedReq->adaptHistoryImport(*request);
}

void
Adaptation::Ecap::XactionRep::vbDiscard()
{
    Must(makingVb == opUndecided);
    // if adapter does not need vb, we do not need to send it
    sinkVb("vbDiscard");
    Must(makingVb == opNever);
}

void
Adaptation::Ecap::XactionRep::vbMake()
{
    Must(makingVb == opUndecided);
    BodyPipePointer &p = theVirginRep.raw().body_pipe;
    Must(p != NULL);
    Must(p->setConsumerIfNotLate(this)); // to deliver vb, we must receive vb
    makingVb = opOn;
}

void
Adaptation::Ecap::XactionRep::vbStopMaking()
{
    Must(makingVb == opOn);
    // if adapter does not need vb, we do not need to receive it
    sinkVb("vbStopMaking");
    Must(makingVb == opComplete);
}

void
Adaptation::Ecap::XactionRep::vbMakeMore()
{
    Must(makingVb == opOn); // cannot make more if done proxying
    // we cannot guarantee more vb, but we can check that there is a chance
    const BodyPipePointer &p = theVirginRep.raw().body_pipe;
    Must(p != NULL && p->stillConsuming(this)); // we are plugged in
    Must(!p->productionEnded() && p->mayNeedMoreData()); // and may get more
}

libecap::Area
Adaptation::Ecap::XactionRep::vbContent(libecap::size_type o, libecap::size_type s)
{
    // We may not be makingVb yet. It should be OK, but see vbContentShift().

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
    // We may not be makingVb yet. It should be OK now, but if BodyPipe
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
    Must(makingVb == opOn); // or we would not be registered as a consumer
    Must(theMaster);
    theMaster->noteVbContentAvailable();
}

void
Adaptation::Ecap::XactionRep::noteBodyProductionEnded(RefCount<BodyPipe> bp)
{
    Must(makingVb == opOn); // or we would not be registered as a consumer
    Must(theMaster);
    theMaster->noteVbContentDone(true);
    vbProductionFinished = true;
}

void
Adaptation::Ecap::XactionRep::noteBodyProducerAborted(RefCount<BodyPipe> bp)
{
    Must(makingVb == opOn); // or we would not be registered as a consumer
    Must(theMaster);
    theMaster->noteVbContentDone(false);
    vbProductionFinished = true;
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

    if (makingVb)
        buf.appendf("M%d", static_cast<int>(makingVb));

    const BodyPipePointer &vp = theVirginRep.raw().body_pipe;
    if (!vp)
        buf.append(" !V", 3);
    else if (vp->stillConsuming(const_cast<XactionRep*>(this)))
        buf.append(" Vc", 3);
    else
        buf.append(" V?", 3);

    if (vbProductionFinished)
        buf.append(".", 1);

    buf.appendf(" A%d", static_cast<int>(proxyingAb));

    if (proxyingAb == opOn) {
        MessageRep *rep = dynamic_cast<MessageRep*>(theAnswerRep.get());
        Must(rep);
        const BodyPipePointer &ap = rep->raw().body_pipe;
        if (!ap)
            buf.append(" !A", 3);
        else if (ap->stillProducing(const_cast<XactionRep*>(this)))
            buf.append(" Ap", 3);
        else
            buf.append(" A?", 3);
    }

    buf.appendf(" %s%u]", id.prefix(), id.value);

    buf.terminate();

    return buf.content();
}

void
Adaptation::Ecap::XactionRep::updateSources(HttpMsg *adapted)
{
    adapted->sources |= service().cfg().connectionEncryption ? HttpMsg::srcEcaps : HttpMsg::srcEcap;
}

