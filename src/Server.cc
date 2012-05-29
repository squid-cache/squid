/*
 * $Id$
 *
 * DEBUG:
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "Server.h"
#include "Store.h"
#include "fde.h" /* for fd_table[fd].closing */
#include "HttpRequest.h"
#include "HttpReply.h"
#include "TextException.h"
#include "errorpage.h"
#include "SquidTime.h"

#if USE_ADAPTATION
#include "adaptation/AccessCheck.h"
#include "adaptation/Iterator.h"
#include "base/AsyncCall.h"
#endif

// implemented in client_side_reply.cc until sides have a common parent
extern void purgeEntriesByUrl(HttpRequest * req, const char *url);


ServerStateData::ServerStateData(FwdState *theFwdState): AsyncJob("ServerStateData"),requestSender(NULL)
#if USE_ADAPTATION
        , adaptedHeadSource(NULL)
        , adaptationAccessCheckPending(false)
        , startedAdaptation(false)
#endif
        ,theVirginReply(NULL),
        theFinalReply(NULL)
{
    fwd = theFwdState;
    entry = fwd->entry;

    entry->lock();

    request = HTTPMSGLOCK(fwd->request);
}

ServerStateData::~ServerStateData()
{
    // paranoid: check that swanSong has been called
    assert(!requestBodySource);
#if USE_ADAPTATION
    assert(!virginBodyDestination);
    assert(!adaptedBodySource);
#endif

    entry->unlock();

    HTTPMSGUNLOCK(request);
    HTTPMSGUNLOCK(theVirginReply);
    HTTPMSGUNLOCK(theFinalReply);

    fwd = NULL; // refcounted

    if (responseBodyBuffer != NULL) {
        delete responseBodyBuffer;
        responseBodyBuffer = NULL;
    }
}

void
ServerStateData::swanSong()
{
    // get rid of our piping obligations
    if (requestBodySource != NULL)
        stopConsumingFrom(requestBodySource);

#if USE_ADAPTATION
    cleanAdaptation();
#endif

    BodyConsumer::swanSong();
#if USE_ADAPTATION
    Initiator::swanSong();
    BodyProducer::swanSong();
#endif

    // paranoid: check that swanSong has been called
    // extra paranoid: yeah, I really mean it. they MUST pass here.
    assert(!requestBodySource);
#if USE_ADAPTATION
    assert(!virginBodyDestination);
    assert(!adaptedBodySource);
#endif
}


HttpReply *
ServerStateData::virginReply()
{
    assert(theVirginReply);
    return theVirginReply;
}

const HttpReply *
ServerStateData::virginReply() const
{
    assert(theVirginReply);
    return theVirginReply;
}

HttpReply *
ServerStateData::setVirginReply(HttpReply *rep)
{
    debugs(11,5, HERE << this << " setting virgin reply to " << rep);
    assert(!theVirginReply);
    assert(rep);
    theVirginReply = HTTPMSGLOCK(rep);
    return theVirginReply;
}

HttpReply *
ServerStateData::finalReply()
{
    assert(theFinalReply);
    return theFinalReply;
}

HttpReply *
ServerStateData::setFinalReply(HttpReply *rep)
{
    debugs(11,5, HERE << this << " setting final reply to " << rep);

    assert(!theFinalReply);
    assert(rep);
    theFinalReply = HTTPMSGLOCK(rep);

    entry->replaceHttpReply(theFinalReply);
    haveParsedReplyHeaders();

    return theFinalReply;
}

// called when no more server communication is expected; may quit
void
ServerStateData::serverComplete()
{
    debugs(11,5,HERE << "serverComplete " << this);

    if (!doneWithServer()) {
        closeServer();
        assert(doneWithServer());
    }

    completed = true;

    HttpRequest *r = originalRequest();
    r->hier.total_response_time = r->hier.first_conn_start.tv_sec ?
                                  tvSubMsec(r->hier.first_conn_start, current_time) : -1;

    if (requestBodySource != NULL)
        stopConsumingFrom(requestBodySource);

    if (responseBodyBuffer != NULL)
        return;

    serverComplete2();
}

void
ServerStateData::serverComplete2()
{
    debugs(11,5,HERE << "serverComplete2 " << this);

#if USE_ADAPTATION
    if (virginBodyDestination != NULL)
        stopProducingFor(virginBodyDestination, true);

    if (!doneWithAdaptation())
        return;
#endif

    completeForwarding();
    quitIfAllDone();
}

// When we are done talking to the primary server, we may be still talking
// to the ICAP service. And vice versa. Here, we quit only if we are done
// talking to both.
void ServerStateData::quitIfAllDone()
{
#if USE_ADAPTATION
    if (!doneWithAdaptation()) {
        debugs(11,5, HERE << "transaction not done: still talking to ICAP");
        return;
    }
#endif

    if (!doneWithServer()) {
        debugs(11,5, HERE << "transaction not done: still talking to server");
        return;
    }

    debugs(11,3, HERE << "transaction done");

    deleteThis("ServerStateData::quitIfAllDone");
}

// FTP side overloads this to work around multiple calls to fwd->complete
void
ServerStateData::completeForwarding()
{
    debugs(11,5, HERE << "completing forwarding for "  << fwd);
    assert(fwd != NULL);
    fwd->complete();
}

// Register to receive request body
bool ServerStateData::startRequestBodyFlow()
{
    HttpRequest *r = originalRequest();
    assert(r->body_pipe != NULL);
    requestBodySource = r->body_pipe;
    if (requestBodySource->setConsumerIfNotLate(this)) {
        debugs(11,3, HERE << "expecting request body from " <<
               requestBodySource->status());
        return true;
    }

    debugs(11,3, HERE << "aborting on partially consumed request body: " <<
           requestBodySource->status());
    requestBodySource = NULL;
    return false;
}

// Entry-dependent callbacks use this check to quit if the entry went bad
bool
ServerStateData::abortOnBadEntry(const char *abortReason)
{
    if (entry->isAccepting())
        return false;

    debugs(11,5, HERE << "entry is not Accepting!");
    abortTransaction(abortReason);
    return true;
}

// more request or adapted response body is available
void
ServerStateData::noteMoreBodyDataAvailable(BodyPipe::Pointer bp)
{
#if USE_ADAPTATION
    if (adaptedBodySource == bp) {
        handleMoreAdaptedBodyAvailable();
        return;
    }
#endif
    if (requestBodySource == bp)
        handleMoreRequestBodyAvailable();
}

// the entire request or adapted response body was provided, successfully
void
ServerStateData::noteBodyProductionEnded(BodyPipe::Pointer bp)
{
#if USE_ADAPTATION
    if (adaptedBodySource == bp) {
        handleAdaptedBodyProductionEnded();
        return;
    }
#endif
    if (requestBodySource == bp)
        handleRequestBodyProductionEnded();
}

// premature end of the request or adapted response body production
void
ServerStateData::noteBodyProducerAborted(BodyPipe::Pointer bp)
{
#if USE_ADAPTATION
    if (adaptedBodySource == bp) {
        handleAdaptedBodyProducerAborted();
        return;
    }
#endif
    if (requestBodySource == bp)
        handleRequestBodyProducerAborted();
}


// more origin request body data is available
void
ServerStateData::handleMoreRequestBodyAvailable()
{
    if (!requestSender)
        sendMoreRequestBody();
    else
        debugs(9,3, HERE << "waiting for request body write to complete");
}

// there will be no more handleMoreRequestBodyAvailable calls
void
ServerStateData::handleRequestBodyProductionEnded()
{
    if (!requestSender)
        doneSendingRequestBody();
    else
        debugs(9,3, HERE << "waiting for request body write to complete");
}

// called when we are done sending request body; kids extend this
void
ServerStateData::doneSendingRequestBody()
{
    debugs(9,3, HERE << "done sending request body");
    assert(requestBodySource != NULL);
    stopConsumingFrom(requestBodySource);

    // kids extend this
}

// called when body producers aborts; kids extend this
void
ServerStateData::handleRequestBodyProducerAborted()
{
    if (requestSender != NULL)
        debugs(9,3, HERE << "fyi: request body aborted while we were sending");

    fwd->dontRetry(true); // the problem is not with the server
    stopConsumingFrom(requestBodySource); // requestSender, if any, will notice

    // kids extend this
}

// called when we wrote request headers(!) or a part of the body
void
ServerStateData::sentRequestBody(const CommIoCbParams &io)
{
    debugs(11, 5, "sentRequestBody: FD " << io.fd << ": size " << io.size << ": errflag " << io.flag << ".");
    debugs(32,3,HERE << "sentRequestBody called");

    requestSender = NULL;

    if (io.size > 0) {
        fd_bytes(io.fd, io.size, FD_WRITE);
        kb_incr(&statCounter.server.all.kbytes_out, io.size);
        // kids should increment their counters
    }

    if (io.flag == COMM_ERR_CLOSING)
        return;

    if (!requestBodySource) {
        debugs(9,3, HERE << "detected while-we-were-sending abort");
        return; // do nothing;
    }

    if (io.flag) {
        debugs(11, 1, "sentRequestBody error: FD " << io.fd << ": " << xstrerr(errno));
        ErrorState *err;
        err = errorCon(ERR_WRITE_ERROR, HTTP_BAD_GATEWAY, fwd->request);
        err->xerrno = errno;
        fwd->fail(err);
        abortTransaction("I/O error while sending request body");
        return;
    }

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("store entry aborted while sending request body");
        return;
    }

    if (requestBodySource->exhausted())
        doneSendingRequestBody();
    else
        sendMoreRequestBody();
}

bool
ServerStateData::canSend(int fd) const
{
    return fd >= 0 && !fd_table[fd].closing();
}

void
ServerStateData::sendMoreRequestBody()
{
    assert(requestBodySource != NULL);
    assert(!requestSender);

    const int fd = dataDescriptor();

    if (!canSend(fd)) {
        debugs(9,3, HERE << "cannot send request body to closing FD " << fd);
        return; // wait for the kid's close handler; TODO: assert(closer);
    }

    MemBuf buf;
    if (requestBodySource->getMoreData(buf)) {
        debugs(9,3, HERE << "will write " << buf.contentSize() << " request body bytes");
        typedef CommCbMemFunT<ServerStateData, CommIoCbParams> Dialer;
        requestSender = JobCallback(93,3,
                                    Dialer, this, ServerStateData::sentRequestBody);
        comm_write_mbuf(fd, &buf, requestSender);
    } else {
        debugs(9,3, HERE << "will wait for more request body bytes or eof");
        requestSender = NULL;
    }
}

// Compares hosts in urls, returns false if different, no sheme, or no host.
static bool
sameUrlHosts(const char *url1, const char *url2)
{
    // XXX: Want urlHostname() here, but it uses static storage and copying
    const char *host1 = strchr(url1, ':');
    const char *host2 = strchr(url2, ':');

    if (host1 && host2) {
        // skip scheme slashes
        do {
            ++host1;
            ++host2;
        } while (*host1 == '/' && *host2 == '/');

        if (!*host1)
            return false; // no host

        // increment while the same until we reach the end of the URL/host
        while (*host1 && *host1 != '/' && *host1 == *host2) {
            ++host1;
            ++host2;
        }
        return *host1 == *host2;
    }

    return false; // no URL scheme
}

// purges entries that match the value of a given HTTP [response] header
static void
purgeEntriesByHeader(HttpRequest *req, const char *reqUrl, HttpMsg *rep, http_hdr_type hdr)
{
    const char *hdrUrl, *absUrl;

    absUrl = NULL;
    hdrUrl = rep->header.getStr(hdr);
    if (hdrUrl == NULL) {
        return;
    }

    /*
     * If the URL is relative, make it absolute so we can find it.
     * If it's absolute, make sure the host parts match to avoid DOS attacks
     * as per RFC 2616 13.10.
     */
    if (urlIsRelative(hdrUrl)) {
        absUrl = urlMakeAbsolute(req, hdrUrl);
        if (absUrl != NULL) {
            hdrUrl = absUrl;
        }
    } else if (!sameUrlHosts(reqUrl, hdrUrl)) {
        return;
    }

    purgeEntriesByUrl(req, hdrUrl);

    if (absUrl != NULL) {
        safe_free(absUrl);
    }
}

// some HTTP methods should purge matching cache entries
void
ServerStateData::maybePurgeOthers()
{
    // only some HTTP methods should purge matching cache entries
    if (!request->method.purgesOthers())
        return;

    // and probably only if the response was successful
    if (theFinalReply->sline.status >= 400)
        return;

    // XXX: should we use originalRequest() here?
    const char *reqUrl = urlCanonical(request);
    debugs(88, 5, "maybe purging due to " << RequestMethodStr(request->method) << ' ' << reqUrl);
    purgeEntriesByUrl(request, reqUrl);
    purgeEntriesByHeader(request, reqUrl, theFinalReply, HDR_LOCATION);
    purgeEntriesByHeader(request, reqUrl, theFinalReply, HDR_CONTENT_LOCATION);
}

// called (usually by kids) when we have final (possibly adapted) reply headers
void
ServerStateData::haveParsedReplyHeaders()
{
    Must(theFinalReply);
    maybePurgeOthers();
}

HttpRequest *
ServerStateData::originalRequest()
{
    return request;
}

#if USE_ADAPTATION
/// Initiate an asynchronous adaptation transaction which will call us back.
void
ServerStateData::startAdaptation(const Adaptation::ServiceGroupPointer &group, HttpRequest *cause)
{
    debugs(11, 5, "ServerStateData::startAdaptation() called");
    // check whether we should be sending a body as well
    // start body pipe to feed ICAP transaction if needed
    assert(!virginBodyDestination);
    HttpReply *vrep = virginReply();
    assert(!vrep->body_pipe);
    int64_t size = 0;
    if (vrep->expectingBody(cause->method, size) && size) {
        virginBodyDestination = new BodyPipe(this);
        vrep->body_pipe = virginBodyDestination;
        debugs(93, 6, HERE << "will send virgin reply body to " <<
               virginBodyDestination << "; size: " << size);
        if (size > 0)
            virginBodyDestination->setBodySize(size);
    }

    adaptedHeadSource = initiateAdaptation(
                            new Adaptation::Iterator(vrep, cause, group));
    startedAdaptation = initiated(adaptedHeadSource);
    Must(startedAdaptation);
}

// properly cleans up ICAP-related state
// may be called multiple times
void ServerStateData::cleanAdaptation()
{
    debugs(11,5, HERE << "cleaning ICAP; ACL: " << adaptationAccessCheckPending);

    if (virginBodyDestination != NULL)
        stopProducingFor(virginBodyDestination, false);

    announceInitiatorAbort(adaptedHeadSource);

    if (adaptedBodySource != NULL)
        stopConsumingFrom(adaptedBodySource);

    if (!adaptationAccessCheckPending) // we cannot cancel a pending callback
        assert(doneWithAdaptation()); // make sure the two methods are in sync
}

bool
ServerStateData::doneWithAdaptation() const
{
    return !adaptationAccessCheckPending &&
           !virginBodyDestination && !adaptedHeadSource && !adaptedBodySource;
}

// sends virgin reply body to ICAP, buffering excesses if needed
void
ServerStateData::adaptVirginReplyBody(const char *data, ssize_t len)
{
    assert(startedAdaptation);

    if (!virginBodyDestination) {
        debugs(11,3, HERE << "ICAP does not want more virgin body");
        return;
    }

    // grow overflow area if already overflowed
    if (responseBodyBuffer) {
        responseBodyBuffer->append(data, len);
        data = responseBodyBuffer->content();
        len = responseBodyBuffer->contentSize();
    }

    const ssize_t putSize = virginBodyDestination->putMoreData(data, len);
    data += putSize;
    len -= putSize;

    // if we had overflow area, shrink it as necessary
    if (responseBodyBuffer) {
        if (putSize == responseBodyBuffer->contentSize()) {
            delete responseBodyBuffer;
            responseBodyBuffer = NULL;
        } else {
            responseBodyBuffer->consume(putSize);
        }
        return;
    }

    // if we did not have an overflow area, create it as needed
    if (len > 0) {
        assert(!responseBodyBuffer);
        responseBodyBuffer = new MemBuf;
        responseBodyBuffer->init(4096, SQUID_TCP_SO_RCVBUF * 10);
        responseBodyBuffer->append(data, len);
    }
}

// can supply more virgin response body data
void
ServerStateData::noteMoreBodySpaceAvailable(BodyPipe::Pointer)
{
    if (responseBodyBuffer) {
        addVirginReplyBody(NULL, 0); // kick the buffered fragment alive again
        if (completed && !responseBodyBuffer) {
            serverComplete2();
            return;
        }
    }
    maybeReadVirginBody();
}

// the consumer of our virgin response body aborted
void
ServerStateData::noteBodyConsumerAborted(BodyPipe::Pointer)
{
    stopProducingFor(virginBodyDestination, false);

    // do not force closeServer here in case we need to bypass AdaptationQueryAbort

    if (doneWithAdaptation()) // we may still be receiving adapted response
        handleAdaptationCompleted();
}

// received adapted response headers (body may follow)
void
ServerStateData::noteAdaptationAnswer(HttpMsg *msg)
{
    clearAdaptation(adaptedHeadSource); // we do not expect more messages

    if (abortOnBadEntry("entry went bad while waiting for adapted headers")) {
        // If the adapted response has a body, the ICAP side needs to know
        // that nobody will consume that body. We will be destroyed upon
        // return. Tell the ICAP side that it is on its own.
        HttpReply *rep = dynamic_cast<HttpReply*>(msg);
        assert(rep);
        if (rep->body_pipe != NULL)
            rep->body_pipe->expectNoConsumption();

        return;
    }

    HttpReply *rep = dynamic_cast<HttpReply*>(msg);
    assert(rep);
    debugs(11,5, HERE << this << " setting adapted reply to " << rep);
    setFinalReply(rep);

    assert(!adaptedBodySource);
    if (rep->body_pipe != NULL) {
        // subscribe to receive adapted body
        adaptedBodySource = rep->body_pipe;
        // assume that ICAP does not auto-consume on failures
        assert(adaptedBodySource->setConsumerIfNotLate(this));
    } else {
        // no body
        if (doneWithAdaptation()) // we may still be sending virgin response
            handleAdaptationCompleted();
    }
}

// will not receive adapted response headers (and, hence, body)
void
ServerStateData::noteAdaptationQueryAbort(bool final)
{
    clearAdaptation(adaptedHeadSource);
    handleAdaptationAborted(!final);
}

void
ServerStateData::resumeBodyStorage()
{
    if (abortOnBadEntry("store entry aborted while kick producer callback"))
        return;

    if (!adaptedBodySource)
        return;

    handleMoreAdaptedBodyAvailable();

    if (adaptedBodySource != NULL && adaptedBodySource->exhausted())
        endAdaptedBodyConsumption();
}

// more adapted response body is available
void
ServerStateData::handleMoreAdaptedBodyAvailable()
{
    if (abortOnBadEntry("entry refuses adapted body"))
        return;

    assert(entry);

    size_t contentSize = adaptedBodySource->buf().contentSize();

    if (!contentSize)
        return; // XXX: bytesWanted asserts on zero-size ranges

    const size_t spaceAvailable = entry->bytesWanted(Range<size_t>(0, contentSize));

    if (spaceAvailable < contentSize ) {
        // No or partial body data consuming
        typedef NullaryMemFunT<ServerStateData> Dialer;
        AsyncCall::Pointer call = asyncCall(93, 5, "ServerStateData::resumeBodyStorage",
                                            Dialer(this, &ServerStateData::resumeBodyStorage));
        entry->deferProducer(call);
    }

    if (!spaceAvailable)  {
        debugs(11, 5, HERE << "NOT storing " << contentSize << " bytes of adapted " <<
               "response body at offset " << adaptedBodySource->consumedSize());
        return;
    }

    if (spaceAvailable < contentSize ) {
        debugs(11, 5, HERE << "postponing storage of " <<
               (contentSize - spaceAvailable) << " body bytes");
        contentSize = spaceAvailable;
    }

    debugs(11,5, HERE << "storing " << contentSize << " bytes of adapted " <<
           "response body at offset " << adaptedBodySource->consumedSize());

    BodyPipeCheckout bpc(*adaptedBodySource);
    const StoreIOBuffer ioBuf(&bpc.buf, currentOffset, contentSize);
    currentOffset += ioBuf.length;
    entry->write(ioBuf);
    bpc.buf.consume(contentSize);
    bpc.checkIn();
}

// the entire adapted response body was produced, successfully
void
ServerStateData::handleAdaptedBodyProductionEnded()
{
    if (abortOnBadEntry("entry went bad while waiting for adapted body eof"))
        return;

    // end consumption if we consumed everything
    if (adaptedBodySource != NULL && adaptedBodySource->exhausted())
        endAdaptedBodyConsumption();
    // else resumeBodyStorage() will eventually consume the rest
}

void
ServerStateData::endAdaptedBodyConsumption()
{
    stopConsumingFrom(adaptedBodySource);
    handleAdaptationCompleted();
}

// premature end of the adapted response body
void ServerStateData::handleAdaptedBodyProducerAborted()
{
    stopConsumingFrom(adaptedBodySource);
    handleAdaptationAborted();
}

// common part of noteAdaptationAnswer and handleAdaptedBodyProductionEnded
void
ServerStateData::handleAdaptationCompleted()
{
    debugs(11,5, HERE << "handleAdaptationCompleted");
    cleanAdaptation();

    // We stop reading origin response because we have no place to put it and
    // cannot use it. If some origin servers do not like that or if we want to
    // reuse more pconns, we can add code to discard unneeded origin responses.
    if (!doneWithServer()) {
        debugs(11,3, HERE << "closing origin conn due to ICAP completion");
        closeServer();
    }

    completeForwarding();
    quitIfAllDone();
}


// common part of noteAdaptation*Aborted and noteBodyConsumerAborted methods
void
ServerStateData::handleAdaptationAborted(bool bypassable)
{
    debugs(11,5, HERE << "handleAdaptationAborted; bypassable: " << bypassable <<
           ", entry empty: " << entry->isEmpty());

    if (abortOnBadEntry("entry went bad while ICAP aborted"))
        return;

    // TODO: bypass if possible

    if (entry->isEmpty()) {
        debugs(11,9, HERE << "creating ICAP error entry after ICAP failure");
        ErrorState *err = errorCon(ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR, request);
        err->xerrno = errno;
        fwd->fail(err);
        fwd->dontRetry(true);
    }

    abortTransaction("ICAP failure");
}

void
ServerStateData::adaptationAclCheckDone(Adaptation::ServiceGroupPointer group)
{
    adaptationAccessCheckPending = false;

    if (abortOnBadEntry("entry went bad while waiting for ICAP ACL check"))
        return;

    // TODO: Should nonICAP and postICAP path check this on the server-side?
    // That check now only happens on client-side, in processReplyAccess().
    if (virginReply()->expectedBodyTooLarge(*request)) {
        sendBodyIsTooLargeError();
        return;
    }
    // TODO: Should we check receivedBodyTooLarge on the server-side as well?

    if (!group) {
        debugs(11,3, HERE << "no adapation needed");
        setFinalReply(virginReply());
        processReplyBody();
        return;
    }

    startAdaptation(group, originalRequest());
    processReplyBody();
}

void
ServerStateData::adaptationAclCheckDoneWrapper(Adaptation::ServiceGroupPointer group, void *data)
{
    ServerStateData *state = (ServerStateData *)data;
    state->adaptationAclCheckDone(group);
}
#endif

void
ServerStateData::sendBodyIsTooLargeError()
{
    ErrorState *err = errorCon(ERR_TOO_BIG, HTTP_FORBIDDEN, request);
    err->xerrno = errno;
    fwd->fail(err);
    fwd->dontRetry(true);
    abortTransaction("Virgin body too large.");
}

// TODO: when HttpStateData sends all errors to ICAP,
// we should be able to move this at the end of setVirginReply().
void
ServerStateData::adaptOrFinalizeReply()
{
#if USE_ADAPTATION
    // TODO: merge with client side and return void to hide the on/off logic?
    // The callback can be called with a NULL service if adaptation is off.
    adaptationAccessCheckPending = Adaptation::AccessCheck::Start(
                                       Adaptation::methodRespmod, Adaptation::pointPreCache,
                                       originalRequest(), virginReply(), adaptationAclCheckDoneWrapper, this);
    debugs(11,5, HERE << "adaptationAccessCheckPending=" << adaptationAccessCheckPending);
    if (adaptationAccessCheckPending)
        return;
#endif

    setFinalReply(virginReply());
}

void
ServerStateData::addVirginReplyBody(const char *data, ssize_t len)
{
#if USE_ADAPTATION
    assert(!adaptationAccessCheckPending); // or would need to buffer while waiting
    if (startedAdaptation) {
        adaptVirginReplyBody(data, len);
        return;
    }
#endif
    storeReplyBody(data, len);
}

// writes virgin or adapted reply body to store
void
ServerStateData::storeReplyBody(const char *data, ssize_t len)
{
    // write even if len is zero to push headers towards the client side
    entry->write (StoreIOBuffer(len, currentOffset, (char*)data));

    currentOffset += len;
}

size_t ServerStateData::replyBodySpace(const MemBuf &readBuf,
                                       const size_t minSpace) const
{
    size_t space = readBuf.spaceSize(); // available space w/o heroic measures
    if (space < minSpace) {
        const size_t maxSpace = readBuf.potentialSpaceSize(); // absolute best
        space = min(minSpace, maxSpace); // do not promise more than asked
    }

#if USE_ADAPTATION
    if (responseBodyBuffer) {
        return 0;	// Stop reading if already overflowed waiting for ICAP to catch up
    }

    if (virginBodyDestination != NULL) {
        /*
         * BodyPipe buffer has a finite size limit.  We
         * should not read more data from the network than will fit
         * into the pipe buffer or we _lose_ what did not fit if
         * the response ends sooner that BodyPipe frees up space:
         * There is no code to keep pumping data into the pipe once
         * response ends and serverComplete() is called.
         *
         * If the pipe is totally full, don't register the read handler.
         * The BodyPipe will call our noteMoreBodySpaceAvailable() method
         * when it has free space again.
         */
        size_t adaptation_space =
            virginBodyDestination->buf().potentialSpaceSize();

        debugs(11,9, "ServerStateData may read up to min(" <<
               adaptation_space << ", " << space << ") bytes");

        if (adaptation_space < space)
            space = adaptation_space;
    }
#endif

    return space;
}
