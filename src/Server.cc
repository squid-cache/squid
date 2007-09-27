/*
 * $Id: Server.cc,v 1.23 2007/09/27 14:34:06 rousskov Exp $
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
#include "HttpRequest.h"
#include "HttpReply.h"
#include "errorpage.h"

#if ICAP_CLIENT
#include "ICAP/ICAPModXact.h"
#include "ICAP/ICAPConfig.h"
extern ICAPConfig TheICAPConfig;
#endif

ServerStateData::ServerStateData(FwdState *theFwdState): requestSender(NULL)
#if ICAP_CLIENT
    , icapAccessCheckPending(false)
#endif
{
    fwd = theFwdState;
    entry = fwd->entry;

    entry->lock();

    request = HTTPMSGLOCK(fwd->request);
}

ServerStateData::~ServerStateData()
{
    entry->unlock();

    HTTPMSGUNLOCK(request);
    HTTPMSGUNLOCK(theVirginReply);
    HTTPMSGUNLOCK(theFinalReply);

    fwd = NULL; // refcounted

    if (requestBodySource != NULL)
        requestBodySource->clearConsumer();

#if ICAP_CLIENT
    cleanIcap();
#endif

    if (responseBodyBuffer != NULL) {
	delete responseBodyBuffer;
	responseBodyBuffer = NULL;
    }
}

HttpReply *
ServerStateData::virginReply() {
    assert(theVirginReply);
    return theVirginReply;
}

const HttpReply *
ServerStateData::virginReply() const {
    assert(theVirginReply);
    return theVirginReply;
}

HttpReply *
ServerStateData::setVirginReply(HttpReply *rep) {
    debugs(11,5, HERE << this << " setting virgin reply to " << rep);
    assert(!theVirginReply);
    assert(rep);
    theVirginReply = HTTPMSGLOCK(rep);
	return theVirginReply;
}

HttpReply *
ServerStateData::finalReply() {
    assert(theFinalReply);
    return theFinalReply;
}

HttpReply *
ServerStateData::setFinalReply(HttpReply *rep) {
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

#if ICAP_CLIENT
    if (virginBodyDestination != NULL)
        stopProducingFor(virginBodyDestination, true);

    if (!doneWithIcap())
        return;
#endif

    completeForwarding();
    quitIfAllDone();
}

// When we are done talking to the primary server, we may be still talking 
// to the ICAP service. And vice versa. Here, we quit only if we are done
// talking to both.
void ServerStateData::quitIfAllDone() {
#if ICAP_CLIENT
    if (!doneWithIcap()) {
        debugs(11,5, HERE << "transaction not done: still talking to ICAP");
        return;
    }
#endif

    if (!doneWithServer()) {
        debugs(11,5, HERE << "transaction not done: still talking to server");
        return;
    }

    debugs(11,3, HERE << "transaction done");
    delete this;
}

// FTP side overloads this to work around multiple calls to fwd->complete
void
ServerStateData::completeForwarding() {
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
ServerStateData::noteMoreBodyDataAvailable(BodyPipe &bp)
{
#if ICAP_CLIENT
    if (adaptedBodySource == &bp) {
        handleMoreAdaptedBodyAvailable();
        return;
    }
#endif
    handleMoreRequestBodyAvailable();
}

// the entire request or adapted response body was provided, successfully
void
ServerStateData::noteBodyProductionEnded(BodyPipe &bp)
{
#if ICAP_CLIENT
    if (adaptedBodySource == &bp) {
        handleAdaptedBodyProductionEnded();
        return;
    }
#endif
    handleRequestBodyProductionEnded();
}

// premature end of the request or adapted response body production
void
ServerStateData::noteBodyProducerAborted(BodyPipe &bp)
{
#if ICAP_CLIENT
    if (adaptedBodySource == &bp) {
        handleAdaptedBodyProducerAborted();
        return;
    }
#endif
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
ServerStateData::doneSendingRequestBody() {
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

void
ServerStateData::sentRequestBodyWrapper(int fd, char *bufnotused, size_t size, comm_err_t errflag, int xerrno, void *data)
{
    ServerStateData *server = static_cast<ServerStateData *>(data);
    server->sentRequestBody(fd, size, errflag);
}

// called when we wrote request headers(!) or a part of the body
void
ServerStateData::sentRequestBody(int fd, size_t size, comm_err_t errflag)
{
    debugs(11, 5, "sentRequestBody: FD " << fd << ": size " << size << ": errflag " << errflag << ".");
    debugs(32,3,HERE << "sentRequestBody called");

    requestSender = NULL;

    if (size > 0) {
        fd_bytes(fd, size, FD_WRITE);
        kb_incr(&statCounter.server.all.kbytes_out, size);
        // kids should increment their counters
    }

    if (errflag == COMM_ERR_CLOSING)
        return;

    if (!requestBodySource) {
        debugs(9,3, HERE << "detected while-we-were-sending abort");
        return; // do nothing;
    }

    if (errflag) {
        debugs(11, 1, "sentRequestBody error: FD " << fd << ": " << xstrerr(errno));
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

void
ServerStateData::sendMoreRequestBody()
{
    assert(requestBodySource != NULL);
    assert(!requestSender);
    MemBuf buf;
    if (requestBodySource->getMoreData(buf)) {
        debugs(9,3, HERE << "will write " << buf.contentSize() << " request body bytes");
        requestSender = &ServerStateData::sentRequestBodyWrapper;
        comm_write_mbuf(dataDescriptor(), &buf, requestSender, this);
    } else {
        debugs(9,3, HERE << "will wait for more request body bytes or eof");
        requestSender = NULL;
    }
}

// called by noteIcapAnswer(), HTTP server overwrites this
void
ServerStateData::haveParsedReplyHeaders()
{
    // default does nothing
}

HttpRequest *
ServerStateData::originalRequest()
{
    return request;
}

#if ICAP_CLIENT
/*
 * Initiate an ICAP transaction.  Return true on success.
 * Caller will handle error condition by generating a Squid error message
 * or take other action.
 */
bool
ServerStateData::startIcap(ICAPServiceRep::Pointer service, HttpRequest *cause)
{
    debugs(11, 5, "ServerStateData::startIcap() called");
    if (!service) {
        debugs(11, 3, "ServerStateData::startIcap fails: lack of service");
        return false;
    }
    if (service->broken()) {
        debugs(11, 3, "ServerStateData::startIcap fails: broken service");
        return false;
    }

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

    adaptedHeadSource = initiateIcap(
        new ICAPModXactLauncher(this, vrep, cause, service));
    return true;
}

// properly cleans up ICAP-related state
// may be called multiple times
void ServerStateData::cleanIcap() {
    debugs(11,5, HERE << "cleaning ICAP; ACL: " << icapAccessCheckPending);

    if (virginBodyDestination != NULL)
        stopProducingFor(virginBodyDestination, false);

    announceInitiatorAbort(adaptedHeadSource);

    if (adaptedBodySource != NULL)
        stopConsumingFrom(adaptedBodySource);

    if (!icapAccessCheckPending) // we cannot cancel a pending callback
        assert(doneWithIcap()); // make sure the two methods are in sync
}

bool
ServerStateData::doneWithIcap() const {
    return !icapAccessCheckPending &&
        !virginBodyDestination && !adaptedHeadSource && !adaptedBodySource;
}

// sends virgin reply body to ICAP, buffering excesses if needed
void
ServerStateData::adaptVirginReplyBody(const char *data, ssize_t len)
{
    assert(startedIcap);

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
ServerStateData::noteMoreBodySpaceAvailable(BodyPipe &)
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
ServerStateData::noteBodyConsumerAborted(BodyPipe &bp)
{
    stopProducingFor(virginBodyDestination, false);

    // do not force closeServer here in case we need to bypass IcapQueryAbort

    if (doneWithIcap()) // we may still be receiving adapted response
        handleIcapCompleted();
}

// received adapted response headers (body may follow)
void
ServerStateData::noteIcapAnswer(HttpMsg *msg)
{
    clearIcap(adaptedHeadSource); // we do not expect more messages

    if (abortOnBadEntry("entry went bad while waiting for adapted headers"))
        return;

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
        if (doneWithIcap()) // we may still be sending virgin response
            handleIcapCompleted();
    }

}

// will not receive adapted response headers (and, hence, body)
void
ServerStateData::noteIcapQueryAbort(bool final)
{
    clearIcap(adaptedHeadSource);
    handleIcapAborted(!final);
}

// more adapted response body is available
void
ServerStateData::handleMoreAdaptedBodyAvailable()
{
    const size_t contentSize = adaptedBodySource->buf().contentSize();

    debugs(11,5, HERE << "consuming " << contentSize << " bytes of adapted " <<
           "response body at offset " << adaptedBodySource->consumedSize());

    if (abortOnBadEntry("entry refuses adapted body"))
        return;

    assert(entry);
    BodyPipeCheckout bpc(*adaptedBodySource);
    const StoreIOBuffer ioBuf(&bpc.buf, bpc.offset);
    entry->write(ioBuf);
    bpc.buf.consume(contentSize);
    bpc.checkIn();
}

// the entire adapted response body was produced, successfully
void
ServerStateData::handleAdaptedBodyProductionEnded()
{
    stopConsumingFrom(adaptedBodySource);

    if (abortOnBadEntry("entry went bad while waiting for adapted body eof"))
        return;

    handleIcapCompleted();
}

// premature end of the adapted response body
void ServerStateData::handleAdaptedBodyProducerAborted()
{
    stopConsumingFrom(adaptedBodySource);
    handleIcapAborted();
}

// common part of noteIcapAnswer and handleAdaptedBodyProductionEnded
void
ServerStateData::handleIcapCompleted()
{
    debugs(11,5, HERE << "handleIcapCompleted");
    cleanIcap();

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


// common part of noteIcap*Aborted and noteBodyConsumerAborted methods
void
ServerStateData::handleIcapAborted(bool bypassable)
{
    debugs(11,5, HERE << "handleIcapAborted; bypassable: " << bypassable <<
        ", entry empty: " << entry->isEmpty());

    if (abortOnBadEntry("entry went bad while ICAP aborted"))
        return;

    // TODO: bypass if possible

    if (entry->isEmpty()) {
        debugs(11,9, HERE << "creating ICAP error entry after ICAP failure");
        ErrorState *err =
            errorCon(ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR, request);
        err->xerrno = errno;
        fwd->fail(err);
        fwd->dontRetry(true);
    }

    abortTransaction("ICAP failure");
}

void
ServerStateData::icapAclCheckDone(ICAPServiceRep::Pointer service)
{
    icapAccessCheckPending = false;

    if (abortOnBadEntry("entry went bad while waiting for ICAP ACL check"))
        return;

    startedIcap = startIcap(service, originalRequest());

    if (!startedIcap && (!service || service->bypass)) {
        // handle ICAP start failure when no service was selected
        // or where the selected service was optional
        setFinalReply(virginReply());
        processReplyBody();
        return;
    }

    if (!startedIcap) {
        // handle start failure for an essential ICAP service
        ErrorState *err = errorCon(ERR_ICAP_FAILURE,
            HTTP_INTERNAL_SERVER_ERROR, originalRequest());
        err->xerrno = errno;
        errorAppendEntry(entry, err);
        abortTransaction("ICAP start failure");
        return;
    }

    processReplyBody();
}

void
ServerStateData::icapAclCheckDoneWrapper(ICAPServiceRep::Pointer service, void *data)
{
    ServerStateData *state = (ServerStateData *)data;
    state->icapAclCheckDone(service);
}
#endif

// TODO: when HttpStateData sends all errors to ICAP, 
// we should be able to move this at the end of setVirginReply().
void
ServerStateData::adaptOrFinalizeReply()
{
#if ICAP_CLIENT

    if (TheICAPConfig.onoff) {
        ICAPAccessCheck *icap_access_check =
            new ICAPAccessCheck(ICAP::methodRespmod, ICAP::pointPreCache,
                request, virginReply(), icapAclCheckDoneWrapper, this);

        icapAccessCheckPending = true;
        icap_access_check->check(); // will eventually delete self
        return;
    }

#endif

    setFinalReply(virginReply());
}

void
ServerStateData::addVirginReplyBody(const char *data, ssize_t len)
{
#if ICAP_CLIENT
    assert(!icapAccessCheckPending); // or would need to buffer while waiting
    if (startedIcap) {
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

size_t ServerStateData::replyBodySpace(size_t space)
{
#if ICAP_CLIENT
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
        size_t icap_space = virginBodyDestination->buf().potentialSpaceSize();

        debugs(11,9, "ServerStateData may read up to min(" << icap_space <<
               ", " << space << ") bytes");

        if (icap_space < space)
            space = icap_space;
    }
#endif

    return space;
}
