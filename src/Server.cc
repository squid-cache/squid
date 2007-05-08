/*
 * $Id: Server.cc,v 1.11 2007/05/08 16:45:00 rousskov Exp $
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
#endif

ServerStateData::ServerStateData(FwdState *theFwdState): requestSender(NULL)
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
    HTTPMSGUNLOCK(reply);

    fwd = NULL; // refcounted

    if (requestBodySource != NULL)
        requestBodySource->clearConsumer();

#if ICAP_CLIENT
    cleanIcap();
#endif
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

    if (requestBodySource != NULL)
        stopConsumingFrom(requestBodySource);

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
    assert(!virginBodyDestination);
    assert(!reply->body_pipe);
    // start body pipe to feed ICAP transaction if needed
    ssize_t size = 0;
    if (reply->expectingBody(cause->method, size) && size) {
        virginBodyDestination = new BodyPipe(this);
        reply->body_pipe = virginBodyDestination;
        debugs(93, 6, HERE << "will send virgin reply body to " << 
            virginBodyDestination << "; size: " << size);
    }

    adaptedHeadSource = initiateIcap(
        new ICAPModXactLauncher(this, reply, cause, service));
    return true;
}

// properly cleans up ICAP-related state
// may be called multiple times
void ServerStateData::cleanIcap() {
    debugs(11,5, HERE << "cleaning ICAP");

    if (virginBodyDestination != NULL)
        stopProducingFor(virginBodyDestination, false);

    announceInitiatorAbort(adaptedHeadSource);

    if (adaptedBodySource != NULL)
        stopConsumingFrom(adaptedBodySource);

    assert(doneWithIcap()); // make sure the two methods are in sync
}

bool
ServerStateData::doneWithIcap() const {
    return !virginBodyDestination && !adaptedHeadSource && !adaptedBodySource;
}

// can supply more virgin response body data
void
ServerStateData::noteMoreBodySpaceAvailable(BodyPipe &)
{
    maybeReadVirginBody();
}

// the consumer of our virgin response body aborted, we should too
void
ServerStateData::noteBodyConsumerAborted(BodyPipe &bp)
{
    stopProducingFor(virginBodyDestination, false);
    handleIcapAborted();
}

// received adapted response headers (body may follow)
void
ServerStateData::noteIcapAnswer(HttpMsg *msg)
{
    HttpReply *rep = dynamic_cast<HttpReply*>(msg);
    HTTPMSGLOCK(rep);
    clearIcap(adaptedHeadSource); // we do not expect more messages

    if (abortOnBadEntry("entry went bad while waiting for adapted headers")) {
        HTTPMSGUNLOCK(rep); // hopefully still safe, even if "this" is deleted
        return;
    }

    assert(rep);
    entry->replaceHttpReply(rep);
    HTTPMSGUNLOCK(reply);

    reply = rep; // already HTTPMSGLOCKed above

    haveParsedReplyHeaders();

    assert(!adaptedBodySource);
    if (reply->body_pipe != NULL) {
        // subscribe to receive adapted body
        adaptedBodySource = reply->body_pipe;
        // assume that ICAP does not auto-consume on failures
        assert(adaptedBodySource->setConsumerIfNotLate(this));
    } else {
        // no body
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

#endif
