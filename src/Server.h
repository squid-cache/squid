
/*
 * $Id: Server.h,v 1.9 2007/08/09 23:30:52 rousskov Exp $
 *
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

/*
 * ServerStateData is a common base for server-side classes such as
 * HttpStateData and FtpStateData. All such classes must be able to
 * consume request bodies from the client-side or ICAP producer, adapt
 * virgin responses using ICAP, and provide the client-side consumer with
 * responses.
 *
 * TODO: Rename to ServerStateDataInfoRecordHandler.
 */


#ifndef SQUID_SERVER_H
#define SQUID_SERVER_H

#include "StoreIOBuffer.h"
#include "forward.h"
#include "BodyPipe.h"

#if ICAP_CLIENT
#include "ICAP/ICAPServiceRep.h"
#include "ICAP/ICAPInitiator.h"

class ICAPAccessCheck;
#endif

class ServerStateData:
#if ICAP_CLIENT
    public ICAPInitiator,
    public BodyProducer,
#endif
    public BodyConsumer
{

public:
    ServerStateData(FwdState *);
    virtual ~ServerStateData();

    // returns primary or "request data connection" fd
    virtual int dataDescriptor() const = 0; 

    // BodyConsumer: consume request body or adapted response body.
    // The implementation just calls the corresponding HTTP or ICAP handle*()
    // method, depending on the pipe.
    virtual void noteMoreBodyDataAvailable(BodyPipe &);
    virtual void noteBodyProductionEnded(BodyPipe &);
    virtual void noteBodyProducerAborted(BodyPipe &);

    // read response data from the network
    virtual void maybeReadVirginBody() = 0;

    // abnormal transaction termination; reason is for debugging only
    virtual void abortTransaction(const char *reason) = 0;

    // a hack to reach HttpStateData::orignal_request
    virtual  HttpRequest *originalRequest();

#if ICAP_CLIENT
    void icapAclCheckDone(ICAPServiceRep::Pointer);
    static void icapAclCheckDoneWrapper(ICAPServiceRep::Pointer service, void *data);

    // ICAPInitiator: start an ICAP transaction and receive adapted headers.
    virtual void noteIcapAnswer(HttpMsg *message);
    virtual void noteIcapQueryAbort(bool final);

    // BodyProducer: provide virgin response body to ICAP.
    virtual void noteMoreBodySpaceAvailable(BodyPipe &);
    virtual void noteBodyConsumerAborted(BodyPipe &);
#endif
    virtual void processReplyBody() = 0;

public: // should be protected
    void serverComplete(); // call when no server communication is expected

private:
    void serverComplete2(); // Continuation of serverComplete
    bool completed;	// serverComplete() has been called

protected:
    // kids customize these
    virtual void haveParsedReplyHeaders(); // default does nothing
    virtual void completeForwarding(); // default calls fwd->complete()

    // BodyConsumer for HTTP: consume request body.
    void handleMoreRequestBodyAvailable();
    void handleRequestBodyProductionEnded();
    virtual void handleRequestBodyProducerAborted() = 0;

    // sending of the request body to the server
    void sendMoreRequestBody();
    // has body; kids overwrite to increment I/O stats counters
    virtual void sentRequestBody(int fd, size_t size, comm_err_t errflag) = 0;
    virtual void doneSendingRequestBody() = 0;
    static IOCB sentRequestBodyWrapper;

    virtual void closeServer() = 0; // end communication with the server
    virtual bool doneWithServer() const = 0; // did we end communication?

    // Entry-dependent callbacks use this check to quit if the entry went bad
    bool abortOnBadEntry(const char *abortReason);

#if ICAP_CLIENT
    bool startIcap(ICAPServiceRep::Pointer, HttpRequest *cause);
    void adaptVirginReplyBody(const char *buf, ssize_t len);
    void cleanIcap();
    virtual bool doneWithIcap() const; // did we end ICAP communication?

    // BodyConsumer for ICAP: consume adapted response body.
    void handleMoreAdaptedBodyAvailable();
    void handleAdaptedBodyProductionEnded();
    void handleAdaptedBodyProducerAborted();

    void handleIcapCompleted();
    void handleIcapAborted(bool bypassable = false);
#endif

protected:
    const HttpReply *virginReply() const;
    HttpReply *virginReply();
    HttpReply *setVirginReply(HttpReply *r);

    HttpReply *finalReply();
    HttpReply *setFinalReply(HttpReply *r);

    // Kids use these to stuff data into the response instead of messing with the entry directly
    void adaptOrFinalizeReply();
    void addVirginReplyBody(const char *buf, ssize_t len);
    void storeReplyBody(const char *buf, ssize_t len);
    size_t replyBodySpace(size_t space = 4096 * 10);

    // These should be private
    off_t currentOffset;	// Our current offset in the StoreEntry
    MemBuf *responseBodyBuffer;	// Data temporarily buffered for ICAP

public: // should not be
    StoreEntry *entry;
    FwdState::Pointer fwd;
    HttpRequest *request;

protected:
    BodyPipe::Pointer requestBodySource; // to consume request body
    IOCB *requestSender; // set if we are expecting comm_write to call us back

#if ICAP_CLIENT
    BodyPipe::Pointer virginBodyDestination; // to provide virgin response body
    ICAPInitiate *adaptedHeadSource; // to get adapted response headers
    BodyPipe::Pointer adaptedBodySource; // to consume adated response body

    bool icapAccessCheckPending;
    bool startedIcap;
#endif

private:
    void quitIfAllDone(); // successful termination

	HttpReply *theVirginReply; // reply received from the origin server
	HttpReply *theFinalReply; // adapted reply from ICAP or virgin reply
};

#endif /* SQUID_SERVER_H */
