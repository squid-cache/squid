
/*
 * $Id$
 *
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


#ifndef SQUID_CLIENTSIDEREQUEST_H
#define SQUID_CLIENTSIDEREQUEST_H

#include "squid.h"
#include "HttpHeader.h"
#include "clientStream.h"
#include "client_side.h"
#include "AccessLogEntry.h"
#include "dlink.h"
#include "base/AsyncJob.h"

#if USE_ADAPTATION
#include "adaptation/forward.h"
#include "adaptation/Initiator.h"

class HttpMsg;
#endif

/* client_side_request.c - client side request related routines (pure logic) */
extern int clientBeginRequest(const HttpRequestMethod&, char const *, CSCB *, CSD *, ClientStreamData, HttpHeader const *, char *, size_t);

class MemObject;

class ConnStateData;

class ClientRequestContext;

class ClientHttpRequest
#if USE_ADAPTATION
        : public Adaptation::Initiator, // to start adaptation transactions
        public BodyConsumer     // to receive reply bodies in request satisf. mode
#endif
{

public:
    void *operator new (size_t);
    void operator delete (void *);
#if USE_ADAPTATION
    void *toCbdata() { return this; }
#endif
    ClientHttpRequest(ConnStateData *);
    ~ClientHttpRequest();
    /* Not implemented - present to prevent synthetic operations */
    ClientHttpRequest(ClientHttpRequest const &);
    ClientHttpRequest& operator=(ClientHttpRequest const &);

    String rangeBoundaryStr() const;
    void freeResources();
    void updateCounters();
    void logRequest();
    _SQUID_INLINE_ MemObject * memObject() const;
    bool multipartRangeRequest() const;
    void processRequest();
    void httpStart();
    bool onlyIfCached()const;
    bool gotEnough() const;
    _SQUID_INLINE_ StoreEntry *storeEntry() const;
    void storeEntry(StoreEntry *);
    _SQUID_INLINE_ StoreEntry *loggingEntry() const;
    void loggingEntry(StoreEntry *);

    _SQUID_INLINE_ ConnStateData * getConn();
    _SQUID_INLINE_ ConnStateData * const getConn() const;
    _SQUID_INLINE_ void setConn(ConnStateData *);
    HttpRequest *request;		/* Parsed URL ... */
    char *uri;
    char *log_uri;

    struct {
        int64_t offset;
        int64_t size;
        size_t headers_sz;
    } out;

    HttpHdrRangeIter range_iter;	/* data for iterating thru range specs */
    size_t req_sz;		/* raw request size on input, not current request size */
    log_type logType;

    struct timeval start_time;
    AccessLogEntry al;

    struct {
        unsigned int accel:1;
        unsigned int intercepted:1;
        unsigned int spoof_client_ip:1;
        unsigned int internal:1;
        unsigned int done_copying:1;
        unsigned int purging:1;
    } flags;

    struct {
        http_status status;
        char *location;
    } redirect;

    dlink_node active;
    dlink_list client_stream;
    int mRangeCLen();

    ClientRequestContext *calloutContext;
    void doCallouts();

#if USE_ADAPTATION
    // AsyncJob virtual methods
    virtual bool doneAll() const {
        return Initiator::doneAll() &&
               BodyConsumer::doneAll() && false;
    }
#endif

private:
    CBDATA_CLASS(ClientHttpRequest);
    int64_t maxReplyBodySize_;
    StoreEntry *entry_;
    StoreEntry *loggingEntry_;
    ConnStateData * conn_;

#if USE_SSL
public:
    bool sslBumpNeeded() const;
    void sslBumpStart();
    void sslBumpEstablish(comm_err_t errflag);
#endif

#if USE_ADAPTATION

public:
    void startAdaptation(const Adaptation::ServiceGroupPointer &g);

    // private but exposed for ClientRequestContext
    void handleAdaptationFailure(bool bypassable = false);

private:
    // Adaptation::Initiator API
    virtual void noteAdaptationAnswer(HttpMsg *message);
    virtual void noteAdaptationQueryAbort(bool final);

    // BodyConsumer API, called by BodyPipe
    virtual void noteMoreBodyDataAvailable(BodyPipe::Pointer);
    virtual void noteBodyProductionEnded(BodyPipe::Pointer);
    virtual void noteBodyProducerAborted(BodyPipe::Pointer);

    void endRequestSatisfaction();

private:
    Adaptation::Initiate *virginHeadSource;
    BodyPipe::Pointer adaptedBodySource;

    bool request_satisfaction_mode;
    int64_t request_satisfaction_offset;
#endif
};

/* client http based routines */
SQUIDCEXTERN char *clientConstructTraceEcho(ClientHttpRequest *);

class ACLFilledChecklist;
SQUIDCEXTERN ACLFilledChecklist *clientAclChecklistCreate(const acl_access * acl,ClientHttpRequest * http);
SQUIDCEXTERN int clientHttpRequestStatus(int fd, ClientHttpRequest const *http);
SQUIDCEXTERN void clientAccessCheck(ClientHttpRequest *);

/* ones that should be elsewhere */
SQUIDCEXTERN void redirectStart(ClientHttpRequest *, RH *, void *);

SQUIDCEXTERN void tunnelStart(ClientHttpRequest *, int64_t *, int *);

#ifdef _USE_INLINE_
#include "Store.h"
#include "client_side_request.cci"
#endif

#endif /* SQUID_CLIENTSIDEREQUEST_H */
