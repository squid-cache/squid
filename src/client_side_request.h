/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CLIENTSIDEREQUEST_H
#define SQUID_CLIENTSIDEREQUEST_H

#include "AccessLogEntry.h"
#include "acl/forward.h"
#include "client_side.h"
#include "clientStream.h"
#include "HttpHeaderRange.h"
#include "LogTags.h"

#if USE_ADAPTATION
#include "adaptation/forward.h"
#include "adaptation/Initiator.h"
class HttpMsg;
#endif

class ClientRequestContext;
class ConnStateData;
class MemObject;

/* client_side_request.c - client side request related routines (pure logic) */
int clientBeginRequest(const HttpRequestMethod&, char const *, CSCB *, CSD *, ClientStreamData, HttpHeader const *, char *, size_t);

class ClientHttpRequest
#if USE_ADAPTATION
    : public Adaptation::Initiator, // to start adaptation transactions
      public BodyConsumer     // to receive reply bodies in request satisf. mode
#endif
{

public:
    ClientHttpRequest(ConnStateData *csd);
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

    _SQUID_INLINE_ ConnStateData * getConn() const;
    _SQUID_INLINE_ void setConn(ConnStateData *);

    /** Details of the client socket which produced us.
     * Treat as read-only for the lifetime of this HTTP request.
     */
    Comm::ConnectionPointer clientConnection;

    HttpRequest *request;       /* Parsed URL ... */
    char *uri;
    char *log_uri;
    String store_id; /* StoreID for transactions where the request member is nil */

    struct {
        int64_t offset;
        uint64_t size;
        size_t headers_sz;
    } out;

    HttpHdrRangeIter range_iter;    /* data for iterating thru range specs */
    size_t req_sz;      /* raw request size on input, not current request size */

    /// the processing tags associated with this request transaction.
    // NP: still an enum so each stage altering it must take care when replacing it.
    LogTags logType;

    AccessLogEntry::Pointer al; ///< access.log entry

    struct {
        bool accel;
        //bool intercepted; //XXX: it's apparently never used.
        //bool spoof_client_ip; //XXX: it's apparently never used.
        bool internal;
        bool done_copying;
        bool purging;
    } flags;

    struct {
        Http::StatusCode status;
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
    virtual void callException(const std::exception &ex);
#endif

private:
    int64_t maxReplyBodySize_;
    StoreEntry *entry_;
    StoreEntry *loggingEntry_;
    ConnStateData * conn_;

#if USE_OPENSSL
    /// whether (and how) the request needs to be bumped
    Ssl::BumpMode sslBumpNeed_;

public:
    /// returns raw sslBump mode value
    Ssl::BumpMode sslBumpNeed() const { return sslBumpNeed_; }
    /// returns true if and only if the request needs to be bumped
    bool sslBumpNeeded() const { return sslBumpNeed_ == Ssl::bumpServerFirst || sslBumpNeed_ == Ssl::bumpClientFirst || sslBumpNeed_ == Ssl::bumpBump || sslBumpNeed_ == Ssl::bumpPeek || sslBumpNeed_ == Ssl::bumpStare; }
    /// set the sslBumpNeeded state
    void sslBumpNeed(Ssl::BumpMode mode);
    void sslBumpStart();
    void sslBumpEstablish(Comm::Flag errflag);
#endif

#if USE_ADAPTATION

public:
    void startAdaptation(const Adaptation::ServiceGroupPointer &g);
    bool requestSatisfactionMode() const { return request_satisfaction_mode; }

    // private but exposed for ClientRequestContext
    void handleAdaptationFailure(int errDetail, bool bypassable = false);

private:
    // Adaptation::Initiator API
    virtual void noteAdaptationAnswer(const Adaptation::Answer &answer);
    void handleAdaptedHeader(HttpMsg *msg);
    void handleAdaptationBlock(const Adaptation::Answer &answer);
    virtual void noteAdaptationAclCheckDone(Adaptation::ServiceGroupPointer group);

    // BodyConsumer API, called by BodyPipe
    virtual void noteMoreBodyDataAvailable(BodyPipe::Pointer);
    virtual void noteBodyProductionEnded(BodyPipe::Pointer);
    virtual void noteBodyProducerAborted(BodyPipe::Pointer);

    void endRequestSatisfaction();
    /// called by StoreEntry when it has more buffer space available
    void resumeBodyStorage();

private:
    CbcPointer<Adaptation::Initiate> virginHeadSource;
    BodyPipe::Pointer adaptedBodySource;

    bool request_satisfaction_mode;
    int64_t request_satisfaction_offset;
#endif

private:
    CBDATA_CLASS2(ClientHttpRequest);
};

/* client http based routines */
char *clientConstructTraceEcho(ClientHttpRequest *);

ACLFilledChecklist *clientAclChecklistCreate(const acl_access * acl,ClientHttpRequest * http);
int clientHttpRequestStatus(int fd, ClientHttpRequest const *http);
void clientAccessCheck(ClientHttpRequest *);

/* ones that should be elsewhere */
void tunnelStart(ClientHttpRequest *);

#if _USE_INLINE_
#include "client_side_request.cci"
#include "Store.h"
#endif

#endif /* SQUID_CLIENTSIDEREQUEST_H */

