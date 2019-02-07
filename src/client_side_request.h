/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
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
#include "http/forward.h"
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
int clientBeginRequest(const HttpRequestMethod&, char const *, CSCB *, CSD *, ClientStreamData, HttpHeader const *, char *, size_t, const MasterXactionPointer &);

class ClientHttpRequest
#if USE_ADAPTATION
    : public Adaptation::Initiator, // to start adaptation transactions
      public BodyConsumer     // to receive reply bodies in request satisf. mode
#endif
{
    CBDATA_CLASS(ClientHttpRequest);

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

    /// Initializes the current request with the virgin request.
    /// Call this method when the virgin request becomes known.
    /// To update the current request later, use resetRequest().
    void initRequest(HttpRequest *);

    /// Resets the current request to the latest adapted or redirected
    /// request. Call this every time adaptation or redirection changes
    /// the request. To set the virgin request, use initRequest().
    void resetRequest(HttpRequest *);

    /** Details of the client socket which produced us.
     * Treat as read-only for the lifetime of this HTTP request.
     */
    Comm::ConnectionPointer clientConnection;

    /// Request currently being handled by ClientHttpRequest.
    /// Starts as a virgin request; see initRequest().
    /// Usually remains nil until the virgin request header is parsed or faked.
    /// Adaptation and redirections replace it; see resetRequest().
    HttpRequest * const request;
    /// Usually starts as a URI received from the client, with scheme and host
    /// added if needed. Is used to create the virgin request for initRequest().
    /// URIs of adapted/redirected requests replace it via resetRequest().
    char *uri;

    // TODO: remove this field and store the URI directly in al->url
    /// Cleaned up URI of the current (virgin or adapted/redirected) request,
    /// computed URI of an internally-generated requests, or
    /// one of the hard-coded "error:..." URIs.
    char * const log_uri;

    String store_id; /* StoreID for transactions where the request member is nil */

    struct Out {
        Out() : offset(0), size(0), headers_sz(0) {}

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

    struct Flags {
        Flags() : accel(false), internal(false), done_copying(false), purging(false) {}

        bool accel;
        bool internal;
        bool done_copying;
        bool purging;
    } flags;

    struct Redirect {
        Redirect() : status(Http::scNone), location(NULL) {}

        Http::StatusCode status;
        char *location;
    } redirect;

    dlink_node active;
    dlink_list client_stream;
    int mRangeCLen();

    ClientRequestContext *calloutContext;
    void doCallouts();

    // The three methods below prepare log_uri and friends for future logging.
    // Call the best-fit method whenever the current request or its URI changes.

    /// sets log_uri when we know the current request
    void setLogUriToRequestUri();
    /// sets log_uri to a parsed request URI when Squid fails to parse or
    /// validate other request components, yielding no current request
    void setLogUriToRawUri(const char *rawUri, const HttpRequestMethod &);
    /// sets log_uri and uri to an internally-generated "error:..." URI when
    /// neither the current request nor the parsed request URI are known
    void setErrorUri(const char *errorUri);

    /// Build an error reply. For use with the callouts.
    void calloutsError(const err_type error, const int errDetail);

#if USE_ADAPTATION
    // AsyncJob virtual methods
    virtual bool doneAll() const {
        return Initiator::doneAll() &&
               BodyConsumer::doneAll() && false;
    }
    virtual void callException(const std::exception &ex);
#endif

private:
    /// assigns log_uri with aUri without copying the entire C-string
    void absorbLogUri(char *aUri);
    /// resets the current request and log_uri to nil
    void clearRequest();
    /// initializes the current unassigned request to the virgin request
    /// sets the current request, asserting that it was unset
    void assignRequest(HttpRequest *aRequest);

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

private:
    /// Handles an adaptation client request failure.
    /// Bypasses the error if possible, or build an error reply.
    void handleAdaptationFailure(int errDetail, bool bypassable = false);

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

