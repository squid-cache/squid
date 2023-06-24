/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CLIENTSIDEREQUEST_H
#define SQUID_CLIENTSIDEREQUEST_H

#include "AccessLogEntry.h"
#include "client_side.h"
#include "clientStream.h"
#include "http/forward.h"
#include "HttpHeaderRange.h"
#include "log/forward.h"
#include "LogTags.h"
#include "Store.h"

#if USE_ADAPTATION
#include "adaptation/forward.h"
#include "adaptation/Initiator.h"
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
#if USE_ADAPTATION
    CBDATA_CHILD(ClientHttpRequest);
#else
    CBDATA_CLASS(ClientHttpRequest);
#endif

public:
    ClientHttpRequest(ConnStateData *);
    ClientHttpRequest(ClientHttpRequest &&) = delete;
#if USE_ADAPTATION
    ~ClientHttpRequest() override;
#else
    ~ClientHttpRequest();
#endif

    String rangeBoundaryStr() const;
    void freeResources();
    void updateCounters();
    void logRequest();
    MemObject * memObject() const {
        return (storeEntry() ? storeEntry()->mem_obj : nullptr);
    }
    bool multipartRangeRequest() const;
    void processRequest();
    void httpStart();
    bool onlyIfCached()const;
    bool gotEnough() const;
    StoreEntry *storeEntry() const { return entry_; }
    void storeEntry(StoreEntry *);
    StoreEntry *loggingEntry() const { return loggingEntry_; }
    void loggingEntry(StoreEntry *);

    ConnStateData *getConn() const {
        return (cbdataReferenceValid(conn_) ? conn_ : nullptr);
    }

    /// Initializes the current request with the virgin request.
    /// Call this method when the virgin request becomes known.
    /// To update the current request later, use resetRequest().
    void initRequest(HttpRequest *);

    /// Resets the current request to the latest adapted or redirected
    /// request. Call this every time adaptation or redirection changes
    /// the request. To set the virgin request, use initRequest().
    void resetRequest(HttpRequest *);

    /// update the code in the transaction processing tags
    void updateLoggingTags(const LogTags_ot code) { al->cache.code.update(code); }

    /// the processing tags associated with this request transaction.
    const LogTags &loggingTags() const { return al->cache.code; }

    int64_t mRangeCLen() const;

    void doCallouts();

    // The three methods below prepare log_uri and friends for future logging.
    // Call the best-fit method whenever the current request or its URI changes.

    /// sets log_uri when we know the current request
    void setLogUriToRequestUri();

    /// sets log_uri to a parsed request URI when Squid fails to parse or
    /// validate other request components, yielding no current request
    void setLogUriToRawUri(const char *, const HttpRequestMethod &);

    /// sets log_uri and uri to an internally-generated "error:..." URI when
    /// neither the current request nor the parsed request URI are known
    void setErrorUri(const char *);

    /// Prepares to satisfy a Range request with a generated HTTP 206 response.
    /// Initializes range_iter state to allow raw range_iter access.
    /// \returns Content-Length value for the future response; never negative
    int64_t prepPartialResponseGeneration();

    /// Build an error reply. For use with the callouts.
    void calloutsError(const err_type, const ErrorDetail::Pointer &);

    /// if necessary, stores new error information (if any)
    void updateError(const Error &);

public:
    /// Request currently being handled by ClientHttpRequest.
    /// Usually remains nil until the virgin request header is parsed or faked.
    /// Starts as a virgin request; see initRequest().
    /// Adaptation and redirections replace it; see resetRequest().
    HttpRequest * const request = nullptr;

    /// Usually starts as a URI received from the client, with scheme and host
    /// added if needed. Is used to create the virgin request for initRequest().
    /// URIs of adapted/redirected requests replace it via resetRequest().
    char *uri = nullptr;

    // TODO: remove this field and store the URI directly in al->url
    /// Cleaned up URI of the current (virgin or adapted/redirected) request,
    /// computed URI of an internally-generated requests, or
    /// one of the hard-coded "error:..." URIs.
    char * const log_uri = nullptr;

    String store_id; /* StoreID for transactions where the request member is nil */

    struct Out {
        /// Roughly speaking, this offset points to the next body byte we want
        /// to receive from Store. Without Ranges (and I/O errors), we should
        /// have received (and written to the client) all the previous bytes.
        /// XXX: The offset is updated by various receive-write steps, making
        /// its exact meaning illusive. Its Out class placement is confusing.
        int64_t offset = 0;
        /// Response header and body bytes written to the client connection.
        uint64_t size = 0;
        /// Response header bytes written to the client connection.
        size_t headers_sz = 0;
    } out;

    HttpHdrRangeIter range_iter;    /* data for iterating thru range specs */
    size_t req_sz = 0; ///< raw request size on input, not current request size

    const AccessLogEntry::Pointer al; ///< access.log entry

    struct Flags {
        bool accel = false;
        bool internal = false;
        bool done_copying = false;
    } flags;

    struct Redirect {
        Http::StatusCode status = Http::scNone;
        char *location = nullptr;
    } redirect;

    dlink_node active;
    dlink_list client_stream;

    ClientRequestContext *calloutContext = nullptr;

private:
    /// assigns log_uri with aUri without copying the entire C-string
    void absorbLogUri(char *);
    /// resets the current request and log_uri to nil
    void clearRequest();
    /// initializes the current unassigned request to the virgin request
    /// sets the current request, asserting that it was unset
    void assignRequest(HttpRequest *);

    int64_t maxReplyBodySize_ = 0;
    StoreEntry *entry_ = nullptr;
    StoreEntry *loggingEntry_ = nullptr;
    ConnStateData * conn_ = nullptr;

#if USE_OPENSSL
public:
    /// returns raw sslBump mode value
    Ssl::BumpMode sslBumpNeed() const { return sslBumpNeed_; }
    /// returns true if and only if the request needs to be bumped
    bool sslBumpNeeded() const { return sslBumpNeed_ == Ssl::bumpServerFirst || sslBumpNeed_ == Ssl::bumpClientFirst || sslBumpNeed_ == Ssl::bumpBump || sslBumpNeed_ == Ssl::bumpPeek || sslBumpNeed_ == Ssl::bumpStare; }
    /// set the sslBumpNeeded state
    void sslBumpNeed(Ssl::BumpMode);
    void sslBumpStart();
    void sslBumpEstablish(Comm::Flag);

private:
    /// whether (and how) the request needs to be bumped
    Ssl::BumpMode sslBumpNeed_ = Ssl::bumpEnd;
#endif

#if USE_ADAPTATION
public:
    void startAdaptation(const Adaptation::ServiceGroupPointer &);
    bool requestSatisfactionMode() const { return request_satisfaction_mode; }

    /* AsyncJob API */
    bool doneAll() const override {
        return Initiator::doneAll() &&
               BodyConsumer::doneAll() &&
               false; // TODO: Refactor into a proper AsyncJob
    }
    void callException(const std::exception &) override;

private:
    /// Handles an adaptation client request failure.
    /// Bypasses the error if possible, or build an error reply.
    void handleAdaptationFailure(const ErrorDetail::Pointer &, bool bypassable = false);

    void handleAdaptedHeader(Http::Message *);
    void handleAdaptationBlock(const Adaptation::Answer &);

    /* Adaptation::Initiator API */
    void noteAdaptationAclCheckDone(Adaptation::ServiceGroupPointer) override;
    void noteAdaptationAnswer(const Adaptation::Answer &) override;

    /* BodyConsumer API */
    void noteMoreBodyDataAvailable(BodyPipe::Pointer) override;
    void noteBodyProductionEnded(BodyPipe::Pointer) override;
    void noteBodyProducerAborted(BodyPipe::Pointer) override;

    void endRequestSatisfaction();
    /// called by StoreEntry when it has more buffer space available
    void resumeBodyStorage();

private:
    CbcPointer<Adaptation::Initiate> virginHeadSource;
    BodyPipe::Pointer adaptedBodySource;

    /// noteBodyProductionEnded() was called
    bool receivedWholeAdaptedReply = false;

    bool request_satisfaction_mode = false;
    int64_t request_satisfaction_offset = 0;
#endif
};

/* client http based routines */
char *clientConstructTraceEcho(ClientHttpRequest *);

ACLFilledChecklist *clientAclChecklistCreate(const acl_access *, ClientHttpRequest *);
void clientAclChecklistFill(ACLFilledChecklist &, ClientHttpRequest *);
void clientAccessCheck(ClientHttpRequest *);

/* ones that should be elsewhere */
void tunnelStart(ClientHttpRequest *);

#endif /* SQUID_CLIENTSIDEREQUEST_H */
