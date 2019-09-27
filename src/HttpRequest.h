/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPREQUEST_H
#define SQUID_HTTPREQUEST_H

#include "anyp/Uri.h"
#include "base/CbcPointer.h"
#include "dns/forward.h"
#include "err_type.h"
#include "HierarchyLogEntry.h"
#include "http/Message.h"
#include "http/RequestMethod.h"
#include "MasterXaction.h"
#include "Notes.h"
#include "RequestFlags.h"

#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_ADAPTATION
#include "adaptation/History.h"
#endif
#if ICAP_CLIENT
#include "adaptation/icap/History.h"
#endif
#if USE_SQUID_EUI
#include "eui/Eui48.h"
#include "eui/Eui64.h"
#endif

class AccessLogEntry;
typedef RefCount<AccessLogEntry> AccessLogEntryPointer;
class CachePeer;
class ConnStateData;
class Downloader;

/*  Http Request */
void httpRequestPack(void *obj, Packable *p);

class HttpHdrRange;

class HttpRequest: public Http::Message
{
    MEMPROXY_CLASS(HttpRequest);

public:
    typedef RefCount<HttpRequest> Pointer;

    HttpRequest(const MasterXaction::Pointer &);
    HttpRequest(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *schemeImage, const char *aUrlpath, const MasterXaction::Pointer &);
    ~HttpRequest();
    virtual void reset();

    void initHTTP(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *schemeImage, const char *aUrlpath);

    virtual HttpRequest *clone() const;

    /// Whether response to this request is potentially cachable
    /// \retval false  Not cacheable.
    /// \retval true   Possibly cacheable. Response factors will determine.
    bool maybeCacheable();

    bool conditional() const; ///< has at least one recognized If-* header

    /// whether the client is likely to be able to handle a 1xx reply
    bool canHandle1xx() const;

    /// \returns a pointer to a local static buffer containing request URI
    /// that honors strip_query_terms and %-encodes unsafe URI characters
    char *canonicalCleanUrl() const;

#if USE_ADAPTATION
    /// Returns possibly nil history, creating it if adapt. logging is enabled
    Adaptation::History::Pointer adaptLogHistory() const;
    /// Returns possibly nil history, creating it if requested
    Adaptation::History::Pointer adaptHistory(bool createIfNone = false) const;
    /// Makes their history ours, throwing on conflicts
    void adaptHistoryImport(const HttpRequest &them);
#endif
#if ICAP_CLIENT
    /// Returns possibly nil history, creating it if icap logging is enabled
    Adaptation::Icap::History::Pointer icapHistory() const;
#endif

    /* If a request goes through several destinations, then the following two
     * methods will be called several times, in destinations-dependent order. */
    /// get ready to be sent to the given cache_peer, including originserver
    void prepForPeering(const CachePeer &peer);
    /// get ready to be sent directly to an origin server, excluding originserver
    void prepForDirect();

    void recordLookup(const Dns::LookupDetails &detail);

    /// sets error detail if no earlier detail was available
    void detailError(err_type aType, int aDetail);
    /// clear error details, useful for retries/repeats
    void clearError();

    /// associates the request with a from-client connection manager
    void manager(const CbcPointer<ConnStateData> &aMgr, const AccessLogEntryPointer &al);

protected:
    void clean();

    void init();

public:
    HttpRequestMethod method;
    AnyP::Uri url; ///< the request URI

private:
#if USE_ADAPTATION
    mutable Adaptation::History::Pointer adaptHistory_; ///< per-HTTP transaction info
#endif
#if ICAP_CLIENT
    mutable Adaptation::Icap::History::Pointer icapHistory_; ///< per-HTTP transaction info
#endif

public:
#if USE_AUTH
    Auth::UserRequest::Pointer auth_user_request;
#endif

    /// RFC 7230 section 5.5 - Effective Request URI
    const SBuf &effectiveRequestUri() const;

    /**
     * If defined, store_id_program mapped the request URL to this ID.
     * Store uses this ID (and not the URL) to find and store entries,
     * avoiding caching duplicate entries when different URLs point to
     * "essentially the same" cachable resource.
     */
    String store_id;

    RequestFlags flags;

    HttpHdrRange *range;

    time_t ims;

    int imslen;

    Ip::Address client_addr;

#if FOLLOW_X_FORWARDED_FOR
    Ip::Address indirect_client_addr;
#endif /* FOLLOW_X_FORWARDED_FOR */

    Ip::Address my_addr;

    HierarchyLogEntry hier;

    int dnsWait; ///< sum of DNS lookup delays in milliseconds, for %dt

    err_type errType;
    int errDetail; ///< errType-specific detail about the transaction error

    char *peer_login;       /* Configured peer login:password */

    char *peer_host;           /* Selected peer host*/

    time_t lastmod;     /* Used on refreshes */

    /// The variant second-stage cache key. Generated from Vary header pattern for this request.
    SBuf vary_headers;

    char *peer_domain;      /* Configured peer forceddomain */

    String myportname; // Internal tag name= value from port this requests arrived in.

    String tag;         /* Internal tag for this request */

    String extacl_user;     /* User name returned by extacl lookup */

    String extacl_passwd;   /* Password returned by extacl lookup */

    String extacl_log;      /* String to be used for access.log purposes */

    String extacl_message;  /* String to be used for error page purposes */

#if FOLLOW_X_FORWARDED_FOR
    String x_forwarded_for_iterator; /* XXX a list of IP addresses */
#endif /* FOLLOW_X_FORWARDED_FOR */

    /// A strong etag of the cached entry. Used for refreshing that entry.
    String etag;

    /// whether we have responded with HTTP 100 or FTP 150 already
    bool forcedBodyContinuation;

public:
    bool multipartRangeRequest() const;

    bool parseFirstLine(const char *start, const char *end);

    virtual bool expectingBody(const HttpRequestMethod& unused, int64_t&) const;

    bool bodyNibbled() const; // the request has a [partially] consumed body

    int prefixLen() const;

    void swapOut(StoreEntry * e);

    void pack(Packable * p) const;

    static void httpRequestPack(void *obj, Packable *p);

    static HttpRequest * FromUrl(const SBuf &url, const MasterXaction::Pointer &, const HttpRequestMethod &method = Http::METHOD_GET);

    /// \deprecated use SBuf variant instead
    static HttpRequest * FromUrlXXX(const char * url, const MasterXaction::Pointer &, const HttpRequestMethod &method = Http::METHOD_GET);

    ConnStateData *pinnedConnection();

    /**
     * Returns the current StoreID for the request as a nul-terminated char*.
     * Always returns the current id for the request
     * (either the effective request URI or modified ID by the helper).
     */
    const SBuf storeId();

    /**
     * The client connection manager, if known;
     * Used for any response actions needed directly to the client.
     * ie 1xx forwarding or connection pinning state changes
     */
    CbcPointer<ConnStateData> clientConnectionManager;

    /// The Downloader object which initiated the HTTP request if any
    CbcPointer<Downloader> downloader;

    /// the master transaction this request belongs to. Never nil.
    MasterXaction::Pointer masterXaction;

    /// forgets about the cached Range header (for a reason)
    void ignoreRange(const char *reason);
    int64_t getRangeOffsetLimit(); /* the result of this function gets cached in rangeOffsetLimit */

    /// \returns existing non-empty transaction annotations,
    /// creates and returns empty annotations otherwise
    NotePairs::Pointer notes();
    bool hasNotes() const { return bool(theNotes) && !theNotes->empty(); }

    virtual void configureContentLengthInterpreter(Http::ContentLengthInterpreter &) {}

    /// Parses request header using Parser.
    /// Use it in contexts where the Parser object is available.
    bool parseHeader(Http1::Parser &hp);
    /// Parses request header from the buffer.
    /// Use it in contexts where the Parser object not available.
    bool parseHeader(const char *buffer, const size_t size);

private:
    mutable int64_t rangeOffsetLimit;  /* caches the result of getRangeOffsetLimit */

    /// annotations added by the note directive and helpers
    /// and(or) by annotate_transaction/annotate_client ACLs.
    NotePairs::Pointer theNotes;
protected:
    virtual void packFirstLineInto(Packable * p, bool full_uri) const;

    virtual bool sanityCheckStartLine(const char *buf, const size_t hdr_len, Http::StatusCode *error);

    virtual void hdrCacheInit();

    virtual bool inheritProperties(const Http::Message *);
};

class ConnStateData;
/**
 * Updates ConnStateData ids and HttpRequest notes from helpers received notes.
 */
void UpdateRequestNotes(ConnStateData *csd, HttpRequest &request, NotePairs const &notes);

/// \returns listening/*_port address used by the client connection (or nil)
/// nil parameter(s) indicate missing caller information and are handled safely
const Ip::Address *FindListeningPortAddress(const HttpRequest *, const AccessLogEntry *);

#endif /* SQUID_HTTPREQUEST_H */

