/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPREQUEST_H
#define SQUID_HTTPREQUEST_H

#include "base/CbcPointer.h"
#include "Debug.h"
#include "err_type.h"
#include "HierarchyLogEntry.h"
#include "HttpMsg.h"
#include "HttpRequestMethod.h"
#include "Notes.h"
#include "RequestFlags.h"
#include "URL.h"

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

class ConnStateData;

/*  Http Request */
void httpRequestPack(void *obj, Packer *p);

class HttpHdrRange;
class DnsLookupDetails;

class HttpRequest: public HttpMsg
{

public:
    typedef RefCount<HttpRequest> Pointer;

    MEMPROXY_CLASS(HttpRequest);
    HttpRequest();
    HttpRequest(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *aUrlpath);
    ~HttpRequest();
    virtual void reset();

    void initHTTP(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *aUrlpath);

    virtual HttpRequest *clone() const;

    /// Whether response to this request is potentially cachable
    /// \retval false  Not cacheable.
    /// \retval true   Possibly cacheable. Response factors will determine.
    bool maybeCacheable();

    bool conditional() const; ///< has at least one recognized If-* header

    /// whether the client is likely to be able to handle a 1xx reply
    bool canHandle1xx() const;

    /* Now that we care what host contains it is better off being protected. */
    /* HACK: These two methods are only inline to get around Makefile dependancies */
    /*      caused by HttpRequest being used in places it really shouldn't.        */
    /*      ideally they would be methods of URL instead. */
    inline void SetHost(const char *src) {
        host_addr.setEmpty();
        host_addr = src;
        if (host_addr.isAnyAddr()) {
            xstrncpy(host, src, SQUIDHOSTNAMELEN);
            host_is_numeric = 0;
        } else {
            host_addr.toHostStr(host, SQUIDHOSTNAMELEN);
            debugs(23, 3, "HttpRequest::SetHost() given IP: " << host_addr);
            host_is_numeric = 1;
        }
        safe_free(canonical); // force its re-build
    };
    inline const char* GetHost(void) const { return host; };
    inline int GetHostIsNumeric(void) const { return host_is_numeric; };

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

    void recordLookup(const DnsLookupDetails &detail);

    /// sets error detail if no earlier detail was available
    void detailError(err_type aType, int aDetail);
    /// clear error details, useful for retries/repeats
    void clearError();

protected:
    void clean();

    void init();

public:
    HttpRequestMethod method;

    // TODO expand to include all URI parts
    URL url; ///< the request URI (scheme only)

    char login[MAX_LOGIN_SZ];

private:
    char host[SQUIDHOSTNAMELEN];
    int host_is_numeric;

#if USE_ADAPTATION
    mutable Adaptation::History::Pointer adaptHistory_; ///< per-HTTP transaction info
#endif
#if ICAP_CLIENT
    mutable Adaptation::Icap::History::Pointer icapHistory_; ///< per-HTTP transaction info
#endif

public:
    Ip::Address host_addr;
#if USE_AUTH
    Auth::UserRequest::Pointer auth_user_request;
#endif
    unsigned short port;

    String urlpath;

    char *canonical;

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

    NotePairs::Pointer notes; ///< annotations added by the note directive and helpers

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

public:
    bool multipartRangeRequest() const;

    bool parseFirstLine(const char *start, const char *end);

    int parseHeader(const char *parse_start, int len);

    virtual bool expectingBody(const HttpRequestMethod& unused, int64_t&) const;

    bool bodyNibbled() const; // the request has a [partially] consumed body

    int prefixLen();

    void swapOut(StoreEntry * e);

    void pack(Packer * p);

    static void httpRequestPack(void *obj, Packer *p);

    static HttpRequest * CreateFromUrlAndMethod(char * url, const HttpRequestMethod& method);

    static HttpRequest * CreateFromUrl(char * url);

    ConnStateData *pinnedConnection();

    /**
     * Returns the current StoreID for the request as a nul-terminated char*.
     * Always returns the current id for the request
     * (either the request canonical url or modified ID by the helper).
     * Does not return NULL.
     */
    const char *storeId();

    /**
     * The client connection manager, if known;
     * Used for any response actions needed directly to the client.
     * ie 1xx forwarding or connection pinning state changes
     */
    CbcPointer<ConnStateData> clientConnectionManager;

    /// forgets about the cached Range header (for a reason)
    void ignoreRange(const char *reason);
    int64_t getRangeOffsetLimit(); /* the result of this function gets cached in rangeOffsetLimit */

private:
    const char *packableURI(bool full_uri) const;

    mutable int64_t rangeOffsetLimit;  /* caches the result of getRangeOffsetLimit */

protected:
    virtual void packFirstLineInto(Packer * p, bool full_uri) const;

    virtual bool sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, Http::StatusCode *error);

    virtual void hdrCacheInit();

    virtual bool inheritProperties(const HttpMsg *aMsg);
};

MEMPROXY_CLASS_INLINE(HttpRequest);

#endif /* SQUID_HTTPREQUEST_H */

