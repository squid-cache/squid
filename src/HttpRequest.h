/*
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

#ifndef SQUID_HTTPREQUEST_H
#define SQUID_HTTPREQUEST_H

#include "base/CbcPointer.h"
#include "Debug.h"
#include "err_type.h"
#include "HierarchyLogEntry.h"
#include "HttpMsg.h"
#include "HttpRequestMethod.h"
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

class ConnStateData;

/*  Http Request */
void httpRequestPack(void *obj, Packer *p);

class HttpHdrRange;
class DnsLookupDetails;

class HttpRequest: public HttpMsg
{

public:
    typedef HttpMsgPointerT<HttpRequest> Pointer;

    MEMPROXY_CLASS(HttpRequest);
    HttpRequest();
    HttpRequest(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *aUrlpath);
    ~HttpRequest();
    virtual void reset();

    // use HTTPMSGLOCK() instead of calling this directly
    virtual HttpRequest *_lock() {
        return static_cast<HttpRequest*>(HttpMsg::_lock());
    };

    void initHTTP(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *aUrlpath);

    virtual HttpRequest *clone() const;

    /* are responses to this request potentially cachable */
    bool cacheable() const;

    bool conditional() const; ///< has at least one recognized If-* header

    /// whether the client is likely to be able to handle a 1xx reply
    bool canHandle1xx() const;

    /* Now that we care what host contains it is better off being protected. */
    /* HACK: These two methods are only inline to get around Makefile dependancies */
    /*      caused by HttpRequest being used in places it really shouldn't.        */
    /*      ideally they would be methods of URL instead. */
    inline void SetHost(const char *src) {
        host_addr.SetEmpty();
        host_addr = src;
        if ( host_addr.IsAnyAddr() ) {
            xstrncpy(host, src, SQUIDHOSTNAMELEN);
            host_is_numeric = 0;
        } else {
            host_addr.ToHostname(host, SQUIDHOSTNAMELEN);
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

    char *peer_login;		/* Configured peer login:password */

    char *peer_host;           /* Selected peer host*/

    time_t lastmod;		/* Used on refreshes */

    const char *vary_headers;	/* Used when varying entities are detected. Changes how the store key is calculated */

    char *peer_domain;		/* Configured peer forceddomain */

    String myportname; // Internal tag name= value from port this requests arrived in.

    String tag;			/* Internal tag for this request */

    String extacl_user;		/* User name returned by extacl lookup */

    String extacl_passwd;	/* Password returned by extacl lookup */

    String extacl_log;		/* String to be used for access.log purposes */

    String extacl_message;	/* String to be used for error page purposes */

#if FOLLOW_X_FORWARDED_FOR
    String x_forwarded_for_iterator; /* XXX a list of IP addresses */
#endif /* FOLLOW_X_FORWARDED_FOR */

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
     * The client connection manager, if known;
     * Used for any response actions needed directly to the client.
     * ie 1xx forwarding or connection pinning state changes
     */
    CbcPointer<ConnStateData> clientConnectionManager;

    int64_t getRangeOffsetLimit(); /* the result of this function gets cached in rangeOffsetLimit */

private:
    const char *packableURI(bool full_uri) const;

    mutable int64_t rangeOffsetLimit;  /* caches the result of getRangeOffsetLimit */

protected:
    virtual void packFirstLineInto(Packer * p, bool full_uri) const;

    virtual bool sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, http_status *error);

    virtual void hdrCacheInit();

    virtual bool inheritProperties(const HttpMsg *aMsg);
};

MEMPROXY_CLASS_INLINE(HttpRequest);

#endif /* SQUID_HTTPREQUEST_H */
