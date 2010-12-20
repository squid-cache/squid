
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

#ifndef SQUID_HTTPREQUEST_H
#define SQUID_HTTPREQUEST_H

#include "HttpMsg.h"
#include "client_side.h"
#include "HierarchyLogEntry.h"
#include "HttpRequestMethod.h"
#if USE_ADAPTATION
#include "adaptation/History.h"
#endif
#if ICAP_CLIENT
#include "adaptation/icap/History.h"
#endif

/*  Http Request */
//DEAD?: extern int httpRequestHdrAllowedByName(http_hdr_type id);
extern void httpRequestPack(void *obj, Packer *p);

// TODO: Move these three to access_log.h or AccessLogEntry.h
#if USE_ADAPTATION
extern bool alLogformatHasAdaptToken;
#endif
#if ICAP_CLIENT
extern bool alLogformatHasIcapToken;
#endif
extern int LogfileStatus;

class HttpHdrRange;
class DnsLookupDetails;

class HttpRequest: public HttpMsg
{

public:
    typedef HttpMsgPointerT<HttpRequest> Pointer;

    MEMPROXY_CLASS(HttpRequest);
    HttpRequest();
    HttpRequest(const HttpRequestMethod& aMethod, protocol_t aProtocol, const char *aUrlpath);
    ~HttpRequest();
    virtual void reset();

    // use HTTPMSGLOCK() instead of calling this directly
    virtual HttpRequest *_lock() {
        return static_cast<HttpRequest*>(HttpMsg::_lock());
    };

    void initHTTP(const HttpRequestMethod& aMethod, protocol_t aProtocol, const char *aUrlpath);

    virtual HttpRequest *clone() const;

    /* are responses to this request potentially cachable */
    bool cacheable() const;

    bool conditional() const; ///< has at least one recognized If-* header

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
    };
    inline const char* GetHost(void) const { return host; };
    inline const int GetHostIsNumeric(void) const { return host_is_numeric; };

#if USE_ADAPTATION
    /// Returns possibly nil history, creating it if adapt. logging is enabled
    Adaptation::History::Pointer adaptLogHistory() const;
    /// Returns possibly nil history, creating it if requested
    Adaptation::History::Pointer adaptHistory(bool createIfNone = false) const;
#endif
#if ICAP_CLIENT
    /// Returns possibly nil history, creating it if icap logging is enabled
    Adaptation::Icap::History::Pointer icapHistory() const;
#endif

    void recordLookup(const DnsLookupDetails &detail);

protected:
    void clean();

    void init();

public:
    HttpRequestMethod method;

    char login[MAX_LOGIN_SZ];

private:
    char host[SQUIDHOSTNAMELEN];
    int host_is_numeric;

    /***
     * The client side connection data of pinned connections for the client side
     * request related objects
     */
    ConnStateData *pinned_connection;

#if USE_ADAPTATION
    mutable Adaptation::History::Pointer adaptHistory_; ///< per-HTTP transaction info
#endif
#if ICAP_CLIENT
    mutable Adaptation::Icap::History::Pointer icapHistory_; ///< per-HTTP transaction info
#endif

public:
    IpAddress host_addr;

    AuthUserRequest *auth_user_request;

    u_short port;

    String urlpath;

    char *canonical;

    request_flags flags;

    HttpHdrRange *range;

    time_t ims;

    int imslen;

    IpAddress client_addr;

#if FOLLOW_X_FORWARDED_FOR
    IpAddress indirect_client_addr;
#endif /* FOLLOW_X_FORWARDED_FOR */

    IpAddress my_addr;

    HierarchyLogEntry hier;

    int dnsWait; ///< sum of DNS lookup delays in milliseconds, for %dt

    err_type errType;

    char *peer_login;		/* Configured peer login:password */

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

    void setPinnedConnection(ConnStateData *conn) {
        pinned_connection = cbdataReference(conn);
    }

    ConnStateData *pinnedConnection() {
        return pinned_connection;
    }

    void releasePinnedConnection() {
        cbdataReferenceDone(pinned_connection);
    }

private:
    const char *packableURI(bool full_uri) const;

protected:
    virtual void packFirstLineInto(Packer * p, bool full_uri) const;

    virtual bool sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, http_status *error);

    virtual void hdrCacheInit();

    virtual bool inheritProperties(const HttpMsg *aMsg);
};

MEMPROXY_CLASS_INLINE(HttpRequest);

#endif /* SQUID_HTTPREQUEST_H */
