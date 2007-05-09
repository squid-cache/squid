
/*
 * $Id: HttpRequest.h,v 1.27 2007/05/09 07:36:24 wessels Exp $
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

/*  Http Request */
extern int httpRequestHdrAllowed(const HttpHeaderEntry * e, String * strConnection);
extern int httpRequestHdrAllowedByName(http_hdr_type id);
extern void httpRequestPack(void *obj, Packer *p);


class HttpHdrRange;

class HttpRequest: public HttpMsg
{

public:
    MEMPROXY_CLASS(HttpRequest);
    HttpRequest();
    HttpRequest(method_t aMethod, protocol_t aProtocol, const char *aUrlpath);
    ~HttpRequest();
    virtual void reset();

    // use HTTPMSGLOCK() instead of calling this directly
    virtual HttpRequest *_lock()
    {
        return static_cast<HttpRequest*>(HttpMsg::_lock());
    };

    void initHTTP(method_t aMethod, protocol_t aProtocol, const char *aUrlpath);

    /* are responses to this request potentially cachable */
    bool cacheable() const;

protected:
    void clean();

    void init();

public:
    method_t method;

    char login[MAX_LOGIN_SZ];

    char host[SQUIDHOSTNAMELEN + 1];

    AuthUserRequest *auth_user_request;

    u_short port;

    String urlpath;

    char *canonical;

    request_flags flags;

    HttpHdrRange *range;

    time_t ims;

    int imslen;

    int max_forwards;

    /* these in_addr's could probably be sockaddr_in's */

    struct IN_ADDR client_addr;

    struct IN_ADDR my_addr;

    unsigned short my_port;

    unsigned short client_port;

    HierarchyLogEntry hier;

    err_type errType;

    char *peer_login;		/* Configured peer login:password */

    time_t lastmod;		/* Used on refreshes */

    const char *vary_headers;	/* Used when varying entities are detected. Changes how the store key is calculated */

    char *peer_domain;		/* Configured peer forceddomain */

    String tag;			/* Internal tag for this request */

    String extacl_user;		/* User name returned by extacl lookup */

    String extacl_passwd;	/* Password returned by extacl lookup */

    String extacl_log;		/* String to be used for access.log purposes */

public:
    bool multipartRangeRequest() const;

    bool parseFirstLine(const char *start, const char *end);

    int parseHeader(const char *parse_start, int len);

    virtual bool expectingBody(method_t unused, ssize_t&) const;

    bool bodyNibbled() const; // the request has a [partially] consumed body

    int prefixLen();

    void swapOut(StoreEntry * e);

    void pack(Packer * p);

    static void httpRequestPack(void *obj, Packer *p);

    static HttpRequest * CreateFromUrlAndMethod(char * url, method_t method);

    static HttpRequest * CreateFromUrl(char * url);

private:
    const char *packableURI(bool full_uri) const;

protected:
    virtual void packFirstLineInto(Packer * p, bool full_uri) const;

    virtual bool sanityCheckStartLine(MemBuf *buf, http_status *error);

    virtual void hdrCacheInit();

};

MEMPROXY_CLASS_INLINE(HttpRequest)

#endif /* SQUID_HTTPREQUEST_H */
