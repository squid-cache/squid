
/*
 * $Id$
 *
 * DEBUG: section 73    HTTP Request
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "HttpRequest.h"
#include "auth/UserRequest.h"
#include "HttpHeaderRange.h"
#include "MemBuf.h"
#include "Store.h"
#if ICAP_CLIENT
#include "adaptation/icap/icap_log.h"
#endif

HttpRequest::HttpRequest() : HttpMsg(hoRequest)
{
    init();
}

HttpRequest::HttpRequest(const HttpRequestMethod& aMethod, protocol_t aProtocol, const char *aUrlpath) : HttpMsg(hoRequest)
{
    init();
    initHTTP(aMethod, aProtocol, aUrlpath);
}

HttpRequest::~HttpRequest()
{
    clean();
}

void
HttpRequest::initHTTP(const HttpRequestMethod& aMethod, protocol_t aProtocol, const char *aUrlpath)
{
    method = aMethod;
    protocol = aProtocol;
    urlpath = aUrlpath;
}

void
HttpRequest::init()
{
    method = METHOD_NONE;
    protocol = PROTO_NONE;
    urlpath = NULL;
    login[0] = '\0';
    host[0] = '\0';
    auth_user_request = NULL;
    pinned_connection = NULL;
    port = 0;
    canonical = NULL;
    memset(&flags, '\0', sizeof(flags));
    range = NULL;
    ims = -1;
    imslen = 0;
    lastmod = -1;
    max_forwards = -1;
    client_addr.SetEmpty();
    my_addr.SetEmpty();
    body_pipe = NULL;
    // hier
    dnsWait = -1;
    errType = ERR_NONE;
    peer_login = NULL;		// not allocated/deallocated by this class
    peer_domain = NULL;		// not allocated/deallocated by this class
    vary_headers = NULL;
    tag = null_string;
    extacl_user = null_string;
    extacl_passwd = null_string;
    extacl_log = null_string;
    pstate = psReadyToParseStartLine;
#if FOLLOW_X_FORWARDED_FOR
    indirect_client_addr.SetEmpty();
#endif /* FOLLOW_X_FORWARDED_FOR */
#if USE_ADAPTATION
    adaptHistory_ = NULL;
#endif
#if ICAP_CLIENT
    icapHistory_ = NULL;
#endif
}

void
HttpRequest::clean()
{
    // we used to assert that the pipe is NULL, but now the request only
    // points to a pipe that is owned and initiated by another object.
    body_pipe = NULL;

    AUTHUSERREQUESTUNLOCK(auth_user_request, "request");

    safe_free(canonical);

    safe_free(vary_headers);

    urlpath.clean();

    header.clean();

    if (cache_control) {
        httpHdrCcDestroy(cache_control);
        cache_control = NULL;
    }

    if (range) {
        delete range;
        range = NULL;
    }

    if (pinned_connection)
        cbdataReferenceDone(pinned_connection);

    tag.clean();

    extacl_user.clean();

    extacl_passwd.clean();

    extacl_log.clean();

#if USE_ADAPTATION
    adaptHistory_ = NULL;
#endif
#if ICAP_CLIENT
    icapHistory_ = NULL;
#endif
}

void
HttpRequest::reset()
{
    clean();
    init();
}

HttpRequest *
HttpRequest::clone() const
{
    HttpRequest *copy = new HttpRequest(method, protocol, urlpath.termedBuf());
    // TODO: move common cloning clone to Msg::copyTo() or copy ctor
    copy->header.append(&header);
    copy->hdrCacheInit();
    copy->hdr_sz = hdr_sz;
    copy->http_ver = http_ver;
    copy->pstate = pstate; // TODO: should we assert a specific state here?
    copy->body_pipe = body_pipe;

    strncpy(copy->login, login, sizeof(login)); // MAX_LOGIN_SZ
    strncpy(copy->host, host, sizeof(host)); // SQUIDHOSTNAMELEN
    copy->host_addr = host_addr;

    copy->port = port;
    // urlPath handled in ctor
    copy->canonical = canonical ? xstrdup(canonical) : NULL;

    copy->range = range ? new HttpHdrRange(*range) : NULL;
    copy->ims = ims;
    copy->imslen = imslen;
    copy->max_forwards = max_forwards;
    copy->hier = hier; // Is it safe to copy? Should we?

    copy->errType = errType;

    // XXX: what to do with copy->peer_login?

    copy->lastmod = lastmod;
    copy->vary_headers = vary_headers ? xstrdup(vary_headers) : NULL;
    // XXX: what to do with copy->peer_domain?

    copy->tag = tag;
    copy->extacl_user = extacl_user;
    copy->extacl_passwd = extacl_passwd;
    copy->extacl_log = extacl_log;

    assert(copy->inheritProperties(this));

    return copy;
}

/**
 * Checks the first line of an HTTP request is valid
 * currently just checks the request method is present.
 *
 * NP: Other errors are left for detection later in the parse.
 */
bool
HttpRequest::sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, http_status *error)
{
    // content is long enough to possibly hold a reply
    // 2 being magic size of a 1-byte request method plus space delimiter
    if ( buf->contentSize() < 2 ) {
        // this is ony a real error if the headers apparently complete.
        if (hdr_len > 0) {
            debugs(58, 3, HERE << "Too large request header (" << hdr_len << " bytes)");
            *error = HTTP_INVALID_HEADER;
        }
        return false;
    }

    /* See if the request buffer starts with a known HTTP request method. */
    if (HttpRequestMethod(buf->content(),NULL) == METHOD_NONE) {
        debugs(73, 3, "HttpRequest::sanityCheckStartLine: did not find HTTP request method");
        *error = HTTP_INVALID_HEADER;
        return false;
    }

    return true;
}

bool
HttpRequest::parseFirstLine(const char *start, const char *end)
{
    const char *t = start + strcspn(start, w_space);
    method = HttpRequestMethod(start, t);

    if (method == METHOD_NONE)
        return false;

    start = t + strspn(t, w_space);

    const char *ver = findTrailingHTTPVersion(start, end);

    if (ver) {
        end = ver - 1;

        while (xisspace(*end)) // find prev non-space
            end--;

        end++;                 // back to space

        if (2 != sscanf(ver + 5, "%d.%d", &http_ver.major, &http_ver.minor)) {
            debugs(73, 1, "parseRequestLine: Invalid HTTP identifier.");
            return false;
        }
    } else {
        http_ver.major = 0;
        http_ver.minor = 9;
    }

    if (end < start)   // missing URI
        return false;

    char save = *end;

    * (char *) end = '\0';     // temp terminate URI, XXX dangerous?

    HttpRequest *tmp = urlParse(method, (char *) start, this);

    * (char *) end = save;

    if (NULL == tmp)
        return false;

    return true;
}

int
HttpRequest::parseHeader(const char *parse_start, int len)
{
    const char *blk_start, *blk_end;

    if (!httpMsgIsolateHeaders(&parse_start, len, &blk_start, &blk_end))
        return 0;

    int result = header.parse(blk_start, blk_end);

    if (result)
        hdrCacheInit();

    return result;
}

/* swaps out request using httpRequestPack */
void
HttpRequest::swapOut(StoreEntry * e)
{
    Packer p;
    assert(e);
    packerToStoreInit(&p, e);
    pack(&p);
    packerClean(&p);
}

/* packs request-line and headers, appends <crlf> terminator */
void
HttpRequest::pack(Packer * p)
{
    assert(p);
    /* pack request-line */
    packerPrintf(p, "%s " SQUIDSTRINGPH " HTTP/1.0\r\n",
                 RequestMethodStr(method), SQUIDSTRINGPRINT(urlpath));
    /* headers */
    header.packInto(p);
    /* trailer */
    packerAppend(p, "\r\n", 2);
}

/*
 * A wrapper for debugObj()
 */
void
httpRequestPack(void *obj, Packer *p)
{
    HttpRequest *request = static_cast<HttpRequest*>(obj);
    request->pack(p);
}

/* returns the length of request line + headers + crlf */
int
HttpRequest::prefixLen()
{
    return strlen(RequestMethodStr(method)) + 1 +
           urlpath.size() + 1 +
           4 + 1 + 3 + 2 +
           header.len + 2;
}

/* sync this routine when you update HttpRequest struct */
void
HttpRequest::hdrCacheInit()
{
    HttpMsg::hdrCacheInit();

    range = header.getRange();
}

/* request_flags */
bool
request_flags::resetTCP() const
{
    return reset_tcp != 0;
}

void
request_flags::setResetTCP()
{
    debugs(73, 9, "request_flags::setResetTCP");
    reset_tcp = 1;
}

void
request_flags::clearResetTCP()
{
    debugs(73, 9, "request_flags::clearResetTCP");
    reset_tcp = 0;
}

#if ICAP_CLIENT
Adaptation::Icap::History::Pointer 
HttpRequest::icapHistory() const
{
    if (!icapHistory_) {
        if ((LogfileStatus == LOG_ENABLE && alLogformatHasIcapToken) ||
            IcapLogfileStatus == LOG_ENABLE) {
            icapHistory_ = new Adaptation::Icap::History();
            debugs(93,4, HERE << "made " << icapHistory_ << " for " << this);
        }
    }

    return icapHistory_;
}
#endif

#if USE_ADAPTATION
Adaptation::History::Pointer 
HttpRequest::adaptHistory(bool createIfNone) const
{
    if (!adaptHistory_ && createIfNone) {
        adaptHistory_ = new Adaptation::History();
        debugs(93,4, HERE << "made " << adaptHistory_ << " for " << this);
    }

    return adaptHistory_;
}

Adaptation::History::Pointer 
HttpRequest::adaptLogHistory() const
{
    const bool loggingNeedsHistory = (LogfileStatus == LOG_ENABLE) &&
        alLogformatHasAdaptToken; // TODO: make global to remove this method?
    return HttpRequest::adaptHistory(loggingNeedsHistory);
}

#endif

bool
HttpRequest::multipartRangeRequest() const
{
    return (range && range->specs.count > 1);
}

void
request_flags::destinationIPLookupCompleted()
{
    destinationIPLookedUp_ = true;
}

bool
request_flags::destinationIPLookedUp() const
{
    return destinationIPLookedUp_;
}

request_flags
request_flags::cloneAdaptationImmune() const
{
    // At the time of writing, all flags where either safe to copy after
    // adaptation or were not set at the time of the adaptation. If there
    // are flags that are different, they should be cleared in the clone.
    return *this;
}

bool
HttpRequest::bodyNibbled() const
{
    return body_pipe != NULL && body_pipe->consumedSize() > 0;
}

const char *HttpRequest::packableURI(bool full_uri) const
{
    if (full_uri)
        return urlCanonical((HttpRequest*)this);

    if (urlpath.size())
        return urlpath.termedBuf();

    return "/";
}

void HttpRequest::packFirstLineInto(Packer * p, bool full_uri) const
{
    // form HTTP request-line
    packerPrintf(p, "%s %s HTTP/%d.%d\r\n",
                 RequestMethodStr(method),
                 packableURI(full_uri),
                 http_ver.major, http_ver.minor);
}

/*
 * Indicate whether or not we would usually expect an entity-body
 * along with this request
 */
bool
HttpRequest::expectingBody(const HttpRequestMethod& unused, int64_t& theSize) const
{
    bool expectBody = false;

    /*
     * GET and HEAD don't usually have bodies, but we should be prepared
     * to accept one if the request_entities directive is set
     */

    if (method == METHOD_GET || method == METHOD_HEAD)
        expectBody = Config.onoff.request_entities ? true : false;
    else if (method == METHOD_PUT || method == METHOD_POST)
        expectBody = true;
    else if (header.hasListMember(HDR_TRANSFER_ENCODING, "chunked", ','))
        expectBody = true;
    else if (content_length >= 0)
        expectBody = true;
    else
        expectBody = false;

    if (expectBody) {
        if (header.hasListMember(HDR_TRANSFER_ENCODING, "chunked", ','))
            theSize = -1;
        else if (content_length >= 0)
            theSize = content_length;
        else
            theSize = -1;
    }

    return expectBody;
}

/*
 * Create a Request from a URL and METHOD.
 *
 * If the METHOD is CONNECT, then a host:port pair is looked for instead of a URL.
 * If the request cannot be created cleanly, NULL is returned
 */
HttpRequest *
HttpRequest::CreateFromUrlAndMethod(char * url, const HttpRequestMethod& method)
{
    return urlParse(method, url, NULL);
}

/*
 * Create a Request from a URL.
 *
 * If the request cannot be created cleanly, NULL is returned
 */
HttpRequest *
HttpRequest::CreateFromUrl(char * url)
{
    return urlParse(METHOD_GET, url, NULL);
}

/*
 * Are responses to this request possible cacheable ?
 * If false then no matter what the response must not be cached.
 */
bool
HttpRequest::cacheable() const
{
    if (protocol == PROTO_HTTP)
        return httpCachable(method);

    /*
     * The below looks questionable: what non HTTP protocols use connect,
     * trace, put and post? RC
     */

    if (!method.isCacheble())
        return false;

    /*
     * XXX POST may be cached sometimes.. ignored
     * for now
     */
    if (protocol == PROTO_GOPHER)
        return gopherCachable(this);

    if (protocol == PROTO_CACHEOBJ)
        return false;

    return true;
}

bool HttpRequest::inheritProperties(const HttpMsg *aMsg)
{
    const HttpRequest* aReq = dynamic_cast<const HttpRequest*>(aMsg);
    if (!aReq)
        return false;

    client_addr = aReq->client_addr;
    my_addr = aReq->my_addr;

    dnsWait = aReq->dnsWait;

#if USE_ADAPTATION
    adaptHistory_ = aReq->adaptHistory();
#endif
#if ICAP_CLIENT
    icapHistory_ = aReq->icapHistory();
#endif

    // This may be too conservative for the 204 No Content case
    // may eventually need cloneNullAdaptationImmune() for that.
    flags = aReq->flags.cloneAdaptationImmune();

    if (aReq->auth_user_request) {
        auth_user_request = aReq->auth_user_request;
        AUTHUSERREQUESTLOCK(auth_user_request, "inheritProperties");
    }

    if (aReq->pinned_connection) {
        pinned_connection = cbdataReference(aReq->pinned_connection);
    }
    return true;
}

void HttpRequest::recordLookup(const DnsLookupDetails &dns)
{
    if (dns.wait >= 0) { // known delay
        if (dnsWait >= 0) // have recorded DNS wait before
            dnsWait += dns.wait;
        else
            dnsWait = dns.wait;
    }
}
