/*
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
#include "AccessLogEntry.h"
#include "acl/AclSizeLimit.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "DnsLookupDetails.h"
#include "err_detail_type.h"
#include "globals.h"
#include "gopher.h"
#include "http.h"
#include "HttpHdrCc.h"
#include "HttpHeaderRange.h"
#include "HttpRequest.h"
#include "log/Config.h"
#include "MemBuf.h"
#include "SquidConfig.h"
#include "Store.h"
#include "URL.h"

#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if ICAP_CLIENT
#include "adaptation/icap/icap_log.h"
#endif

HttpRequest::HttpRequest() :
        HttpMsg(hoRequest)
{
    init();
}

HttpRequest::HttpRequest(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *aUrlpath) :
        HttpMsg(hoRequest)
{
    static unsigned int id = 1;
    debugs(93,7, HERE << "constructed, this=" << this << " id=" << ++id);
    init();
    initHTTP(aMethod, aProtocol, aUrlpath);
}

HttpRequest::~HttpRequest()
{
    clean();
    debugs(93,7, HERE << "destructed, this=" << this);
}

void
HttpRequest::initHTTP(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *aUrlpath)
{
    method = aMethod;
    protocol = aProtocol;
    urlpath = aUrlpath;
}

void
HttpRequest::init()
{
    method = Http::METHOD_NONE;
    protocol = AnyP::PROTO_NONE;
    urlpath = NULL;
    login[0] = '\0';
    host[0] = '\0';
    host_is_numeric = -1;
#if USE_AUTH
    auth_user_request = NULL;
#endif
    port = 0;
    canonical = NULL;
    memset(&flags, '\0', sizeof(flags));
    range = NULL;
    ims = -1;
    imslen = 0;
    lastmod = -1;
    client_addr.setEmpty();
    my_addr.setEmpty();
    body_pipe = NULL;
    // hier
    dnsWait = -1;
    errType = ERR_NONE;
    errDetail = ERR_DETAIL_NONE;
    peer_login = NULL;		// not allocated/deallocated by this class
    peer_domain = NULL;		// not allocated/deallocated by this class
    peer_host = NULL;
    vary_headers = NULL;
    myportname = null_string;
    tag = null_string;
#if USE_AUTH
    extacl_user = null_string;
    extacl_passwd = null_string;
#endif
    extacl_log = null_string;
    extacl_message = null_string;
    pstate = psReadyToParseStartLine;
#if FOLLOW_X_FORWARDED_FOR
    indirect_client_addr.setEmpty();
#endif /* FOLLOW_X_FORWARDED_FOR */
#if USE_ADAPTATION
    adaptHistory_ = NULL;
#endif
#if ICAP_CLIENT
    icapHistory_ = NULL;
#endif
    rangeOffsetLimit = -2; //a value of -2 means not checked yet
}

void
HttpRequest::clean()
{
    // we used to assert that the pipe is NULL, but now the request only
    // points to a pipe that is owned and initiated by another object.
    body_pipe = NULL;
#if USE_AUTH
    auth_user_request = NULL;
#endif
    safe_free(canonical);

    safe_free(vary_headers);

    urlpath.clean();

    header.clean();

    if (cache_control) {
        delete cache_control;
        cache_control = NULL;
    }

    if (range) {
        delete range;
        range = NULL;
    }

    myportname.clean();

    notes = NULL;

    tag.clean();
#if USE_AUTH
    extacl_user.clean();
    extacl_passwd.clean();
#endif
    extacl_log.clean();

    extacl_message.clean();

    etag.clean();

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

    // range handled in hdrCacheInit()
    copy->ims = ims;
    copy->imslen = imslen;
    copy->hier = hier; // Is it safe to copy? Should we?

    copy->errType = errType;

    // XXX: what to do with copy->peer_login?

    copy->lastmod = lastmod;
    copy->etag = etag;
    copy->vary_headers = vary_headers ? xstrdup(vary_headers) : NULL;
    // XXX: what to do with copy->peer_domain?

    copy->tag = tag;
    copy->extacl_log = extacl_log;
    copy->extacl_message = extacl_message;

    const bool inheritWorked = copy->inheritProperties(this);
    assert(inheritWorked);

    return copy;
}

bool
HttpRequest::inheritProperties(const HttpMsg *aMsg)
{
    const HttpRequest* aReq = dynamic_cast<const HttpRequest*>(aMsg);
    if (!aReq)
        return false;

    client_addr = aReq->client_addr;
#if FOLLOW_X_FORWARDED_FOR
    indirect_client_addr = aReq->indirect_client_addr;
#endif
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

    errType = aReq->errType;
    errDetail = aReq->errDetail;
#if USE_AUTH
    auth_user_request = aReq->auth_user_request;
    extacl_user = aReq->extacl_user;
    extacl_passwd = aReq->extacl_passwd;
#endif

    myportname = aReq->myportname;

    // main property is which connection the request was received on (if any)
    clientConnectionManager = aReq->clientConnectionManager;

    notes = aReq->notes;
    return true;
}

/**
 * Checks the first line of an HTTP request is valid
 * currently just checks the request method is present.
 *
 * NP: Other errors are left for detection later in the parse.
 */
bool
HttpRequest::sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, Http::StatusCode *error)
{
    // content is long enough to possibly hold a reply
    // 2 being magic size of a 1-byte request method plus space delimiter
    if ( buf->contentSize() < 2 ) {
        // this is ony a real error if the headers apparently complete.
        if (hdr_len > 0) {
            debugs(58, 3, HERE << "Too large request header (" << hdr_len << " bytes)");
            *error = Http::scInvalidHeader;
        }
        return false;
    }

    /* See if the request buffer starts with a known HTTP request method. */
    if (HttpRequestMethod(buf->content(),NULL) == Http::METHOD_NONE) {
        debugs(73, 3, "HttpRequest::sanityCheckStartLine: did not find HTTP request method");
        *error = Http::scInvalidHeader;
        return false;
    }

    return true;
}

bool
HttpRequest::parseFirstLine(const char *start, const char *end)
{
    const char *t = start + strcspn(start, w_space);
    method = HttpRequestMethod(start, t);

    if (method == Http::METHOD_NONE)
        return false;

    start = t + strspn(t, w_space);

    const char *ver = findTrailingHTTPVersion(start, end);

    if (ver) {
        end = ver - 1;

        while (xisspace(*end)) // find prev non-space
            --end;

        ++end;                 // back to space

        if (2 != sscanf(ver + 5, "%d.%d", &http_ver.major, &http_ver.minor)) {
            debugs(73, DBG_IMPORTANT, "parseRequestLine: Invalid HTTP identifier.");
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
    packerPrintf(p, "%s " SQUIDSTRINGPH " HTTP/%d.%d\r\n",
                 RequestMethodStr(method), SQUIDSTRINGPRINT(urlpath),
                 http_ver.major, http_ver.minor);
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

    assert(!range);
    range = header.getRange();
}

#if ICAP_CLIENT
Adaptation::Icap::History::Pointer
HttpRequest::icapHistory() const
{
    if (!icapHistory_) {
        if (Log::TheConfig.hasIcapToken || IcapLogfileStatus == LOG_ENABLE) {
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
    return HttpRequest::adaptHistory(Log::TheConfig.hasAdaptToken);
}

void
HttpRequest::adaptHistoryImport(const HttpRequest &them)
{
    if (!adaptHistory_) {
        adaptHistory_ = them.adaptHistory_; // may be nil
    } else {
        // check that histories did not diverge
        Must(!them.adaptHistory_ || them.adaptHistory_ == adaptHistory_);
    }
}

#endif

bool
HttpRequest::multipartRangeRequest() const
{
    return (range && range->specs.count > 1);
}

bool
HttpRequest::bodyNibbled() const
{
    return body_pipe != NULL && body_pipe->consumedSize() > 0;
}

void
HttpRequest::detailError(err_type aType, int aDetail)
{
    if (errType || errDetail)
        debugs(11, 5, HERE << "old error details: " << errType << '/' << errDetail);
    debugs(11, 5, HERE << "current error details: " << aType << '/' << aDetail);
    // checking type and detail separately may cause inconsistency, but
    // may result in more details available if they only become available later
    if (!errType)
        errType = aType;
    if (!errDetail)
        errDetail = aDetail;
}

void
HttpRequest::clearError()
{
    debugs(11, 7, HERE << "old error details: " << errType << '/' << errDetail);
    errType = ERR_NONE;
    errDetail = ERR_DETAIL_NONE;
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
 * Indicate whether or not we would expect an entity-body
 * along with this request
 */
bool
HttpRequest::expectingBody(const HttpRequestMethod& unused, int64_t& theSize) const
{
    bool expectBody = false;

    /*
     * Note: Checks for message validity is in clientIsContentLengthValid().
     * this just checks if a entity-body is expected based on HTTP message syntax
     */
    if (header.chunked()) {
        expectBody = true;
        theSize = -1;
    } else if (content_length >= 0) {
        expectBody = true;
        theSize = content_length;
    } else {
        expectBody = false;
        // theSize undefined
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
    return urlParse(Http::METHOD_GET, url, NULL);
}

/**
 * Are responses to this request possible cacheable ?
 * If false then no matter what the response must not be cached.
 */
bool
HttpRequest::maybeCacheable()
{
    // Intercepted request with Host: header which cannot be trusted.
    // Because it failed verification, or someone bypassed the security tests
    // we cannot cache the reponse for sharing between clients.
    // TODO: update cache to store for particular clients only (going to same Host: and destination IP)
    if (!flags.hostVerified && (flags.intercepted || flags.interceptTproxy))
        return false;

    switch (protocol) {
    case AnyP::PROTO_HTTP:
    case AnyP::PROTO_HTTPS:
        if (!method.respMaybeCacheable())
            return false;

        // XXX: this would seem the correct place to detect request cache-controls
        //      no-store, private and related which block cacheability
        break;

    case AnyP::PROTO_GOPHER:
        if (!gopherCachable(this))
            return false;
        break;

    case AnyP::PROTO_CACHE_OBJECT:
        return false;

        //case AnyP::PROTO_FTP:
    default:
        break;
    }

    return true;
}

bool
HttpRequest::conditional() const
{
    return flags.ims ||
           header.has(HDR_IF_MATCH) ||
           header.has(HDR_IF_NONE_MATCH);
}

void
HttpRequest::recordLookup(const DnsLookupDetails &dns)
{
    if (dns.wait >= 0) { // known delay
        if (dnsWait >= 0) // have recorded DNS wait before
            dnsWait += dns.wait;
        else
            dnsWait = dns.wait;
    }
}

int64_t
HttpRequest::getRangeOffsetLimit()
{
    /* -2 is the starting value of rangeOffsetLimit.
     * If it is -2, that means we haven't checked it yet.
     *  Otherwise, return the current value */
    if (rangeOffsetLimit != -2)
        return rangeOffsetLimit;

    rangeOffsetLimit = 0; // default value for rangeOffsetLimit

    ACLFilledChecklist ch(NULL, this, NULL);
    ch.src_addr = client_addr;
    ch.my_addr =  my_addr;

    for (AclSizeLimit *l = Config.rangeOffsetLimit; l; l = l -> next) {
        /* if there is no ACL list or if the ACLs listed match use this limit value */
        if (!l->aclList || ch.fastCheck(l->aclList) == ACCESS_ALLOWED) {
            debugs(58, 4, HERE << "rangeOffsetLimit=" << rangeOffsetLimit);
            rangeOffsetLimit = l->size; // may be -1
            break;
        }
    }

    return rangeOffsetLimit;
}

void
HttpRequest::ignoreRange(const char *reason)
{
    if (range) {
        debugs(73, 3, static_cast<void*>(range) << " for " << reason);
        delete range;
        range = NULL;
    }
    // Some callers also reset isRanged but it may not be safe for all callers:
    // isRanged is used to determine whether a weak ETag comparison is allowed,
    // and that check should not ignore the Range header if it was present.
    // TODO: Some callers also delete HDR_RANGE, HDR_REQUEST_RANGE. Should we?
}

bool
HttpRequest::canHandle1xx() const
{
    // old clients do not support 1xx unless they sent Expect: 100-continue
    // (we reject all other HDR_EXPECT values so just check for HDR_EXPECT)
    if (http_ver <= Http::ProtocolVersion(1,0) && !header.has(HDR_EXPECT))
        return false;

    // others must support 1xx control messages
    return true;
}

ConnStateData *
HttpRequest::pinnedConnection()
{
    if (clientConnectionManager.valid() && clientConnectionManager->pinning.pinned)
        return clientConnectionManager.get();
    return NULL;
}

const char *
HttpRequest::storeId()
{
    if (store_id.size() != 0) {
        debugs(73, 3, "sent back store_id:" << store_id);

        return store_id.termedBuf();
    }
    debugs(73, 3, "sent back canonicalUrl:" << urlCanonical(this) );

    return urlCanonical(this);
}
