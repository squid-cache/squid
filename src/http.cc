/*
 * DEBUG: section 11    Hypertext Transfer Protocol (HTTP)
 * AUTHOR: Harvest Derived
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
 */

/*
 * Anonymizing patch by lutz@as-node.jena.thur.de
 * have a look into http-anon.c to get more informations.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base64.h"
#include "base/AsyncJobCalls.h"
#include "base/TextException.h"
#include "CachePeer.h"
#include "ChunkedCodingParser.h"
#include "client_side.h"
#include "comm/Connection.h"
#include "comm/Write.h"
#include "err_detail_type.h"
#include "errorpage.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "HttpControlMsg.h"
#include "http.h"
#include "HttpHdrCc.h"
#include "HttpHdrContRange.h"
#include "HttpHdrSc.h"
#include "HttpHdrScTarget.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "HttpStateFlags.h"
#include "log/access_log.h"
#include "MemBuf.h"
#include "MemObject.h"
#include "mime_header.h"
#include "neighbors.h"
#include "peer_proxy_negotiate_auth.h"
#include "profiler/Profiler.h"
#include "refresh.h"
#include "RefreshPattern.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "StatCounters.h"
#include "Store.h"
#include "StrList.h"
#include "tools.h"
#include "URL.h"

#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_DELAY_POOLS
#include "DelayPools.h"
#endif

#define SQUID_ENTER_THROWING_CODE() try {
#define SQUID_EXIT_THROWING_CODE(status) \
  	status = true; \
    } \
    catch (const std::exception &e) { \
	debugs (11, 1, "Exception error:" << e.what()); \
	status = false; \
    }

CBDATA_CLASS_INIT(HttpStateData);

static const char *const crlf = "\r\n";

static void httpMaybeRemovePublic(StoreEntry *, http_status);
static void copyOneHeaderFromClientsideRequestToUpstreamRequest(const HttpHeaderEntry *e, const String strConnection, const HttpRequest * request,
        HttpHeader * hdr_out, const int we_do_ranges, const HttpStateFlags &);
//Declared in HttpHeaderTools.cc
void httpHdrAdd(HttpHeader *heads, HttpRequest *request, const AccessLogEntryPointer &al, HeaderWithAclList &headers_add);

HttpStateData::HttpStateData(FwdState *theFwdState) : AsyncJob("HttpStateData"), ServerStateData(theFwdState),
        lastChunk(0), header_bytes_read(0), reply_bytes_read(0),
        body_bytes_truncated(0), httpChunkDecoder(NULL)
{
    debugs(11,5,HERE << "HttpStateData " << this << " created");
    ignoreCacheControl = false;
    surrogateNoStore = false;
    serverConnection = fwd->serverConnection();
    readBuf = new MemBuf;
    readBuf->init(16*1024, 256*1024);

    // reset peer response time stats for %<pt
    request->hier.peer_http_request_sent.tv_sec = 0;
    request->hier.peer_http_request_sent.tv_usec = 0;

    if (fwd->serverConnection() != NULL)
        _peer = cbdataReference(fwd->serverConnection()->getPeer());         /* might be NULL */

    if (_peer) {
        request->flags.proxying = 1;
        /*
         * This NEIGHBOR_PROXY_ONLY check probably shouldn't be here.
         * We might end up getting the object from somewhere else if,
         * for example, the request to this neighbor fails.
         */
        if (_peer->options.proxy_only)
            entry->releaseRequest();

#if USE_DELAY_POOLS
        entry->setNoDelay(_peer->options.no_delay);
#endif
    }

    /*
     * register the handler to free HTTP state data when the FD closes
     */
    typedef CommCbMemFunT<HttpStateData, CommCloseCbParams> Dialer;
    closeHandler = JobCallback(9, 5, Dialer, this, HttpStateData::httpStateConnClosed);
    comm_add_close_handler(serverConnection->fd, closeHandler);
}

HttpStateData::~HttpStateData()
{
    /*
     * don't forget that ~ServerStateData() gets called automatically
     */

    if (!readBuf->isNull())
        readBuf->clean();

    delete readBuf;

    if (httpChunkDecoder)
        delete httpChunkDecoder;

    cbdataReferenceDone(_peer);

    debugs(11,5, HERE << "HttpStateData " << this << " destroyed; " << serverConnection);
}

const Comm::ConnectionPointer &
HttpStateData::dataConnection() const
{
    return serverConnection;
}

void
HttpStateData::httpStateConnClosed(const CommCloseCbParams &params)
{
    debugs(11, 5, "httpStateFree: FD " << params.fd << ", httpState=" << params.data);
    mustStop("HttpStateData::httpStateConnClosed");
}

int
httpCachable(const HttpRequestMethod& method)
{
    /* GET and HEAD are cachable. Others are not. */

    // TODO: replase to HttpRequestMethod::isCachable() ?
    if (method != METHOD_GET && method != METHOD_HEAD)
        return 0;

    /* else cachable */
    return 1;
}

void
HttpStateData::httpTimeout(const CommTimeoutCbParams &params)
{
    debugs(11, 4, HERE << serverConnection << ": '" << entry->url() << "'" );

    if (entry->store_status == STORE_PENDING) {
        fwd->fail(new ErrorState(ERR_READ_TIMEOUT, HTTP_GATEWAY_TIMEOUT, fwd->request));
    }

    serverConnection->close();
}

static void
httpMaybeRemovePublic(StoreEntry * e, http_status status)
{
    int remove = 0;
    int forbidden = 0;
    StoreEntry *pe;

    if (!EBIT_TEST(e->flags, KEY_PRIVATE))
        return;

    switch (status) {

    case HTTP_OK:

    case HTTP_NON_AUTHORITATIVE_INFORMATION:

    case HTTP_MULTIPLE_CHOICES:

    case HTTP_MOVED_PERMANENTLY:

    case HTTP_MOVED_TEMPORARILY:

    case HTTP_GONE:

    case HTTP_NOT_FOUND:
        remove = 1;

        break;

    case HTTP_FORBIDDEN:

    case HTTP_METHOD_NOT_ALLOWED:
        forbidden = 1;

        break;

#if WORK_IN_PROGRESS

    case HTTP_UNAUTHORIZED:
        forbidden = 1;

        break;

#endif

    default:
#if QUESTIONABLE
        /*
         * Any 2xx response should eject previously cached entities...
         */

        if (status >= 200 && status < 300)
            remove = 1;

#endif

        break;
    }

    if (!remove && !forbidden)
        return;

    assert(e->mem_obj);

    if (e->mem_obj->request)
        pe = storeGetPublicByRequest(e->mem_obj->request);
    else
        pe = storeGetPublic(e->mem_obj->url, e->mem_obj->method);

    if (pe != NULL) {
        assert(e != pe);
#if USE_HTCP
        neighborsHtcpClear(e, NULL, e->mem_obj->request, e->mem_obj->method, HTCP_CLR_INVALIDATION);
#endif
        pe->release();
    }

    /** \par
     * Also remove any cached HEAD response in case the object has
     * changed.
     */
    if (e->mem_obj->request)
        pe = storeGetPublicByRequestMethod(e->mem_obj->request, METHOD_HEAD);
    else
        pe = storeGetPublic(e->mem_obj->url, METHOD_HEAD);

    if (pe != NULL) {
        assert(e != pe);
#if USE_HTCP
        neighborsHtcpClear(e, NULL, e->mem_obj->request, HttpRequestMethod(METHOD_HEAD), HTCP_CLR_INVALIDATION);
#endif
        pe->release();
    }
}

void
HttpStateData::processSurrogateControl(HttpReply *reply)
{
    if (request->flags.accelerated && reply->surrogate_control) {
        HttpHdrScTarget *sctusable = reply->surrogate_control->getMergedTarget(Config.Accel.surrogate_id);

        if (sctusable) {
            if (sctusable->noStore() ||
                    (Config.onoff.surrogate_is_remote
                     && sctusable->noStoreRemote())) {
                surrogateNoStore = true;
                entry->makePrivate();
            }

            /* The HttpHeader logic cannot tell if the header it's parsing is a reply to an
             * accelerated request or not...
             * Still, this is an abstraction breach. - RC
             */
            if (sctusable->hasMaxAge()) {
                if (sctusable->maxAge() < sctusable->maxStale())
                    reply->expires = reply->date + sctusable->maxAge();
                else
                    reply->expires = reply->date + sctusable->maxStale();

                /* And update the timestamps */
                entry->timestampsSet();
            }

            /* We ignore cache-control directives as per the Surrogate specification */
            ignoreCacheControl = true;

            delete sctusable;
        }
    }
}

int
HttpStateData::cacheableReply()
{
    HttpReply const *rep = finalReply();
    HttpHeader const *hdr = &rep->header;
    const char *v;
#if USE_HTTP_VIOLATIONS

    const RefreshPattern *R = NULL;

    /* This strange looking define first looks up the refresh pattern
     * and then checks if the specified flag is set. The main purpose
     * of this is to simplify the refresh pattern lookup and USE_HTTP_VIOLATIONS
     * condition
     */
#define REFRESH_OVERRIDE(flag) \
    ((R = (R ? R : refreshLimits(entry->mem_obj->url))) , \
    (R && R->flags.flag))
#else
#define REFRESH_OVERRIDE(flag) 0
#endif

    // Check for Surrogate/1.0 protocol conditions
    // NP: reverse-proxy traffic our parent server has instructed us never to cache
    if (surrogateNoStore) {
        debugs(22, 3, HERE << "NO because Surrogate-Control:no-store");
        return 0;
    }

    // RFC 2616: HTTP/1.1 Cache-Control conditions
    if (!ignoreCacheControl) {
        // XXX: check to see if the request headers alone were enough to prevent caching earlier
        // (ie no-store request header) no need to check those all again here if so.
        // for now we are not reliably doing that so we waste CPU re-checking request CC

        // RFC 2616 section 14.9.2 - MUST NOT cache any response with request CC:no-store
        if (request && request->cache_control && request->cache_control->noStore() &&
                !REFRESH_OVERRIDE(ignore_no_store)) {
            debugs(22, 3, HERE << "NO because client request Cache-Control:no-store");
            return 0;
        }

        // NP: request CC:no-cache only means cache READ is forbidden. STORE is permitted.
        if (rep->cache_control && rep->cache_control->hasNoCache() && rep->cache_control->noCache().defined()) {
            /* TODO: we are allowed to cache when no-cache= has parameters.
             * Provided we strip away any of the listed headers unless they are revalidated
             * successfully (ie, must revalidate AND these headers are prohibited on stale replies).
             * That is a bit tricky for squid right now so we avoid caching entirely.
             */
            debugs(22, 3, HERE << "NO because server reply Cache-Control:no-cache has parameters");
            return 0;
        }

        // NP: request CC:private is undefined. We ignore.
        // NP: other request CC flags are limiters on HIT/MISS. We don't care about here.

        // RFC 2616 section 14.9.2 - MUST NOT cache any response with CC:no-store
        if (rep->cache_control && rep->cache_control->noStore() &&
                !REFRESH_OVERRIDE(ignore_no_store)) {
            debugs(22, 3, HERE << "NO because server reply Cache-Control:no-store");
            return 0;
        }

        // RFC 2616 section 14.9.1 - MUST NOT cache any response with CC:private in a shared cache like Squid.
        // CC:private overrides CC:public when both are present in a response.
        // TODO: add a shared/private cache configuration possibility.
        if (rep->cache_control &&
                rep->cache_control->hasPrivate() &&
                !REFRESH_OVERRIDE(ignore_private)) {
            /* TODO: we are allowed to cache when private= has parameters.
             * Provided we strip away any of the listed headers unless they are revalidated
             * successfully (ie, must revalidate AND these headers are prohibited on stale replies).
             * That is a bit tricky for squid right now so we avoid caching entirely.
             */
            debugs(22, 3, HERE << "NO because server reply Cache-Control:private");
            return 0;
        }
    }

    // RFC 2068, sec 14.9.4 - MUST NOT cache any response with Authentication UNLESS certain CC controls are present
    // allow HTTP violations to IGNORE those controls (ie re-block caching Auth)
    if (request && (request->flags.auth || request->flags.authSent) && !REFRESH_OVERRIDE(ignore_auth)) {
        if (!rep->cache_control) {
            debugs(22, 3, HERE << "NO because Authenticated and server reply missing Cache-Control");
            return 0;
        }

        if (ignoreCacheControl) {
            debugs(22, 3, HERE << "NO because Authenticated and ignoring Cache-Control");
            return 0;
        }

        bool mayStore = false;
        // HTTPbis pt6 section 3.2: a response CC:public is present
        if (rep->cache_control->Public()) {
            debugs(22, 3, HERE << "Authenticated but server reply Cache-Control:public");
            mayStore = true;

            // HTTPbis pt6 section 3.2: a response CC:must-revalidate is present
        } else if (rep->cache_control->mustRevalidate() && !REFRESH_OVERRIDE(ignore_must_revalidate)) {
            debugs(22, 3, HERE << "Authenticated but server reply Cache-Control:public");
            mayStore = true;

#if USE_HTTP_VIOLATIONS
            // NP: given the must-revalidate exception we should also be able to exempt no-cache.
            // HTTPbis WG verdict on this is that it is omitted from the spec due to being 'unexpected' by
            // some. The caching+revalidate is not exactly unsafe though with Squids interpretation of no-cache
            // (without parameters) as equivalent to must-revalidate in the reply.
        } else if (rep->cache_control->hasNoCache() && !rep->cache_control->noCache().defined() && !REFRESH_OVERRIDE(ignore_must_revalidate)) {
            debugs(22, 3, HERE << "Authenticated but server reply Cache-Control:no-cache (equivalent to must-revalidate)");
            mayStore = true;
#endif

            // HTTPbis pt6 section 3.2: a response CC:s-maxage is present
        } else if (rep->cache_control->sMaxAge()) {
            debugs(22, 3, HERE << "Authenticated but server reply Cache-Control:s-maxage");
            mayStore = true;
        }

        if (!mayStore) {
            debugs(22, 3, HERE << "NO because Authenticated transaction");
            return 0;
        }

        // NP: response CC:no-cache is equivalent to CC:must-revalidate,max-age=0. We MAY cache, and do so.
        // NP: other request CC flags are limiters on HIT/MISS/REFRESH. We don't care about here.
    }

    /* HACK: The "multipart/x-mixed-replace" content type is used for
     * continuous push replies.  These are generally dynamic and
     * probably should not be cachable
     */
    if ((v = hdr->getStr(HDR_CONTENT_TYPE)))
        if (!strncasecmp(v, "multipart/x-mixed-replace", 25)) {
            debugs(22, 3, HERE << "NO because Content-Type:multipart/x-mixed-replace");
            return 0;
        }

    switch (rep->sline.status) {
        /* Responses that are cacheable */

    case HTTP_OK:

    case HTTP_NON_AUTHORITATIVE_INFORMATION:

    case HTTP_MULTIPLE_CHOICES:

    case HTTP_MOVED_PERMANENTLY:
    case HTTP_PERMANENT_REDIRECT:

    case HTTP_GONE:
        /*
         * Don't cache objects that need to be refreshed on next request,
         * unless we know how to refresh it.
         */

        if (!refreshIsCachable(entry) && !REFRESH_OVERRIDE(store_stale)) {
            debugs(22, 3, "NO because refreshIsCachable() returned non-cacheable..");
            return 0;
        } else {
            debugs(22, 3, HERE << "YES because HTTP status " << rep->sline.status);
            return 1;
        }
        /* NOTREACHED */
        break;

        /* Responses that only are cacheable if the server says so */

    case HTTP_MOVED_TEMPORARILY:
    case HTTP_TEMPORARY_REDIRECT:
        if (rep->date <= 0) {
            debugs(22, 3, HERE << "NO because HTTP status " << rep->sline.status << " and Date missing/invalid");
            return 0;
        }
        if (rep->expires > rep->date) {
            debugs(22, 3, HERE << "YES because HTTP status " << rep->sline.status << " and Expires > Date");
            return 1;
        } else {
            debugs(22, 3, HERE << "NO because HTTP status " << rep->sline.status << " and Expires <= Date");
            return 0;
        }
        /* NOTREACHED */
        break;

        /* Errors can be negatively cached */

    case HTTP_NO_CONTENT:

    case HTTP_USE_PROXY:

    case HTTP_BAD_REQUEST:

    case HTTP_FORBIDDEN:

    case HTTP_NOT_FOUND:

    case HTTP_METHOD_NOT_ALLOWED:

    case HTTP_REQUEST_URI_TOO_LARGE:

    case HTTP_INTERNAL_SERVER_ERROR:

    case HTTP_NOT_IMPLEMENTED:

    case HTTP_BAD_GATEWAY:

    case HTTP_SERVICE_UNAVAILABLE:

    case HTTP_GATEWAY_TIMEOUT:
        debugs(22, 3, HERE << "MAYBE because HTTP status " << rep->sline.status);
        return -1;

        /* NOTREACHED */
        break;

        /* Some responses can never be cached */

    case HTTP_PARTIAL_CONTENT:	/* Not yet supported */

    case HTTP_SEE_OTHER:

    case HTTP_NOT_MODIFIED:

    case HTTP_UNAUTHORIZED:

    case HTTP_PROXY_AUTHENTICATION_REQUIRED:

    case HTTP_INVALID_HEADER:	/* Squid header parsing error */

    case HTTP_HEADER_TOO_LARGE:

    case HTTP_PAYMENT_REQUIRED:
    case HTTP_NOT_ACCEPTABLE:
    case HTTP_REQUEST_TIMEOUT:
    case HTTP_CONFLICT:
    case HTTP_LENGTH_REQUIRED:
    case HTTP_PRECONDITION_FAILED:
    case HTTP_REQUEST_ENTITY_TOO_LARGE:
    case HTTP_UNSUPPORTED_MEDIA_TYPE:
    case HTTP_UNPROCESSABLE_ENTITY:
    case HTTP_LOCKED:
    case HTTP_FAILED_DEPENDENCY:
    case HTTP_INSUFFICIENT_STORAGE:
    case HTTP_REQUESTED_RANGE_NOT_SATISFIABLE:
    case HTTP_EXPECTATION_FAILED:

        debugs(22, 3, HERE << "NO because HTTP status " << rep->sline.status);
        return 0;

    default:
        /* RFC 2616 section 6.1.1: an unrecognized response MUST NOT be cached. */
        debugs (11, 3, HERE << "NO because unknown HTTP status code " << rep->sline.status);
        return 0;

        /* NOTREACHED */
        break;
    }

    /* NOTREACHED */
}

/*
 * For Vary, store the relevant request headers as
 * virtual headers in the reply
 * Returns false if the variance cannot be stored
 */
const char *
httpMakeVaryMark(HttpRequest * request, HttpReply const * reply)
{
    String vary, hdr;
    const char *pos = NULL;
    const char *item;
    const char *value;
    int ilen;
    static String vstr;

    vstr.clean();
    vary = reply->header.getList(HDR_VARY);

    while (strListGetItem(&vary, ',', &item, &ilen, &pos)) {
        char *name = (char *)xmalloc(ilen + 1);
        xstrncpy(name, item, ilen + 1);
        Tolower(name);

        if (strcmp(name, "*") == 0) {
            /* Can not handle "Vary: *" withtout ETag support */
            safe_free(name);
            vstr.clean();
            break;
        }

        strListAdd(&vstr, name, ',');
        hdr = request->header.getByName(name);
        safe_free(name);
        value = hdr.termedBuf();

        if (value) {
            value = rfc1738_escape_part(value);
            vstr.append("=\"", 2);
            vstr.append(value);
            vstr.append("\"", 1);
        }

        hdr.clean();
    }

    vary.clean();
#if X_ACCELERATOR_VARY

    pos = NULL;
    vary = reply->header.getList(HDR_X_ACCELERATOR_VARY);

    while (strListGetItem(&vary, ',', &item, &ilen, &pos)) {
        char *name = (char *)xmalloc(ilen + 1);
        xstrncpy(name, item, ilen + 1);
        Tolower(name);
        strListAdd(&vstr, name, ',');
        hdr = request->header.getByName(name);
        safe_free(name);
        value = hdr.termedBuf();

        if (value) {
            value = rfc1738_escape_part(value);
            vstr.append("=\"", 2);
            vstr.append(value);
            vstr.append("\"", 1);
        }

        hdr.clean();
    }

    vary.clean();
#endif

    debugs(11, 3, "httpMakeVaryMark: " << vstr);
    return vstr.termedBuf();
}

void
HttpStateData::keepaliveAccounting(HttpReply *reply)
{
    if (flags.keepalive)
        if (_peer)
            ++ _peer->stats.n_keepalives_sent;

    if (reply->keep_alive) {
        if (_peer)
            ++ _peer->stats.n_keepalives_recv;

        if (Config.onoff.detect_broken_server_pconns
                && reply->bodySize(request->method) == -1 && !flags.chunked) {
            debugs(11, DBG_IMPORTANT, "keepaliveAccounting: Impossible keep-alive header from '" << entry->url() << "'" );
            // debugs(11, 2, "GOT HTTP REPLY HDR:\n---------\n" << readBuf->content() << "\n----------" );
            flags.keepalive_broken = true;
        }
    }
}

void
HttpStateData::checkDateSkew(HttpReply *reply)
{
    if (reply->date > -1 && !_peer) {
        int skew = abs((int)(reply->date - squid_curtime));

        if (skew > 86400)
            debugs(11, 3, "" << request->GetHost() << "'s clock is skewed by " << skew << " seconds!");
    }
}

/**
 * This creates the error page itself.. its likely
 * that the forward ported reply header max size patch
 * generates non http conformant error pages - in which
 * case the errors where should be 'BAD_GATEWAY' etc
 */
void
HttpStateData::processReplyHeader()
{
    /** Creates a blank header. If this routine is made incremental, this will not do */

    /* NP: all exit points to this function MUST call ctx_exit(ctx) */
    Ctx ctx = ctx_enter(entry->mem_obj->url);

    debugs(11, 3, "processReplyHeader: key '" << entry->getMD5Text() << "'");

    assert(!flags.headers_parsed);

    if (!readBuf->hasContent()) {
        ctx_exit(ctx);
        return;
    }

    http_status error = HTTP_STATUS_NONE;

    HttpReply *newrep = new HttpReply;
    const bool parsed = newrep->parse(readBuf, eof, &error);

    if (!parsed && readBuf->contentSize() > 5 && strncmp(readBuf->content(), "HTTP/", 5) != 0 && strncmp(readBuf->content(), "ICY", 3) != 0) {
        MemBuf *mb;
        HttpReply *tmprep = new HttpReply;
        tmprep->setHeaders(HTTP_OK, "Gatewaying", NULL, -1, -1, -1);
        tmprep->header.putExt("X-Transformed-From", "HTTP/0.9");
        mb = tmprep->pack();
        newrep->parse(mb, eof, &error);
        delete mb;
        delete tmprep;
    } else {
        if (!parsed && error > 0) { // unrecoverable parsing error
            debugs(11, 3, "processReplyHeader: Non-HTTP-compliant header: '" <<  readBuf->content() << "'");
            flags.headers_parsed = true;
            newrep->sline.version = HttpVersion(1,1);
            newrep->sline.status = error;
            HttpReply *vrep = setVirginReply(newrep);
            entry->replaceHttpReply(vrep);
            ctx_exit(ctx);
            return;
        }

        if (!parsed) { // need more data
            assert(!error);
            assert(!eof);
            delete newrep;
            ctx_exit(ctx);
            return;
        }

        debugs(11, 2, "HTTP Server " << serverConnection);
        debugs(11, 2, "HTTP Server REPLY:\n---------\n" << readBuf->content() << "\n----------");

        header_bytes_read = headersEnd(readBuf->content(), readBuf->contentSize());
        readBuf->consume(header_bytes_read);
    }

    newrep->removeStaleWarnings();

    if (newrep->sline.protocol == AnyP::PROTO_HTTP && newrep->sline.status >= 100 && newrep->sline.status < 200) {
        handle1xx(newrep);
        ctx_exit(ctx);
        return;
    }

    flags.chunked = false;
    if (newrep->sline.protocol == AnyP::PROTO_HTTP && newrep->header.chunked()) {
        flags.chunked = true;
        httpChunkDecoder = new ChunkedCodingParser;
    }

    if (!peerSupportsConnectionPinning())
        request->flags.connectionAuthDisabled = 1;

    HttpReply *vrep = setVirginReply(newrep);
    flags.headers_parsed = true;

    keepaliveAccounting(vrep);

    checkDateSkew(vrep);

    processSurrogateControl (vrep);

    request->hier.peer_reply_status = newrep->sline.status;

    ctx_exit(ctx);
}

/// ignore or start forwarding the 1xx response (a.k.a., control message)
void
HttpStateData::handle1xx(HttpReply *reply)
{
    HttpMsgPointerT<HttpReply> msg(reply); // will destroy reply if unused

    // one 1xx at a time: we must not be called while waiting for previous 1xx
    Must(!flags.handling1xx);
    flags.handling1xx = true;

    if (!request->canHandle1xx()) {
        debugs(11, 2, HERE << "ignoring client-unsupported 1xx");
        proceedAfter1xx();
        return;
    }

#if USE_HTTP_VIOLATIONS
    // check whether the 1xx response forwarding is allowed by squid.conf
    if (Config.accessList.reply) {
        ACLFilledChecklist ch(Config.accessList.reply, originalRequest(), NULL);
        ch.reply = HTTPMSGLOCK(reply);
        if (ch.fastCheck() != ACCESS_ALLOWED) { // TODO: support slow lookups?
            debugs(11, 3, HERE << "ignoring denied 1xx");
            proceedAfter1xx();
            return;
        }
    }
#endif // USE_HTTP_VIOLATIONS

    debugs(11, 2, HERE << "forwarding 1xx to client");

    // the Sink will use this to call us back after writing 1xx to the client
    typedef NullaryMemFunT<HttpStateData> CbDialer;
    const AsyncCall::Pointer cb = JobCallback(11, 3, CbDialer, this,
                                  HttpStateData::proceedAfter1xx);
    CallJobHere1(11, 4, request->clientConnectionManager, ConnStateData,
                 ConnStateData::sendControlMsg, HttpControlMsg(msg, cb));
    // If the call is not fired, then the Sink is gone, and HttpStateData
    // will terminate due to an aborted store entry or another similar error.
    // If we get stuck, it is not handle1xx fault if we could get stuck
    // for similar reasons without a 1xx response.
}

/// restores state and resumes processing after 1xx is ignored or forwarded
void
HttpStateData::proceedAfter1xx()
{
    Must(flags.handling1xx);

    debugs(11, 2, HERE << "consuming " << header_bytes_read <<
           " header and " << reply_bytes_read << " body bytes read after 1xx");
    header_bytes_read = 0;
    reply_bytes_read = 0;

    CallJobHere(11, 3, this, HttpStateData, HttpStateData::processReply);
}

/**
 * returns true if the peer can support connection pinning
*/
bool HttpStateData::peerSupportsConnectionPinning() const
{
    const HttpReply *rep = entry->mem_obj->getReply();
    const HttpHeader *hdr = &rep->header;
    bool rc;
    String header;

    if (!_peer)
        return true;

    /*If this peer does not support connection pinning (authenticated
      connections) return false
     */
    if (!_peer->connection_auth)
        return false;

    /*The peer supports connection pinning and the http reply status
      is not unauthorized, so the related connection can be pinned
     */
    if (rep->sline.status != HTTP_UNAUTHORIZED)
        return true;

    /*The server respond with HTTP_UNAUTHORIZED and the peer configured
      with "connection-auth=on" we know that the peer supports pinned
      connections
    */
    if (_peer->connection_auth == 1)
        return true;

    /*At this point peer has configured with "connection-auth=auto"
      parameter so we need some extra checks to decide if we are going
      to allow pinned connections or not
    */

    /*if the peer configured with originserver just allow connection
        pinning (squid 2.6 behaviour)
     */
    if (_peer->options.originserver)
        return true;

    /*if the connections it is already pinned it is OK*/
    if (request->flags.pinned)
        return true;

    /*Allow pinned connections only if the Proxy-support header exists in
      reply and has in its list the "Session-Based-Authentication"
      which means that the peer supports connection pinning.
     */
    if (!hdr->has(HDR_PROXY_SUPPORT))
        return false;

    header = hdr->getStrOrList(HDR_PROXY_SUPPORT);
    /* XXX This ought to be done in a case-insensitive manner */
    rc = (strstr(header.termedBuf(), "Session-Based-Authentication") != NULL);

    return rc;
}

// Called when we parsed (and possibly adapted) the headers but
// had not starting storing (a.k.a., sending) the body yet.
void
HttpStateData::haveParsedReplyHeaders()
{
    ServerStateData::haveParsedReplyHeaders();

    Ctx ctx = ctx_enter(entry->mem_obj->url);
    HttpReply *rep = finalReply();

    if (rep->sline.status == HTTP_PARTIAL_CONTENT &&
            rep->content_range)
        currentOffset = rep->content_range->spec.offset;

    entry->timestampsSet();

    /* Check if object is cacheable or not based on reply code */
    debugs(11, 3, "haveParsedReplyHeaders: HTTP CODE: " << rep->sline.status);

    if (neighbors_do_private_keys)
        httpMaybeRemovePublic(entry, rep->sline.status);

    if (rep->header.has(HDR_VARY)
#if X_ACCELERATOR_VARY
            || rep->header.has(HDR_X_ACCELERATOR_VARY)
#endif
       ) {
        const char *vary = httpMakeVaryMark(request, rep);

        if (!vary) {
            entry->makePrivate();
            if (!fwd->reforwardableStatus(rep->sline.status))
                EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
            goto no_cache;
        }

        entry->mem_obj->vary_headers = xstrdup(vary);
    }

    /*
     * If its not a reply that we will re-forward, then
     * allow the client to get it.
     */
    if (!fwd->reforwardableStatus(rep->sline.status))
        EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);

    switch (cacheableReply()) {

    case 1:
        entry->makePublic();
        break;

    case 0:
        entry->makePrivate();
        break;

    case -1:

#if USE_HTTP_VIOLATIONS
        if (Config.negativeTtl > 0)
            entry->cacheNegatively();
        else
#endif
            entry->makePrivate();

        break;

    default:
        assert(0);

        break;
    }

no_cache:

    if (!ignoreCacheControl) {
        if (rep->cache_control) {
            // We are required to revalidate on many conditions.
            // For security reasons we do so even if storage was caused by refresh_pattern ignore-* option

            // CC:must-revalidate or CC:proxy-revalidate
            const bool ccMustRevalidate = (rep->cache_control->proxyRevalidate() || rep->cache_control->mustRevalidate());

            // CC:no-cache (only if there are no parameters)
            const bool ccNoCacheNoParams = (rep->cache_control->hasNoCache() && rep->cache_control->noCache().undefined());

            // CC:s-maxage=N
            const bool ccSMaxAge = rep->cache_control->hasSMaxAge();

            // CC:private (yes, these can sometimes be stored)
            const bool ccPrivate = rep->cache_control->hasPrivate();

            if (ccMustRevalidate || ccNoCacheNoParams || ccSMaxAge || ccPrivate)
                EBIT_SET(entry->flags, ENTRY_REVALIDATE);
        }
#if USE_HTTP_VIOLATIONS // response header Pragma::no-cache is undefined in HTTP
        else {
            // Expensive calculation. So only do it IF the CC: header is not present.

            /* HACK: Pragma: no-cache in _replies_ is not documented in HTTP,
             * but servers like "Active Imaging Webcast/2.0" sure do use it */
            if (rep->header.has(HDR_PRAGMA) &&
                    rep->header.hasListMember(HDR_PRAGMA,"no-cache",','))
                EBIT_SET(entry->flags, ENTRY_REVALIDATE);
        }
#endif
    }

#if HEADERS_LOG
    headersLog(1, 0, request->method, rep);

#endif

    ctx_exit(ctx);
}

HttpStateData::ConnectionStatus
HttpStateData::statusIfComplete() const
{
    const HttpReply *rep = virginReply();
    /** \par
     * If the reply wants to close the connection, it takes precedence */

    if (httpHeaderHasConnDir(&rep->header, "close"))
        return COMPLETE_NONPERSISTENT_MSG;

    /** \par
     * If we didn't send a keep-alive request header, then this
     * can not be a persistent connection.
     */
    if (!flags.keepalive)
        return COMPLETE_NONPERSISTENT_MSG;

    /** \par
     * If we haven't sent the whole request then this can not be a persistent
     * connection.
     */
    if (!flags.request_sent) {
        debugs(11, 2, "statusIfComplete: Request not yet fully sent \"" << RequestMethodStr(request->method) << " " << entry->url() << "\"" );
        return COMPLETE_NONPERSISTENT_MSG;
    }

    /** \par
     * What does the reply have to say about keep-alive?
     */
    /**
     \bug XXX BUG?
     * If the origin server (HTTP/1.0) does not send a keep-alive
     * header, but keeps the connection open anyway, what happens?
     * We'll return here and http.c waits for an EOF before changing
     * store_status to STORE_OK.   Combine this with ENTRY_FWD_HDR_WAIT
     * and an error status code, and we might have to wait until
     * the server times out the socket.
     */
    if (!rep->keep_alive)
        return COMPLETE_NONPERSISTENT_MSG;

    return COMPLETE_PERSISTENT_MSG;
}

HttpStateData::ConnectionStatus
HttpStateData::persistentConnStatus() const
{
    debugs(11, 3, HERE << serverConnection << " eof=" << eof);
    if (eof) // already reached EOF
        return COMPLETE_NONPERSISTENT_MSG;

    /* If server fd is closing (but we have not been notified yet), stop Comm
       I/O to avoid assertions. TODO: Change Comm API to handle callers that
       want more I/O after async closing (usually initiated by others). */
    // XXX: add canReceive or s/canSend/canTalkToServer/
    if (!Comm::IsConnOpen(serverConnection))
        return COMPLETE_NONPERSISTENT_MSG;

    /** \par
     * In chunked response we do not know the content length but we are absolutely
     * sure about the end of response, so we are calling the statusIfComplete to
     * decide if we can be persistant
     */
    if (lastChunk && flags.chunked)
        return statusIfComplete();

    const HttpReply *vrep = virginReply();
    debugs(11, 5, "persistentConnStatus: content_length=" << vrep->content_length);

    const int64_t clen = vrep->bodySize(request->method);

    debugs(11, 5, "persistentConnStatus: clen=" << clen);

    /* If the body size is unknown we must wait for EOF */
    if (clen < 0)
        return INCOMPLETE_MSG;

    /** \par
     * If the body size is known, we must wait until we've gotten all of it. */
    if (clen > 0) {
        // old technique:
        // if (entry->mem_obj->endOffset() < vrep->content_length + vrep->hdr_sz)
        const int64_t body_bytes_read = reply_bytes_read - header_bytes_read;
        debugs(11,5, "persistentConnStatus: body_bytes_read=" <<
               body_bytes_read << " content_length=" << vrep->content_length);

        if (body_bytes_read < vrep->content_length)
            return INCOMPLETE_MSG;

        if (body_bytes_truncated > 0) // already read more than needed
            return COMPLETE_NONPERSISTENT_MSG; // disable pconns
    }

    /** \par
     * If there is no message body or we got it all, we can be persistent */
    return statusIfComplete();
}

/*
 * This is the callback after some data has been read from the network
 */
/*
void
HttpStateData::ReadReplyWrapper(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    HttpStateData *httpState = static_cast<HttpStateData *>(data);
    assert (fd == httpState->serverConnection->fd);
    // assert(buf == readBuf->content());
    PROF_start(HttpStateData_readReply);
    httpState->readReply(len, flag, xerrno);
    PROF_stop(HttpStateData_readReply);
}
*/

/* XXX this function is too long! */
void
HttpStateData::readReply(const CommIoCbParams &io)
{
    int bin;
    int clen;
    int len = io.size;

    flags.do_next_read = false;

    debugs(11, 5, HERE << io.conn << ": len " << len << ".");

    // Bail out early on COMM_ERR_CLOSING - close handlers will tidy up for us
    if (io.flag == COMM_ERR_CLOSING) {
        debugs(11, 3, "http socket closing");
        return;
    }

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        abortTransaction("store entry aborted while reading reply");
        return;
    }

    // handle I/O errors
    if (io.flag != COMM_OK || len < 0) {
        debugs(11, 2, HERE << io.conn << ": read failure: " << xstrerror() << ".");

        if (ignoreErrno(io.xerrno)) {
            flags.do_next_read = true;
        } else {
            ErrorState *err = new ErrorState(ERR_READ_ERROR, HTTP_BAD_GATEWAY, fwd->request);
            err->xerrno = io.xerrno;
            fwd->fail(err);
            flags.do_next_read = false;
            serverConnection->close();
        }

        return;
    }

    // update I/O stats
    if (len > 0) {
        readBuf->appended(len);
        reply_bytes_read += len;
#if USE_DELAY_POOLS
        DelayId delayId = entry->mem_obj->mostBytesAllowed();
        delayId.bytesIn(len);
#endif

        kb_incr(&(statCounter.server.all.kbytes_in), len);
        kb_incr(&(statCounter.server.http.kbytes_in), len);
        ++ IOStats.Http.reads;

        for (clen = len - 1, bin = 0; clen; ++bin)
            clen >>= 1;

        ++ IOStats.Http.read_hist[bin];

        // update peer response time stats (%<pt)
        const timeval &sent = request->hier.peer_http_request_sent;
        request->hier.peer_response_time =
            sent.tv_sec ? tvSubMsec(sent, current_time) : -1;
    }

    /** \par
     * Here the RFC says we should ignore whitespace between replies, but we can't as
     * doing so breaks HTTP/0.9 replies beginning with witespace, and in addition
     * the response splitting countermeasures is extremely likely to trigger on this,
     * not allowing connection reuse in the first place.
     *
     * 2012-02-10: which RFC? not 2068 or 2616,
     *     tolerance there is all about whitespace between requests and header tokens.
     */

    if (len == 0) { // reached EOF?
        eof = 1;
        flags.do_next_read = false;

        /* Bug 2879: Replies may terminate with \r\n then EOF instead of \r\n\r\n
         * Ensure here that we have at minimum two \r\n when EOF is seen.
         * TODO: Add eof parameter to headersEnd() and move this hack there.
         */
        if (readBuf->contentSize() && !flags.headers_parsed) {
            /*
             * Yes Henrik, there is a point to doing this.  When we
             * called httpProcessReplyHeader() before, we didn't find
             * the end of headers, but now we are definately at EOF, so
             * we want to process the reply headers.
             */
            /* Fake an "end-of-headers" to work around such broken servers */
            readBuf->append("\r\n", 2);
        }
    }

    processReply();
}

/// processes the already read and buffered response data, possibly after
/// waiting for asynchronous 1xx control message processing
void
HttpStateData::processReply()
{

    if (flags.handling1xx) { // we came back after handling a 1xx response
        debugs(11, 5, HERE << "done with 1xx handling");
        flags.handling1xx = false;
        Must(!flags.headers_parsed);
    }

    if (!flags.headers_parsed) { // have not parsed headers yet?
        PROF_start(HttpStateData_processReplyHeader);
        processReplyHeader();
        PROF_stop(HttpStateData_processReplyHeader);

        if (!continueAfterParsingHeader()) // parsing error or need more data
            return; // TODO: send errors to ICAP

        adaptOrFinalizeReply(); // may write to, abort, or "close" the entry
    }

    // kick more reads if needed and/or process the response body, if any
    PROF_start(HttpStateData_processReplyBody);
    processReplyBody(); // may call serverComplete()
    PROF_stop(HttpStateData_processReplyBody);
}

/**
 \retval true    if we can continue with processing the body or doing ICAP.
 */
bool
HttpStateData::continueAfterParsingHeader()
{
    if (flags.handling1xx) {
        debugs(11, 5, HERE << "wait for 1xx handling");
        Must(!flags.headers_parsed);
        return false;
    }

    if (!flags.headers_parsed && !eof) {
        debugs(11, 9, HERE << "needs more at " << readBuf->contentSize());
        flags.do_next_read = true;
        /** \retval false If we have not finished parsing the headers and may get more data.
         *                Schedules more reads to retrieve the missing data.
         */
        maybeReadVirginBody(); // schedules all kinds of reads; TODO: rename
        return false;
    }

    /** If we are done with parsing, check for errors */

    err_type error = ERR_NONE;

    if (flags.headers_parsed) { // parsed headers, possibly with errors
        // check for header parsing errors
        if (HttpReply *vrep = virginReply()) {
            const http_status s = vrep->sline.status;
            const HttpVersion &v = vrep->sline.version;
            if (s == HTTP_INVALID_HEADER && v != HttpVersion(0,9)) {
                debugs(11, DBG_IMPORTANT, "WARNING: HTTP: Invalid Response: Bad header encountered from " << entry->url() << " AKA " << request->GetHost() << request->urlpath.termedBuf() );
                error = ERR_INVALID_RESP;
            } else if (s == HTTP_HEADER_TOO_LARGE) {
                fwd->dontRetry(true);
                error = ERR_TOO_BIG;
            } else {
                return true; // done parsing, got reply, and no error
            }
        } else {
            // parsed headers but got no reply
            debugs(11, DBG_IMPORTANT, "WARNING: HTTP: Invalid Response: No reply at all for " << entry->url() << " AKA " << request->GetHost() << request->urlpath.termedBuf() );
            error = ERR_INVALID_RESP;
        }
    } else {
        assert(eof);
        if (readBuf->hasContent()) {
            error = ERR_INVALID_RESP;
            debugs(11, DBG_IMPORTANT, "WARNING: HTTP: Invalid Response: Headers did not parse at all for " << entry->url() << " AKA " << request->GetHost() << request->urlpath.termedBuf() );
        } else {
            error = ERR_ZERO_SIZE_OBJECT;
            debugs(11, (request->flags.accelerated?DBG_IMPORTANT:2), "WARNING: HTTP: Invalid Response: No object data received for " <<
                   entry->url() << " AKA " << request->GetHost() << request->urlpath.termedBuf() );
        }
    }

    assert(error != ERR_NONE);
    entry->reset();
    fwd->fail(new ErrorState(error, HTTP_BAD_GATEWAY, fwd->request));
    flags.do_next_read = false;
    serverConnection->close();
    return false; // quit on error
}

/** truncate what we read if we read too much so that writeReplyBody()
    writes no more than what we should have read */
void
HttpStateData::truncateVirginBody()
{
    assert(flags.headers_parsed);

    HttpReply *vrep = virginReply();
    int64_t clen = -1;
    if (!vrep->expectingBody(request->method, clen) || clen < 0)
        return; // no body or a body of unknown size, including chunked

    const int64_t body_bytes_read = reply_bytes_read - header_bytes_read;
    if (body_bytes_read - body_bytes_truncated <= clen)
        return; // we did not read too much or already took care of the extras

    if (const int64_t extras = body_bytes_read - body_bytes_truncated - clen) {
        // server sent more that the advertised content length
        debugs(11,5, HERE << "body_bytes_read=" << body_bytes_read <<
               " clen=" << clen << '/' << vrep->content_length <<
               " body_bytes_truncated=" << body_bytes_truncated << '+' << extras);

        readBuf->truncate(extras);
        body_bytes_truncated += extras;
    }
}

/**
 * Call this when there is data from the origin server
 * which should be sent to either StoreEntry, or to ICAP...
 */
void
HttpStateData::writeReplyBody()
{
    truncateVirginBody(); // if needed
    const char *data = readBuf->content();
    int len = readBuf->contentSize();
    addVirginReplyBody(data, len);
    readBuf->consume(len);
}

bool
HttpStateData::decodeAndWriteReplyBody()
{
    const char *data = NULL;
    int len;
    bool wasThereAnException = false;
    assert(flags.chunked);
    assert(httpChunkDecoder);
    SQUID_ENTER_THROWING_CODE();
    MemBuf decodedData;
    decodedData.init();
    const bool doneParsing = httpChunkDecoder->parse(readBuf,&decodedData);
    len = decodedData.contentSize();
    data=decodedData.content();
    addVirginReplyBody(data, len);
    if (doneParsing) {
        lastChunk = 1;
        flags.do_next_read = false;
    }
    SQUID_EXIT_THROWING_CODE(wasThereAnException);
    return wasThereAnException;
}

/**
 * processReplyBody has two purposes:
 *  1 - take the reply body data, if any, and put it into either
 *      the StoreEntry, or give it over to ICAP.
 *  2 - see if we made it to the end of the response (persistent
 *      connections and such)
 */
void
HttpStateData::processReplyBody()
{
    Ip::Address client_addr;
    bool ispinned = false;

    if (!flags.headers_parsed) {
        flags.do_next_read = true;
        maybeReadVirginBody();
        return;
    }

#if USE_ADAPTATION
    debugs(11,5, HERE << "adaptationAccessCheckPending=" << adaptationAccessCheckPending);
    if (adaptationAccessCheckPending)
        return;

#endif

    /*
     * At this point the reply headers have been parsed and consumed.
     * That means header content has been removed from readBuf and
     * it contains only body data.
     */
    if (entry->isAccepting()) {
        if (flags.chunked) {
            if (!decodeAndWriteReplyBody()) {
                flags.do_next_read = false;
                serverComplete();
                return;
            }
        } else
            writeReplyBody();
    }

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        // The above writeReplyBody() call may have aborted the store entry.
        abortTransaction("store entry aborted while storing reply");
        return;
    } else
        switch (persistentConnStatus()) {
        case INCOMPLETE_MSG: {
            debugs(11, 5, "processReplyBody: INCOMPLETE_MSG from " << serverConnection);
            /* Wait for more data or EOF condition */
            AsyncCall::Pointer nil;
            if (flags.keepalive_broken) {
                commSetConnTimeout(serverConnection, 10, nil);
            } else {
                commSetConnTimeout(serverConnection, Config.Timeout.read, nil);
            }

            flags.do_next_read = true;
        }
        break;

        case COMPLETE_PERSISTENT_MSG:
            debugs(11, 5, "processReplyBody: COMPLETE_PERSISTENT_MSG from " << serverConnection);
            /* yes we have to clear all these! */
            commUnsetConnTimeout(serverConnection);
            flags.do_next_read = false;

            comm_remove_close_handler(serverConnection->fd, closeHandler);
            closeHandler = NULL;
            fwd->unregister(serverConnection);

            if (request->flags.spoofClientIp)
                client_addr = request->client_addr;

            if (request->flags.pinned) {
                ispinned = true;
            } else if (request->flags.connectionAuth && request->flags.authSent) {
                ispinned = true;
            }

            if (ispinned && request->clientConnectionManager.valid()) {
                request->clientConnectionManager->pinConnection(serverConnection, request, _peer,
                        (request->flags.connectionAuth != 0));
            } else {
                fwd->pconnPush(serverConnection, request->GetHost());
            }

            serverConnection = NULL;
            serverComplete();
            return;

        case COMPLETE_NONPERSISTENT_MSG:
            debugs(11, 5, "processReplyBody: COMPLETE_NONPERSISTENT_MSG from " << serverConnection);
            serverComplete();
            return;
        }

    maybeReadVirginBody();
}

void
HttpStateData::maybeReadVirginBody()
{
    // too late to read
    if (!Comm::IsConnOpen(serverConnection) || fd_table[serverConnection->fd].closing())
        return;

    // we may need to grow the buffer if headers do not fit
    const int minRead = flags.headers_parsed ? 0 :1024;
    const int read_size = replyBodySpace(*readBuf, minRead);

    debugs(11,9, HERE << (flags.do_next_read ? "may" : "wont") <<
           " read up to " << read_size << " bytes from " << serverConnection);

    /*
     * why <2? Because delayAwareRead() won't actually read if
     * you ask it to read 1 byte.  The delayed read request
     * just gets re-queued until the client side drains, then
     * the I/O thread hangs.  Better to not register any read
     * handler until we get a notification from someone that
     * its okay to read again.
     */
    if (read_size < 2)
        return;

    if (flags.do_next_read) {
        flags.do_next_read = false;
        typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
        entry->delayAwareRead(serverConnection, readBuf->space(read_size), read_size,
                              JobCallback(11, 5, Dialer, this,  HttpStateData::readReply));
    }
}

/// called after writing the very last request byte (body, last-chunk, etc)
void
HttpStateData::wroteLast(const CommIoCbParams &io)
{
    debugs(11, 5, HERE << serverConnection << ": size " << io.size << ": errflag " << io.flag << ".");
#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    if (io.size > 0) {
        fd_bytes(io.fd, io.size, FD_WRITE);
        kb_incr(&(statCounter.server.all.kbytes_out), io.size);
        kb_incr(&(statCounter.server.http.kbytes_out), io.size);
    }

    if (io.flag == COMM_ERR_CLOSING)
        return;

    if (io.flag) {
        ErrorState *err = new ErrorState(ERR_WRITE_ERROR, HTTP_BAD_GATEWAY, fwd->request);
        err->xerrno = io.xerrno;
        fwd->fail(err);
        serverConnection->close();
        return;
    }

    sendComplete();
}

/// successfully wrote the entire request (including body, last-chunk, etc.)
void
HttpStateData::sendComplete()
{
    /*
     * Set the read timeout here because it hasn't been set yet.
     * We only set the read timeout after the request has been
     * fully written to the server-side.  If we start the timeout
     * after connection establishment, then we are likely to hit
     * the timeout for POST/PUT requests that have very large
     * request bodies.
     */
    typedef CommCbMemFunT<HttpStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(11, 5,
                                      TimeoutDialer, this, HttpStateData::httpTimeout);

    commSetConnTimeout(serverConnection, Config.Timeout.read, timeoutCall);
    flags.request_sent = true;
    request->hier.peer_http_request_sent = current_time;
}

// Close the HTTP server connection. Used by serverComplete().
void
HttpStateData::closeServer()
{
    debugs(11,5, HERE << "closing HTTP server " << serverConnection << " this " << this);

    if (Comm::IsConnOpen(serverConnection)) {
        fwd->unregister(serverConnection);
        comm_remove_close_handler(serverConnection->fd, closeHandler);
        closeHandler = NULL;
        serverConnection->close();
    }
}

bool
HttpStateData::doneWithServer() const
{
    return !Comm::IsConnOpen(serverConnection);
}

/*
 * Fixup authentication request headers for special cases
 */
static void
httpFixupAuthentication(HttpRequest * request, const HttpHeader * hdr_in, HttpHeader * hdr_out, const HttpStateFlags &flags)
{
    http_hdr_type header = flags.originpeer ? HDR_AUTHORIZATION : HDR_PROXY_AUTHORIZATION;

    /* Nothing to do unless we are forwarding to a peer */
    if (!request->flags.proxying)
        return;

    /* Needs to be explicitly enabled */
    if (!request->peer_login)
        return;

    /* Maybe already dealt with? */
    if (hdr_out->has(header))
        return;

    /* Nothing to do here for PASSTHRU */
    if (strcmp(request->peer_login, "PASSTHRU") == 0)
        return;

    /* PROXYPASS is a special case, single-signon to servers with the proxy password (basic only) */
    if (flags.originpeer && strcmp(request->peer_login, "PROXYPASS") == 0 && hdr_in->has(HDR_PROXY_AUTHORIZATION)) {
        const char *auth = hdr_in->getStr(HDR_PROXY_AUTHORIZATION);

        if (auth && strncasecmp(auth, "basic ", 6) == 0) {
            hdr_out->putStr(header, auth);
            return;
        }
    }

    /* Special mode to pass the username to the upstream cache */
    if (*request->peer_login == '*') {
        char loginbuf[256];
        const char *username = "-";

        if (request->extacl_user.size())
            username = request->extacl_user.termedBuf();
#if USE_AUTH
        else if (request->auth_user_request != NULL)
            username = request->auth_user_request->username();
#endif

        snprintf(loginbuf, sizeof(loginbuf), "%s%s", username, request->peer_login + 1);

        httpHeaderPutStrf(hdr_out, header, "Basic %s",
                          old_base64_encode(loginbuf));
        return;
    }

    /* external_acl provided credentials */
    if (request->extacl_user.size() && request->extacl_passwd.size() &&
            (strcmp(request->peer_login, "PASS") == 0 ||
             strcmp(request->peer_login, "PROXYPASS") == 0)) {
        char loginbuf[256];
        snprintf(loginbuf, sizeof(loginbuf), SQUIDSTRINGPH ":" SQUIDSTRINGPH,
                 SQUIDSTRINGPRINT(request->extacl_user),
                 SQUIDSTRINGPRINT(request->extacl_passwd));
        httpHeaderPutStrf(hdr_out, header, "Basic %s",
                          old_base64_encode(loginbuf));
        return;
    }
    // if no external user credentials are available to fake authentication with PASS acts like PASSTHRU
    if (strcmp(request->peer_login, "PASS") == 0)
        return;

    /* Kerberos login to peer */
#if HAVE_AUTH_MODULE_NEGOTIATE && HAVE_KRB5 && HAVE_GSSAPI
    if (strncmp(request->peer_login, "NEGOTIATE",strlen("NEGOTIATE")) == 0) {
        char *Token=NULL;
        char *PrincipalName=NULL,*p;
        if ((p=strchr(request->peer_login,':')) != NULL ) {
            PrincipalName=++p;
        }
        Token = peer_proxy_negotiate_auth(PrincipalName, request->peer_host);
        if (Token) {
            httpHeaderPutStrf(hdr_out, header, "Negotiate %s",Token);
        }
        return;
    }
#endif /* HAVE_KRB5 && HAVE_GSSAPI */

    httpHeaderPutStrf(hdr_out, header, "Basic %s",
                      old_base64_encode(request->peer_login));
    return;
}

/*
 * build request headers and append them to a given MemBuf
 * used by buildRequestPrefix()
 * note: initialised the HttpHeader, the caller is responsible for Clean()-ing
 */
void
HttpStateData::httpBuildRequestHeader(HttpRequest * request,
                                      StoreEntry * entry,
                                      const AccessLogEntryPointer &al,
                                      HttpHeader * hdr_out,
                                      const HttpStateFlags &flags)
{
    /* building buffer for complex strings */
#define BBUF_SZ (MAX_URL+32)
    LOCAL_ARRAY(char, bbuf, BBUF_SZ);
    LOCAL_ARRAY(char, ntoabuf, MAX_IPSTRLEN);
    const HttpHeader *hdr_in = &request->header;
    const HttpHeaderEntry *e = NULL;
    HttpHeaderPos pos = HttpHeaderInitPos;
    assert (hdr_out->owner == hoRequest);

    /* append our IMS header */
    if (request->lastmod > -1)
        hdr_out->putTime(HDR_IF_MODIFIED_SINCE, request->lastmod);

    bool we_do_ranges = decideIfWeDoRanges (request);

    String strConnection (hdr_in->getList(HDR_CONNECTION));

    while ((e = hdr_in->getEntry(&pos)))
        copyOneHeaderFromClientsideRequestToUpstreamRequest(e, strConnection, request, hdr_out, we_do_ranges, flags);

    /* Abstraction break: We should interpret multipart/byterange responses
     * into offset-length data, and this works around our inability to do so.
     */
    if (!we_do_ranges && request->multipartRangeRequest()) {
        /* don't cache the result */
        request->flags.cachable = 0;
        /* pretend it's not a range request */
        delete request->range;
        request->range = NULL;
        request->flags.isRanged=false;
    }

    /* append Via */
    if (Config.onoff.via) {
        String strVia;
        strVia = hdr_in->getList(HDR_VIA);
        snprintf(bbuf, BBUF_SZ, "%d.%d %s",
                 request->http_ver.major,
                 request->http_ver.minor, ThisCache);
        strListAdd(&strVia, bbuf, ',');
        hdr_out->putStr(HDR_VIA, strVia.termedBuf());
        strVia.clean();
    }

    if (request->flags.accelerated) {
        /* Append Surrogate-Capabilities */
        String strSurrogate(hdr_in->getList(HDR_SURROGATE_CAPABILITY));
#if USE_SQUID_ESI
        snprintf(bbuf, BBUF_SZ, "%s=\"Surrogate/1.0 ESI/1.0\"", Config.Accel.surrogate_id);
#else
        snprintf(bbuf, BBUF_SZ, "%s=\"Surrogate/1.0\"", Config.Accel.surrogate_id);
#endif
        strListAdd(&strSurrogate, bbuf, ',');
        hdr_out->putStr(HDR_SURROGATE_CAPABILITY, strSurrogate.termedBuf());
    }

    /** \pre Handle X-Forwarded-For */
    if (strcmp(opt_forwarded_for, "delete") != 0) {

        String strFwd = hdr_in->getList(HDR_X_FORWARDED_FOR);

        if (strFwd.size() > 65536/2) {
            // There is probably a forwarding loop with Via detection disabled.
            // If we do nothing, String will assert on overflow soon.
            // TODO: Terminate all transactions with huge XFF?
            strFwd = "error";

            static int warnedCount = 0;
            if (warnedCount++ < 100) {
                const char *url = entry ? entry->url() : urlCanonical(request);
                debugs(11, DBG_IMPORTANT, "Warning: likely forwarding loop with " << url);
            }
        }

        if (strcmp(opt_forwarded_for, "on") == 0) {
            /** If set to ON - append client IP or 'unknown'. */
            if ( request->client_addr.IsNoAddr() )
                strListAdd(&strFwd, "unknown", ',');
            else
                strListAdd(&strFwd, request->client_addr.NtoA(ntoabuf, MAX_IPSTRLEN), ',');
        } else if (strcmp(opt_forwarded_for, "off") == 0) {
            /** If set to OFF - append 'unknown'. */
            strListAdd(&strFwd, "unknown", ',');
        } else if (strcmp(opt_forwarded_for, "transparent") == 0) {
            /** If set to TRANSPARENT - pass through unchanged. */
        } else if (strcmp(opt_forwarded_for, "truncate") == 0) {
            /** If set to TRUNCATE - drop existing list and replace with client IP or 'unknown'. */
            if ( request->client_addr.IsNoAddr() )
                strFwd = "unknown";
            else
                strFwd = request->client_addr.NtoA(ntoabuf, MAX_IPSTRLEN);
        }
        if (strFwd.size() > 0)
            hdr_out->putStr(HDR_X_FORWARDED_FOR, strFwd.termedBuf());
    }
    /** If set to DELETE - do not copy through. */

    /* append Host if not there already */
    if (!hdr_out->has(HDR_HOST)) {
        if (request->peer_domain) {
            hdr_out->putStr(HDR_HOST, request->peer_domain);
        } else if (request->port == urlDefaultPort(request->protocol)) {
            /* use port# only if not default */
            hdr_out->putStr(HDR_HOST, request->GetHost());
        } else {
            httpHeaderPutStrf(hdr_out, HDR_HOST, "%s:%d",
                              request->GetHost(),
                              (int) request->port);
        }
    }

    /* append Authorization if known in URL, not in header and going direct */
    if (!hdr_out->has(HDR_AUTHORIZATION)) {
        if (!request->flags.proxying && request->login && *request->login) {
            httpHeaderPutStrf(hdr_out, HDR_AUTHORIZATION, "Basic %s",
                              old_base64_encode(request->login));
        }
    }

    /* Fixup (Proxy-)Authorization special cases. Plain relaying dealt with above */
    httpFixupAuthentication(request, hdr_in, hdr_out, flags);

    /* append Cache-Control, add max-age if not there already */
    {
        HttpHdrCc *cc = hdr_in->getCc();

        if (!cc)
            cc = new HttpHdrCc();

#if 0 /* see bug 2330 */
        /* Set no-cache if determined needed but not found */
        if (request->flags.nocache)
            EBIT_SET(cc->mask, CC_NO_CACHE);
#endif

        /* Add max-age only without no-cache */
        if (!cc->hasMaxAge() && !cc->hasNoCache()) {
            const char *url =
                entry ? entry->url() : urlCanonical(request);
            cc->maxAge(getMaxAge(url));

        }

        /* Enforce sibling relations */
        if (flags.only_if_cached)
            cc->onlyIfCached(true);

        hdr_out->putCc(cc);

        delete cc;
    }

    /* maybe append Connection: keep-alive */
    if (flags.keepalive) {
        hdr_out->putStr(HDR_CONNECTION, "keep-alive");
    }

    /* append Front-End-Https */
    if (flags.front_end_https) {
        if (flags.front_end_https == 1 || request->protocol == AnyP::PROTO_HTTPS)
            hdr_out->putStr(HDR_FRONT_END_HTTPS, "On");
    }

    if (flags.chunked_request) {
        // Do not just copy the original value so that if the client-side
        // starts decode other encodings, this code may remain valid.
        hdr_out->putStr(HDR_TRANSFER_ENCODING, "chunked");
    }

    /* Now mangle the headers. */
    if (Config2.onoff.mangle_request_headers)
        httpHdrMangleList(hdr_out, request, ROR_REQUEST);

    if (Config.request_header_add && !Config.request_header_add->empty())
        httpHdrAdd(hdr_out, request, al, *Config.request_header_add);

    strConnection.clean();
}

/**
 * Decides whether a particular header may be cloned from the received Clients request
 * to our outgoing fetch request.
 */
void
copyOneHeaderFromClientsideRequestToUpstreamRequest(const HttpHeaderEntry *e, const String strConnection, const HttpRequest * request, HttpHeader * hdr_out, const int we_do_ranges, const HttpStateFlags &flags)
{
    debugs(11, 5, "httpBuildRequestHeader: " << e->name << ": " << e->value );

    switch (e->id) {

        /** \par RFC 2616 sect 13.5.1 - Hop-by-Hop headers which Squid should not pass on. */

    case HDR_PROXY_AUTHORIZATION:
        /** \par Proxy-Authorization:
         * Only pass on proxy authentication to peers for which
         * authentication forwarding is explicitly enabled
         */
        if (!flags.originpeer && flags.proxying && request->peer_login &&
                (strcmp(request->peer_login, "PASS") == 0 ||
                 strcmp(request->peer_login, "PROXYPASS") == 0 ||
                 strcmp(request->peer_login, "PASSTHRU") == 0)) {
            hdr_out->addEntry(e->clone());
        }
        break;

        /** \par RFC 2616 sect 13.5.1 - Hop-by-Hop headers which Squid does not pass on. */

    case HDR_CONNECTION:          /** \par Connection: */
    case HDR_TE:                  /** \par TE: */
    case HDR_KEEP_ALIVE:          /** \par Keep-Alive: */
    case HDR_PROXY_AUTHENTICATE:  /** \par Proxy-Authenticate: */
    case HDR_TRAILER:             /** \par Trailer: */
    case HDR_UPGRADE:             /** \par Upgrade: */
    case HDR_TRANSFER_ENCODING:   /** \par Transfer-Encoding: */
        break;

        /** \par OTHER headers I haven't bothered to track down yet. */

    case HDR_AUTHORIZATION:
        /** \par WWW-Authorization:
         * Pass on WWW authentication */

        if (!flags.originpeer) {
            hdr_out->addEntry(e->clone());
        } else {
            /** \note In accelerators, only forward authentication if enabled
             * (see also httpFixupAuthentication for special cases)
             */
            if (request->peer_login &&
                    (strcmp(request->peer_login, "PASS") == 0 ||
                     strcmp(request->peer_login, "PASSTHRU") == 0 ||
                     strcmp(request->peer_login, "PROXYPASS") == 0)) {
                hdr_out->addEntry(e->clone());
            }
        }

        break;

    case HDR_HOST:
        /** \par Host:
         * Normally Squid rewrites the Host: header.
         * However, there is one case when we don't: If the URL
         * went through our redirector and the admin configured
         * 'redir_rewrites_host' to be off.
         */
        if (request->peer_domain)
            hdr_out->putStr(HDR_HOST, request->peer_domain);
        else if (request->flags.redirected && !Config.onoff.redir_rewrites_host)
            hdr_out->addEntry(e->clone());
        else {
            /* use port# only if not default */

            if (request->port == urlDefaultPort(request->protocol)) {
                hdr_out->putStr(HDR_HOST, request->GetHost());
            } else {
                httpHeaderPutStrf(hdr_out, HDR_HOST, "%s:%d",
                                  request->GetHost(),
                                  (int) request->port);
            }
        }

        break;

    case HDR_IF_MODIFIED_SINCE:
        /** \par If-Modified-Since:
        * append unless we added our own;
         * \note at most one client's ims header can pass through */

        if (!hdr_out->has(HDR_IF_MODIFIED_SINCE))
            hdr_out->addEntry(e->clone());

        break;

    case HDR_MAX_FORWARDS:
        /** \par Max-Forwards:
         * pass only on TRACE or OPTIONS requests */
        if (request->method == METHOD_TRACE || request->method == METHOD_OPTIONS) {
            const int64_t hops = e->getInt64();

            if (hops > 0)
                hdr_out->putInt64(HDR_MAX_FORWARDS, hops - 1);
        }

        break;

    case HDR_VIA:
        /** \par Via:
         * If Via is disabled then forward any received header as-is.
         * Otherwise leave for explicit updated addition later. */

        if (!Config.onoff.via)
            hdr_out->addEntry(e->clone());

        break;

    case HDR_RANGE:

    case HDR_IF_RANGE:

    case HDR_REQUEST_RANGE:
        /** \par Range:, If-Range:, Request-Range:
         * Only pass if we accept ranges */
        if (!we_do_ranges)
            hdr_out->addEntry(e->clone());

        break;

    case HDR_PROXY_CONNECTION: // SHOULD ignore. But doing so breaks things.
        break;

    case HDR_CONTENT_LENGTH:
        // pass through unless we chunk; also, keeping this away from default
        // prevents request smuggling via Connection: Content-Length tricks
        if (!flags.chunked_request)
            hdr_out->addEntry(e->clone());
        break;

    case HDR_X_FORWARDED_FOR:

    case HDR_CACHE_CONTROL:
        /** \par X-Forwarded-For:, Cache-Control:
         * handled specially by Squid, so leave off for now.
         * append these after the loop if needed */
        break;

    case HDR_FRONT_END_HTTPS:
        /** \par Front-End-Https:
         * Pass thru only if peer is configured with front-end-https */
        if (!flags.front_end_https)
            hdr_out->addEntry(e->clone());

        break;

    default:
        /** \par default.
         * pass on all other header fields
         * which are NOT listed by the special Connection: header. */

        if (strConnection.size()>0 && strListIsMember(&strConnection, e->name.termedBuf(), ',')) {
            debugs(11, 2, "'" << e->name << "' header cropped by Connection: definition");
            return;
        }

        hdr_out->addEntry(e->clone());
    }
}

bool
HttpStateData::decideIfWeDoRanges (HttpRequest * request)
{
    bool result = true;
    /* decide if we want to do Ranges ourselves
     * and fetch the whole object now)
     * We want to handle Ranges ourselves iff
     *    - we can actually parse client Range specs
     *    - the specs are expected to be simple enough (e.g. no out-of-order ranges)
     *    - reply will be cachable
     * (If the reply will be uncachable we have to throw it away after
     *  serving this request, so it is better to forward ranges to
     *  the server and fetch only the requested content)
     */

    int64_t roffLimit = request->getRangeOffsetLimit();

    if (NULL == request->range || !request->flags.cachable
            || request->range->offsetLimitExceeded(roffLimit) || request->flags.connectionAuth)
        result = false;

    debugs(11, 8, "decideIfWeDoRanges: range specs: " <<
           request->range << ", cachable: " <<
           request->flags.cachable << "; we_do_ranges: " << result);

    return result;
}

/* build request prefix and append it to a given MemBuf;
 * return the length of the prefix */
mb_size_t
HttpStateData::buildRequestPrefix(MemBuf * mb)
{
    const int offset = mb->size;
    HttpVersion httpver(1,1);
    const char * url;
    if (_peer && !_peer->options.originserver)
        url = entry->url();
    else
        url = request->urlpath.termedBuf();
    mb->Printf("%s %s %s/%d.%d\r\n",
               RequestMethodStr(request->method),
               url && *url ? url : "/",
               AnyP::ProtocolType_str[httpver.protocol],
               httpver.major,httpver.minor);
    /* build and pack headers */
    {
        HttpHeader hdr(hoRequest);
        Packer p;
        httpBuildRequestHeader(request, entry, fwd->al, &hdr, flags);

        if (request->flags.pinned && request->flags.connectionAuth)
            request->flags.authSent = 1;
        else if (hdr.has(HDR_AUTHORIZATION))
            request->flags.authSent = 1;

        packerToMemInit(&p, mb);
        hdr.packInto(&p);
        hdr.clean();
        packerClean(&p);
    }
    /* append header terminator */
    mb->append(crlf, 2);
    return mb->size - offset;
}

/* This will be called when connect completes. Write request. */
bool
HttpStateData::sendRequest()
{
    MemBuf mb;

    debugs(11, 5, HERE << serverConnection << ", request " << request << ", this " << this << ".");

    if (!Comm::IsConnOpen(serverConnection)) {
        debugs(11,3, HERE << "cannot send request to closing " << serverConnection);
        assert(closeHandler != NULL);
        return false;
    }

    typedef CommCbMemFunT<HttpStateData, CommTimeoutCbParams> TimeoutDialer;
    AsyncCall::Pointer timeoutCall =  JobCallback(11, 5,
                                      TimeoutDialer, this, HttpStateData::httpTimeout);
    commSetConnTimeout(serverConnection, Config.Timeout.lifetime, timeoutCall);
    flags.do_next_read = true;
    maybeReadVirginBody();

    if (request->body_pipe != NULL) {
        if (!startRequestBodyFlow()) // register to receive body data
            return false;
        typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
        requestSender = JobCallback(11,5,
                                    Dialer, this, HttpStateData::sentRequestBody);

        Must(!flags.chunked_request);
        // use chunked encoding if we do not know the length
        if (request->content_length < 0)
            flags.chunked_request = true;
    } else {
        assert(!requestBodySource);
        typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
        requestSender = JobCallback(11,5,
                                    Dialer, this,  HttpStateData::wroteLast);
    }

    flags.originpeer = (_peer != NULL && _peer->options.originserver);
    flags.proxying = (_peer != NULL && !flags.originpeer);

    /*
     * Is keep-alive okay for all request methods?
     */
    if (request->flags.mustKeepalive)
        flags.keepalive = true;
    else if (request->flags.pinned)
        flags.keepalive = request->persistent();
    else if (!Config.onoff.server_pconns)
        flags.keepalive = false;
    else if (_peer == NULL)
        flags.keepalive = true;
    else if (_peer->stats.n_keepalives_sent < 10)
        flags.keepalive = true;
    else if ((double) _peer->stats.n_keepalives_recv /
             (double) _peer->stats.n_keepalives_sent > 0.50)
        flags.keepalive = true;

    if (_peer) {
        /*The old code here was
          if (neighborType(_peer, request) == PEER_SIBLING && ...
          which is equivalent to:
          if (neighborType(_peer, NULL) == PEER_SIBLING && ...
          or better:
          if (((_peer->type == PEER_MULTICAST && p->options.mcast_siblings) ||
                 _peer->type == PEER_SIBLINGS ) && _peer->options.allow_miss)
               flags.only_if_cached = 1;

           But I suppose it was a bug
         */
        if (neighborType(_peer, request) == PEER_SIBLING &&
                !_peer->options.allow_miss)
            flags.only_if_cached = true;

        flags.front_end_https = _peer->front_end_https;
    }

    mb.init();
    request->peer_host=_peer?_peer->host:NULL;
    buildRequestPrefix(&mb);

    debugs(11, 2, "HTTP Server " << serverConnection);
    debugs(11, 2, "HTTP Server REQUEST:\n---------\n" << mb.buf << "\n----------");

    Comm::Write(serverConnection, &mb, requestSender);
    return true;
}

bool
HttpStateData::getMoreRequestBody(MemBuf &buf)
{
    // parent's implementation can handle the no-encoding case
    if (!flags.chunked_request)
        return ServerStateData::getMoreRequestBody(buf);

    MemBuf raw;

    Must(requestBodySource != NULL);
    if (!requestBodySource->getMoreData(raw))
        return false; // no request body bytes to chunk yet

    // optimization: pre-allocate buffer size that should be enough
    const mb_size_t rawDataSize = raw.contentSize();
    // we may need to send: hex-chunk-size CRLF raw-data CRLF last-chunk
    buf.init(16 + 2 + rawDataSize + 2 + 5, raw.max_capacity);

    buf.Printf("%x\r\n", static_cast<unsigned int>(rawDataSize));
    buf.append(raw.content(), rawDataSize);
    buf.Printf("\r\n");

    Must(rawDataSize > 0); // we did not accidently created last-chunk above

    // Do not send last-chunk unless we successfully received everything
    if (receivedWholeRequestBody) {
        Must(!flags.sentLastChunk);
        flags.sentLastChunk = true;
        buf.append("0\r\n\r\n", 5);
    }

    return true;
}

void
httpStart(FwdState *fwd)
{
    debugs(11, 3, "httpStart: \"" << RequestMethodStr(fwd->request->method) << " " << fwd->entry->url() << "\"" );
    AsyncJob::Start(new HttpStateData(fwd));
}

void
HttpStateData::start()
{
    if (!sendRequest()) {
        debugs(11, 3, "httpStart: aborted");
        mustStop("HttpStateData::start failed");
        return;
    }

    ++ statCounter.server.all.requests;
    ++ statCounter.server.http.requests;

    /*
     * We used to set the read timeout here, but not any more.
     * Now its set in httpSendComplete() after the full request,
     * including request body, has been written to the server.
     */
}

/// if broken posts are enabled for the request, try to fix and return true
bool
HttpStateData::finishingBrokenPost()
{
#if USE_HTTP_VIOLATIONS
    if (!Config.accessList.brokenPosts) {
        debugs(11, 5, HERE << "No brokenPosts list");
        return false;
    }

    ACLFilledChecklist ch(Config.accessList.brokenPosts, originalRequest(), NULL);
    if (ch.fastCheck() != ACCESS_ALLOWED) {
        debugs(11, 5, HERE << "didn't match brokenPosts");
        return false;
    }

    if (!Comm::IsConnOpen(serverConnection)) {
        debugs(11, 3, HERE << "ignoring broken POST for closed " << serverConnection);
        assert(closeHandler != NULL);
        return true; // prevent caller from proceeding as if nothing happened
    }

    debugs(11, 3, "finishingBrokenPost: fixing broken POST");
    typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
    requestSender = JobCallback(11,5,
                                Dialer, this, HttpStateData::wroteLast);
    Comm::Write(serverConnection, "\r\n", 2, requestSender, NULL);
    return true;
#else
    return false;
#endif /* USE_HTTP_VIOLATIONS */
}

/// if needed, write last-chunk to end the request body and return true
bool
HttpStateData::finishingChunkedRequest()
{
    if (flags.sentLastChunk) {
        debugs(11, 5, HERE << "already sent last-chunk");
        return false;
    }

    Must(receivedWholeRequestBody); // or we should not be sending last-chunk
    flags.sentLastChunk = true;

    typedef CommCbMemFunT<HttpStateData, CommIoCbParams> Dialer;
    requestSender = JobCallback(11,5, Dialer, this, HttpStateData::wroteLast);
    Comm::Write(serverConnection, "0\r\n\r\n", 5, requestSender, NULL);
    return true;
}

void
HttpStateData::doneSendingRequestBody()
{
    ServerStateData::doneSendingRequestBody();
    debugs(11,5, HERE << serverConnection);

    // do we need to write something after the last body byte?
    if (flags.chunked_request && finishingChunkedRequest())
        return;
    if (!flags.chunked_request && finishingBrokenPost())
        return;

    sendComplete();
}

// more origin request body data is available
void
HttpStateData::handleMoreRequestBodyAvailable()
{
    if (eof || !Comm::IsConnOpen(serverConnection)) {
        // XXX: we should check this condition in other callbacks then!
        // TODO: Check whether this can actually happen: We should unsubscribe
        // as a body consumer when the above condition(s) are detected.
        debugs(11, DBG_IMPORTANT, HERE << "Transaction aborted while reading HTTP body");
        return;
    }

    assert(requestBodySource != NULL);

    if (requestBodySource->buf().hasContent()) {
        // XXX: why does not this trigger a debug message on every request?

        if (flags.headers_parsed && !flags.abuse_detected) {
            flags.abuse_detected = true;
            debugs(11, DBG_IMPORTANT, "http handleMoreRequestBodyAvailable: Likely proxy abuse detected '" << request->client_addr << "' -> '" << entry->url() << "'" );

            if (virginReply()->sline.status == HTTP_INVALID_HEADER) {
                serverConnection->close();
                return;
            }
        }
    }

    HttpStateData::handleMoreRequestBodyAvailable();
}

// premature end of the request body
void
HttpStateData::handleRequestBodyProducerAborted()
{
    ServerStateData::handleRequestBodyProducerAborted();
    if (entry->isEmpty()) {
        debugs(11, 3, "request body aborted: " << serverConnection);
        // We usually get here when ICAP REQMOD aborts during body processing.
        // We might also get here if client-side aborts, but then our response
        // should not matter because either client-side will provide its own or
        // there will be no response at all (e.g., if the the client has left).
        ErrorState *err = new ErrorState(ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR, fwd->request);
        err->detailError(ERR_DETAIL_SRV_REQMOD_REQ_BODY);
        fwd->fail(err);
    }

    abortTransaction("request body producer aborted");
}

// called when we wrote request headers(!) or a part of the body
void
HttpStateData::sentRequestBody(const CommIoCbParams &io)
{
    if (io.size > 0)
        kb_incr(&statCounter.server.http.kbytes_out, io.size);

    ServerStateData::sentRequestBody(io);
}

// Quickly abort the transaction
// TODO: destruction should be sufficient as the destructor should cleanup,
// including canceling close handlers
void
HttpStateData::abortTransaction(const char *reason)
{
    debugs(11,5, HERE << "aborting transaction for " << reason <<
           "; " << serverConnection << ", this " << this);

    if (Comm::IsConnOpen(serverConnection)) {
        serverConnection->close();
        return;
    }

    fwd->handleUnregisteredServerEnd();
    mustStop("HttpStateData::abortTransaction");
}
