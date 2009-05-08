
/*
 * $Id: http.cc,v 1.541 2007/11/18 22:00:58 hno Exp $
 *
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
 *
 */

/*
 * Anonymizing patch by lutz@as-node.jena.thur.de
 * have a look into http-anon.c to get more informations.
 */

#include "squid.h"
#include "errorpage.h"
#include "MemBuf.h"
#include "http.h"
#include "AuthUserRequest.h"
#include "Store.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemObject.h"
#include "HttpHdrContRange.h"
#include "HttpHdrSc.h"
#include "HttpHdrScTarget.h"
#include "ACLChecklist.h"
#include "fde.h"
#if DELAY_POOLS
#include "DelayPools.h"
#endif
#include "SquidTime.h"
#include "TextException.h"

#define SQUID_ENTER_THROWING_CODE() try {
#define SQUID_EXIT_THROWING_CODE(status) \
  	status = true; \
    } \
    catch (const TextException &e) { \
	debugs (11, 1, "Exception error:" << e.message); \
	status = false; \
    }  

CBDATA_CLASS_INIT(HttpStateData);

static const char *const crlf = "\r\n";

static PF httpStateFree;
static PF httpTimeout;
static void httpMaybeRemovePublic(StoreEntry *, http_status);
static void copyOneHeaderFromClientsideRequestToUpstreamRequest(const HttpHeaderEntry *e, String strConnection, HttpRequest * request, HttpRequest * orig_request,
        HttpHeader * hdr_out, int we_do_ranges, http_state_flags);

HttpStateData::HttpStateData(FwdState *theFwdState) : ServerStateData(theFwdState),
		       lastChunk(0), header_bytes_read(0), reply_bytes_read(0), httpChunkDecoder(NULL)
{
    debugs(11,5,HERE << "HttpStateData " << this << " created");
    ignoreCacheControl = false;
    surrogateNoStore = false;
    fd = fwd->server_fd;
    readBuf = new MemBuf;
    readBuf->init(4096, SQUID_TCP_SO_RCVBUF);
    orig_request = HTTPMSGLOCK(fwd->request);

    if (fwd->servers)
        _peer = fwd->servers->_peer;         /* might be NULL */

    if (_peer) {
        const char *url;

        if (_peer->options.originserver)
            url = orig_request->urlpath.buf();
        else
            url = entry->url();

        HttpRequest * proxy_req = new HttpRequest(orig_request->method,
                                  orig_request->protocol, url);

        xstrncpy(proxy_req->host, _peer->host, SQUIDHOSTNAMELEN);

        proxy_req->port = _peer->http_port;

        proxy_req->flags = orig_request->flags;

        proxy_req->lastmod = orig_request->lastmod;

        proxy_req->flags.proxying = 1;

        HTTPMSGUNLOCK(request);

        request = HTTPMSGLOCK(proxy_req);

        /*
         * This NEIGHBOR_PROXY_ONLY check probably shouldn't be here.
         * We might end up getting the object from somewhere else if,
         * for example, the request to this neighbor fails.
         */
        if (_peer->options.proxy_only)
            entry->releaseRequest();

#if DELAY_POOLS

        entry->setNoDelay(_peer->options.no_delay);

#endif
    }

    /*
     * register the handler to free HTTP state data when the FD closes
     */
    comm_add_close_handler(fd, httpStateFree, this);
}

HttpStateData::~HttpStateData()
{
    /*
     * don't forget that ~ServerStateData() gets called automatically
     */

    if (!readBuf->isNull())
        readBuf->clean();

    delete readBuf;

    if(httpChunkDecoder)
	delete httpChunkDecoder;

    HTTPMSGUNLOCK(orig_request);

    debugs(11,5, HERE << "HttpStateData " << this << " destroyed; FD " << fd);
}

int
HttpStateData::dataDescriptor() const
{
    return fd;
}

static void
httpStateFree(int fd, void *data)
{
    HttpStateData *httpState = static_cast<HttpStateData *>(data);
    debugs(11, 5, "httpStateFree: FD " << fd << ", httpState=" << data);
    delete httpState;
}

int
httpCachable(method_t method)
{
    /* GET and HEAD are cachable. Others are not. */

    if (method != METHOD_GET && method != METHOD_HEAD)
        return 0;

    /* else cachable */
    return 1;
}

static void
httpTimeout(int fd, void *data)
{
    HttpStateData *httpState = static_cast<HttpStateData *>(data);
    StoreEntry *entry = httpState->entry;
    debugs(11, 4, "httpTimeout: FD " << fd << ": '" << entry->url() << "'" );

    if (entry->store_status == STORE_PENDING) {
        httpState->fwd->fail(errorCon(ERR_READ_TIMEOUT, HTTP_GATEWAY_TIMEOUT, httpState->fwd->request));
    }

    comm_close(fd);
}

static void
httpMaybeRemovePublic(StoreEntry * e, http_status status)
{

    int remove
        = 0;

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

        remove
            = 1;

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
            remove
                = 1;

#endif

        break;
    }

    if (!remove
            && !forbidden)
        return;

    assert(e->mem_obj);

    if (e->mem_obj->request)
        pe = storeGetPublicByRequest(e->mem_obj->request);
    else
        pe = storeGetPublic(e->mem_obj->url, e->mem_obj->method);

    if (pe != NULL) {
        assert(e != pe);
        pe->release();
    }

    /*
     * Also remove any cached HEAD response in case the object has
     * changed.
     */
    if (e->mem_obj->request)
        pe = storeGetPublicByRequestMethod(e->mem_obj->request, METHOD_HEAD);
    else
        pe = storeGetPublic(e->mem_obj->url, METHOD_HEAD);

    if (pe != NULL) {
        assert(e != pe);
        pe->release();
    }

    if (forbidden)
        return;

    switch (e->mem_obj->method) {

    case METHOD_PUT:

    case METHOD_DELETE:

    case METHOD_PROPPATCH:

    case METHOD_MKCOL:

    case METHOD_MOVE:

    case METHOD_BMOVE:

    case METHOD_BDELETE:
        /*
         * Remove any cached GET object if it is beleived that the
         * object may have changed as a result of other methods
         */

        if (e->mem_obj->request)
            pe = storeGetPublicByRequestMethod(e->mem_obj->request, METHOD_GET);
        else
            pe = storeGetPublic(e->mem_obj->url, METHOD_GET);

        if (pe != NULL) {
            assert(e != pe);
            pe->release();
        }

        break;

    default:
        /* Keep GCC happy. The methods above are all mutating HTTP methods
         */
        break;
    }
}

void
HttpStateData::processSurrogateControl(HttpReply *reply)
{
#if USE_SQUID_ESI

    if (request->flags.accelerated && reply->surrogate_control) {
        HttpHdrScTarget *sctusable =
            httpHdrScGetMergedTarget(reply->surrogate_control,
                                     Config.Accel.surrogate_id);

        if (sctusable) {
            if (EBIT_TEST(sctusable->mask, SC_NO_STORE) ||
                    (Config.onoff.surrogate_is_remote
                     && EBIT_TEST(sctusable->mask, SC_NO_STORE_REMOTE))) {
                surrogateNoStore = true;
                entry->makePrivate();
            }

            /* The HttpHeader logic cannot tell if the header it's parsing is a reply to an
             * accelerated request or not...
             * Still, this is an abtraction breach. - RC
             */
            if (sctusable->max_age != -1) {
                if (sctusable->max_age < sctusable->max_stale)
                    reply->expires = reply->date + sctusable->max_age;
                else
                    reply->expires = reply->date + sctusable->max_stale;

                /* And update the timestamps */
                entry->timestampsSet();
            }

            /* We ignore cache-control directives as per the Surrogate specification */
            ignoreCacheControl = true;

            httpHdrScTargetDestroy(sctusable);
        }
    }

#endif
}

int
HttpStateData::cacheableReply()
{
    HttpReply const *rep = finalReply();
    HttpHeader const *hdr = &rep->header;
    const int cc_mask = (rep->cache_control) ? rep->cache_control->mask : 0;
    const char *v;
#if HTTP_VIOLATIONS

    const refresh_t *R = NULL;

    /* This strange looking define first looks up the refresh pattern
     * and then checks if the specified flag is set. The main purpose
     * of this is to simplify the refresh pattern lookup and HTTP_VIOLATIONS
     * condition
     */
#define REFRESH_OVERRIDE(flag) \
    ((R = (R ? R : refreshLimits(entry->mem_obj->url))) , \
    (R && R->flags.flag))
#else
#define REFRESH_OVERRIDE(flag) 0
#endif

    if (surrogateNoStore)
        return 0;

    if (!ignoreCacheControl) {
        if (EBIT_TEST(cc_mask, CC_PRIVATE)) {
            if (!REFRESH_OVERRIDE(ignore_private))
                return 0;
        }

        if (EBIT_TEST(cc_mask, CC_NO_CACHE)) {
            if (!REFRESH_OVERRIDE(ignore_no_cache))
                return 0;
        }

        if (EBIT_TEST(cc_mask, CC_NO_STORE)) {
            if (!REFRESH_OVERRIDE(ignore_no_store))
                return 0;
        }
    }

    if (request->flags.auth) {
        /*
         * Responses to requests with authorization may be cached
         * only if a Cache-Control: public reply header is present.
         * RFC 2068, sec 14.9.4
         */

        if (!EBIT_TEST(cc_mask, CC_PUBLIC)) {
            if (!REFRESH_OVERRIDE(ignore_auth))
                return 0;
        }
    }

    /* Pragma: no-cache in _replies_ is not documented in HTTP,
     * but servers like "Active Imaging Webcast/2.0" sure do use it */
    if (hdr->has(HDR_PRAGMA)) {
        String s = hdr->getList(HDR_PRAGMA);
        const int no_cache = strListIsMember(&s, "no-cache", ',');
        s.clean();

        if (no_cache) {
            if (!REFRESH_OVERRIDE(ignore_no_cache))
                return 0;
        }
    }

    /*
     * The "multipart/x-mixed-replace" content type is used for
     * continuous push replies.  These are generally dynamic and
     * probably should not be cachable
     */
    if ((v = hdr->getStr(HDR_CONTENT_TYPE)))
        if (!strncasecmp(v, "multipart/x-mixed-replace", 25))
            return 0;

    switch (rep->sline.status) {
        /* Responses that are cacheable */

    case HTTP_OK:

    case HTTP_NON_AUTHORITATIVE_INFORMATION:

    case HTTP_MULTIPLE_CHOICES:

    case HTTP_MOVED_PERMANENTLY:

    case HTTP_GONE:
        /*
         * Don't cache objects that need to be refreshed on next request,
         * unless we know how to refresh it.
         */

        if (!refreshIsCachable(entry)) {
            debugs(22, 3, "refreshIsCachable() returned non-cacheable..");
            return 0;
        }

        /* don't cache objects from peers w/o LMT, Date, or Expires */
        /* check that is it enough to check headers @?@ */
        if (rep->date > -1)
            return 1;
        else if (rep->last_modified > -1)
            return 1;
        else if (!_peer)
            return 1;

        /* @?@ (here and 302): invalid expires header compiles to squid_curtime */
        else if (rep->expires > -1)
            return 1;
        else
            return 0;

        /* NOTREACHED */
        break;

        /* Responses that only are cacheable if the server says so */

    case HTTP_MOVED_TEMPORARILY:
    case HTTP_TEMPORARY_REDIRECT:
        if (rep->expires > rep->date && rep->date > 0)
            return 1;
        else
            return 0;

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

        return 0;

    default:			/* Unknown status code */
        debugs (11, 0, HERE << "HttpStateData::cacheableReply: unexpected http status code " << rep->sline.status);

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
        value = hdr.buf();

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
        value = hdr.buf();

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

    debugs(11, 3, "httpMakeVaryMark: " << vstr.buf());
    return vstr.buf();
}

void
HttpStateData::keepaliveAccounting(HttpReply *reply)
{
    if (flags.keepalive)
        if (_peer)
            _peer->stats.n_keepalives_sent++;

    if (reply->keep_alive) {
        if (_peer)
            _peer->stats.n_keepalives_recv++;

        if (Config.onoff.detect_broken_server_pconns && reply->bodySize(request->method) == -1) {
            debugs(11, 1, "keepaliveAccounting: Impossible keep-alive header from '" << entry->url() << "'" );
            // debugs(11, 2, "GOT HTTP REPLY HDR:\n---------\n" << readBuf->content() << "\n----------" );
            flags.keepalive_broken = 1;
        }
    }
}

void
HttpStateData::checkDateSkew(HttpReply *reply)
{
    if (reply->date > -1 && !_peer) {
        int skew = abs((int)(reply->date - squid_curtime));

        if (skew > 86400)
            debugs(11, 3, "" << request->host << "'s clock is skewed by " << skew << " seconds!");
    }
}

/*
 * This creates the error page itself.. its likely
 * that the forward ported reply header max size patch
 * generates non http conformant error pages - in which
 * case the errors where should be 'BAD_GATEWAY' etc
 */
void
HttpStateData::processReplyHeader()
{
    /* Creates a blank header. If this routine is made incremental, this will
     * not do 
     */
    Ctx ctx = ctx_enter(entry->mem_obj->url);
    debugs(11, 3, "processReplyHeader: key '" << entry->getMD5Text() << "'");

    assert(!flags.headers_parsed);

    http_status error = HTTP_STATUS_NONE;

    HttpReply *newrep = new HttpReply;
    const bool parsed = newrep->parse(readBuf, eof, &error);

    if(!parsed && readBuf->contentSize() > 5 && strncmp(readBuf->content(), "HTTP/", 5) != 0){
	 MemBuf *mb;
	 HttpReply *tmprep = new HttpReply;
	 tmprep->sline.version = HttpVersion(1, 0);
	 tmprep->sline.status = HTTP_OK;
	 tmprep->header.putTime(HDR_DATE, squid_curtime);
	 tmprep->header.putExt("X-Transformed-From", "HTTP/0.9");
	 mb = tmprep->pack();
	 newrep->parse(mb, eof, &error);
	 delete tmprep;
    }
    else{
	 if (!parsed && error > 0) { // unrecoverable parsing error
	      debugs(11, 3, "processReplyHeader: Non-HTTP-compliant header: '" <<  readBuf->content() << "'");
	      flags.headers_parsed = 1;
          newrep->sline.version = HttpVersion(1, 0);
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
	 
	 debugs(11, 9, "GOT HTTP REPLY HDR:\n---------\n" << readBuf->content() << "\n----------");
	 
	 header_bytes_read = headersEnd(readBuf->content(), readBuf->contentSize());
	 readBuf->consume(header_bytes_read);
    }

    flags.chunked = 0;
    if (newrep->header.hasListMember(HDR_TRANSFER_ENCODING, "chunked", ',')) {
	 flags.chunked = 1;
	 httpChunkDecoder = new ChunkedCodingParser;
    }

    HttpReply *vrep = setVirginReply(newrep);
    flags.headers_parsed = 1;

    keepaliveAccounting(vrep);

    checkDateSkew(vrep);

    processSurrogateControl (vrep);

    /* TODO: IF the reply is a 1.0 reply, AND it has a Connection: Header
     * Parse the header and remove all referenced headers
     */

    ctx_exit(ctx);

}

// Called when we parsed (and possibly adapted) the headers but
// had not starting storing (a.k.a., sending) the body yet.
void
HttpStateData::haveParsedReplyHeaders()
{
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
        const char *vary = httpMakeVaryMark(orig_request, rep);

        if (!vary) {
            entry->makePrivate();
            goto no_cache;

        }

        entry->mem_obj->vary_headers = xstrdup(vary);
    }

#if WIP_FWD_LOG
    fwdStatus(fwd, s);

#endif
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

        if (Config.negativeTtl > 0)
            entry->cacheNegatively();
        else
            entry->makePrivate();

        break;

    default:
        assert(0);

        break;
    }

no_cache:

    if (!ignoreCacheControl && rep->cache_control) {
        if (EBIT_TEST(rep->cache_control->mask, CC_PROXY_REVALIDATE))
            EBIT_SET(entry->flags, ENTRY_REVALIDATE);
        else if (EBIT_TEST(rep->cache_control->mask, CC_MUST_REVALIDATE))
            EBIT_SET(entry->flags, ENTRY_REVALIDATE);
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
    /* If the reply wants to close the connection, it takes precedence */

    if (httpHeaderHasConnDir(&rep->header, "close"))
        return COMPLETE_NONPERSISTENT_MSG;

    /* If we didn't send a keep-alive request header, then this
     * can not be a persistent connection.
     */
    if (!flags.keepalive)
        return COMPLETE_NONPERSISTENT_MSG;

    /*
     * If we haven't sent the whole request then this can not be a persistent
     * connection.
     */
    if (!flags.request_sent) {
        debugs(11, 1, "statusIfComplete: Request not yet fully sent \"" << RequestMethodStr[orig_request->method] << " " << entry->url() << "\"" );
        return COMPLETE_NONPERSISTENT_MSG;
    }

    /*
     * What does the reply have to say about keep-alive?
     */
    /*
     * XXX BUG?
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
    debugs(11, 3, "persistentConnStatus: FD " << fd << " eof=" << eof);
    const HttpReply *vrep = virginReply();
    debugs(11, 5, "persistentConnStatus: content_length=" << vrep->content_length);

    /* If we haven't seen the end of reply headers, we are not done */
    debugs(11, 5, "persistentConnStatus: flags.headers_parsed=" << flags.headers_parsed);

    if (!flags.headers_parsed)
        return INCOMPLETE_MSG;

    if (eof) // already reached EOF
        return COMPLETE_NONPERSISTENT_MSG;

    /* In chunked responce we do not know the content length but we are absolutelly 
     * sure about the end of response, so we are calling the statusIfComplete to
     * decide if we can be persistant 
     */
    if (lastChunk && flags.chunked)
	return statusIfComplete();

    const int64_t clen = vrep->bodySize(request->method);

    debugs(11, 5, "persistentConnStatus: clen=" << clen);

    /* If the body size is unknown we must wait for EOF */
    if (clen < 0)
        return INCOMPLETE_MSG;

    /* If the body size is known, we must wait until we've gotten all of it. */
    if (clen > 0) {
        // old technique:
        // if (entry->mem_obj->endOffset() < vrep->content_length + vrep->hdr_sz)
        const int64_t body_bytes_read = reply_bytes_read - header_bytes_read;
        debugs(11,5, "persistentConnStatus: body_bytes_read=" <<
               body_bytes_read << " content_length=" << vrep->content_length);

        if (body_bytes_read < vrep->content_length)
            return INCOMPLETE_MSG;
    }

    /* If there is no message body or we got it all, we can be persistent */
    return statusIfComplete();
}

/*
 * This is the callback after some data has been read from the network
 */
void
HttpStateData::ReadReplyWrapper(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    HttpStateData *httpState = static_cast<HttpStateData *>(data);
    assert (fd == httpState->fd);
    // assert(buf == readBuf->content());
    PROF_start(HttpStateData_readReply);
    httpState->readReply (len, flag, xerrno);
    PROF_stop(HttpStateData_readReply);
}

/* XXX this function is too long! */
void
HttpStateData::readReply (size_t len, comm_err_t flag, int xerrno)
{
    int bin;
    int clen;
    flags.do_next_read = 0;

    debugs(11, 5, "httpReadReply: FD " << fd << ": len " << len << ".");

    // Bail out early on COMM_ERR_CLOSING - close handlers will tidy up for us
    if (flag == COMM_ERR_CLOSING) {
        debugs(11, 3, "http socket closing");
        return;
    }

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        maybeReadVirginBody();
        return;
    }

    // handle I/O errors
    if (flag != COMM_OK || len < 0) {
        debugs(11, 2, "httpReadReply: FD " << fd << ": read failure: " << xstrerror() << ".");

        if (ignoreErrno(xerrno)) {
            flags.do_next_read = 1;
        } else {
            ErrorState *err;
            err = errorCon(ERR_READ_ERROR, HTTP_BAD_GATEWAY, fwd->request);
            err->xerrno = xerrno;
            fwd->fail(err);
            flags.do_next_read = 0;
            comm_close(fd);
        }

        return;
    }

    // update I/O stats
    if (len > 0) {
        readBuf->appended(len);
        reply_bytes_read += len;
#if DELAY_POOLS

        DelayId delayId = entry->mem_obj->mostBytesAllowed();
        delayId.bytesIn(len);
#endif

        kb_incr(&statCounter.server.all.kbytes_in, len);
        kb_incr(&statCounter.server.http.kbytes_in, len);
        IOStats.Http.reads++;

        for (clen = len - 1, bin = 0; clen; bin++)
            clen >>= 1;

        IOStats.Http.read_hist[bin]++;
    }

    /* here the RFC says we should ignore whitespace between replies, but we can't as
     * doing so breaks HTTP/0.9 replies beginning with witespace, and in addition
     * the response splitting countermeasures is extremely likely to trigger on this,
     * not allowing connection reuse in the first place.
     */
#if DONT_DO_THIS
    if (!flags.headers_parsed && len > 0 && fd_table[fd].uses > 1) {
        /* Skip whitespace between replies */

        while (len > 0 && xisspace(*buf))
            xmemmove(buf, buf + 1, len--);

        if (len == 0) {
            /* Continue to read... */
            /* Timeout NOT increased. This whitespace was from previous reply */
            flags.do_next_read = 1;
            maybeReadVirginBody();
            return;
        }
    }

#endif

    if (len == 0) { // reached EOF?
        eof = 1;
        flags.do_next_read = 0;
    }

    if (!flags.headers_parsed) { // have not parsed headers yet?
        PROF_start(HttpStateData_processReplyHeader);
        processReplyHeader();
        PROF_stop(HttpStateData_processReplyHeader);

        if (!continueAfterParsingHeader()) // parsing error or need more data
            return; // TODO: send errors to ICAP

        adaptOrFinalizeReply();
    }

    // kick more reads if needed and/or process the response body, if any
    PROF_start(HttpStateData_processReplyBody);
    processReplyBody(); // may call serverComplete()
    PROF_stop(HttpStateData_processReplyBody);
}

// Checks whether we can continue with processing the body or doing ICAP.
// Returns false if we cannot (e.g., due to lack of headers or errors).
bool
HttpStateData::continueAfterParsingHeader()
{
    if (!flags.headers_parsed && !eof) { // need more and may get more
        debugs(11, 9, HERE << "needs more at " << readBuf->contentSize());
        flags.do_next_read = 1;
        maybeReadVirginBody(); // schedules all kinds of reads; TODO: rename
        return false; // wait for more data
    }

    /* we are done with parsing, now check for errors */

    err_type error = ERR_NONE;

    if (flags.headers_parsed) { // parsed headers, possibly with errors
        // check for header parsing errors
        if (HttpReply *vrep = virginReply()) {
            const http_status s = vrep->sline.status;
            const HttpVersion &v = vrep->sline.version;
            if (s == HTTP_INVALID_HEADER && v != HttpVersion(0,9)) {
                error = ERR_INVALID_RESP;
            } else
            if (s == HTTP_HEADER_TOO_LARGE) {
                fwd->dontRetry(true);
                error = ERR_TOO_BIG;
            } else {
                return true; // done parsing, got reply, and no error
            }
        } else {
            // parsed headers but got no reply
            error = ERR_INVALID_RESP;
        }
    } else {
        assert(eof);
        error = readBuf->hasContent() ?
            ERR_INVALID_RESP : ERR_ZERO_SIZE_OBJECT;
    }

    assert(error != ERR_NONE);
    entry->reset();
    fwd->fail(errorCon(error, HTTP_BAD_GATEWAY, fwd->request));
    flags.do_next_read = 0;
    comm_close(fd);
    return false; // quit on error
}

/*
 * Call this when there is data from the origin server
 * which should be sent to either StoreEntry, or to ICAP...
 */
void
HttpStateData::writeReplyBody()
{
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
    bool status = false;
    assert(flags.chunked);
    assert(httpChunkDecoder);
    SQUID_ENTER_THROWING_CODE();
    MemBuf decodedData;
    decodedData.init();
    const bool done = httpChunkDecoder->parse(readBuf,&decodedData);
    len = decodedData.contentSize();
    data=decodedData.content();
    addVirginReplyBody(data, len);
    if (done) {
        lastChunk = 1;
        flags.do_next_read = 0;
    }
    SQUID_EXIT_THROWING_CODE(status);
    return status;
}

/*
 * processReplyBody has two purposes:
 *  1 - take the reply body data, if any, and put it into either
 *      the StoreEntry, or give it over to ICAP.
 *  2 - see if we made it to the end of the response (persistent
 *      connections and such)
 */
void
HttpStateData::processReplyBody()
{

    struct IN_ADDR *client_addr = NULL;

    if (!flags.headers_parsed) {
        flags.do_next_read = 1;
        maybeReadVirginBody();
        return;
    }

#if ICAP_CLIENT
    if (icapAccessCheckPending)
        return;

#endif

    /*
     * At this point the reply headers have been parsed and consumed.
     * That means header content has been removed from readBuf and
     * it contains only body data.
     */
    if(flags.chunked){
	if(!decodeAndWriteReplyBody()){
	    flags.do_next_read = 0;
	    serverComplete();
	    return;
	}
    }
    else
	writeReplyBody();

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        /*
         * the above writeReplyBody() call could ABORT this entry,
         * in that case, the server FD should already be closed.
         * there's nothing for us to do.
         */
        (void) 0;
    } else
        switch (persistentConnStatus()) {

        case INCOMPLETE_MSG:
            debugs(11, 5, "processReplyBody: INCOMPLETE_MSG");
            /* Wait for more data or EOF condition */

            if (flags.keepalive_broken) {
                commSetTimeout(fd, 10, NULL, NULL);
            } else {
                commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
            }

            flags.do_next_read = 1;
            break;

        case COMPLETE_PERSISTENT_MSG:
            debugs(11, 5, "processReplyBody: COMPLETE_PERSISTENT_MSG");
            /* yes we have to clear all these! */
            commSetTimeout(fd, -1, NULL, NULL);
            flags.do_next_read = 0;

            comm_remove_close_handler(fd, httpStateFree, this);
            fwd->unregister(fd);

#if LINUX_TPROXY

            if (orig_request->flags.tproxy)
                client_addr = &orig_request->client_addr;

#endif

            fwd->pconnPush(fd, _peer, request, orig_request->host, client_addr);

            fd = -1;

            serverComplete();
            return;

        case COMPLETE_NONPERSISTENT_MSG:
            debugs(11, 5, "processReplyBody: COMPLETE_NONPERSISTENT_MSG");
            serverComplete();
            return;
        }

    maybeReadVirginBody();
}

void
HttpStateData::maybeReadVirginBody()
{
    int read_sz = replyBodySpace(readBuf->spaceSize());

    debugs(11,9, HERE << (flags.do_next_read ? "may" : "wont") <<
           " read up to " << read_sz << " bytes from FD " << fd);

    /*
     * why <2? Because delayAwareRead() won't actually read if
     * you ask it to read 1 byte.  The delayed read request
     * just gets re-queued until the client side drains, then
     * the I/O thread hangs.  Better to not register any read
     * handler until we get a notification from someone that
     * its okay to read again.
     */
    if (read_sz < 2) {
	if (flags.headers_parsed)
	    return;
	else
	    read_sz = 1024;
    }

    if (flags.do_next_read) {
	flags.do_next_read = 0;
	entry->delayAwareRead(fd, readBuf->space(read_sz), read_sz, ReadReplyWrapper, this);
    }
}

/*
 * This will be called when request write is complete.
 */
void
HttpStateData::SendComplete(int fd, char *bufnotused, size_t size, comm_err_t errflag, int xerrno, void *data)
{
    HttpStateData *httpState = static_cast<HttpStateData *>(data);
    debugs(11, 5, "httpSendComplete: FD " << fd << ": size " << size << ": errflag " << errflag << ".");
#if URL_CHECKSUM_DEBUG

    entry->mem_obj->checkUrlChecksum();
#endif

    if (size > 0) {
        fd_bytes(fd, size, FD_WRITE);
        kb_incr(&statCounter.server.all.kbytes_out, size);
        kb_incr(&statCounter.server.http.kbytes_out, size);
    }

    if (errflag == COMM_ERR_CLOSING)
        return;

    if (errflag) {
        ErrorState *err;
        err = errorCon(ERR_WRITE_ERROR, HTTP_BAD_GATEWAY, httpState->fwd->request);
        err->xerrno = xerrno;
        httpState->fwd->fail(err);
        comm_close(fd);
        return;
    }

    /*
     * Set the read timeout here because it hasn't been set yet.
     * We only set the read timeout after the request has been
     * fully written to the server-side.  If we start the timeout
     * after connection establishment, then we are likely to hit
     * the timeout for POST/PUT requests that have very large
     * request bodies.
     */
    commSetTimeout(fd, Config.Timeout.read, httpTimeout, httpState);

    httpState->flags.request_sent = 1;
}

// Close the HTTP server connection. Used by serverComplete().
void
HttpStateData::closeServer()
{
    debugs(11,5, HERE << "closing HTTP server FD " << fd << " this " << this);

    if (fd >= 0) {
        fwd->unregister(fd);
        comm_remove_close_handler(fd, httpStateFree, this);
        comm_close(fd);
        fd = -1;
    }
}

bool
HttpStateData::doneWithServer() const
{
    return fd < 0;
}

/*
 * build request headers and append them to a given MemBuf 
 * used by buildRequestPrefix()
 * note: initialised the HttpHeader, the caller is responsible for Clean()-ing
 */
void
HttpStateData::httpBuildRequestHeader(HttpRequest * request,
                                      HttpRequest * orig_request,
                                      StoreEntry * entry,
                                      HttpHeader * hdr_out,
                                      http_state_flags flags)
{
    /* building buffer for complex strings */
#define BBUF_SZ (MAX_URL+32)
    LOCAL_ARRAY(char, bbuf, BBUF_SZ);
    const HttpHeader *hdr_in = &orig_request->header;
    const HttpHeaderEntry *e;
    String strFwd;
    HttpHeaderPos pos = HttpHeaderInitPos;
    assert (hdr_out->owner == hoRequest);
    /* append our IMS header */

    if (request->lastmod > -1)
        hdr_out->putTime(HDR_IF_MODIFIED_SINCE, request->lastmod);

    bool we_do_ranges = decideIfWeDoRanges (orig_request);

    String strConnection (hdr_in->getList(HDR_CONNECTION));

    while ((e = hdr_in->getEntry(&pos)))
        copyOneHeaderFromClientsideRequestToUpstreamRequest(e, strConnection, request, orig_request, hdr_out, we_do_ranges, flags);

    /* Abstraction break: We should interpret multipart/byterange responses
     * into offset-length data, and this works around our inability to do so.
     */
    if (!we_do_ranges && orig_request->multipartRangeRequest()) {
        /* don't cache the result */
        orig_request->flags.cachable = 0;
        /* pretend it's not a range request */
        delete orig_request->range;
        orig_request->range = NULL;
        orig_request->flags.range = 0;
    }

    /* append Via */
    if (Config.onoff.via) {
        String strVia;
        strVia = hdr_in->getList(HDR_VIA);
        snprintf(bbuf, BBUF_SZ, "%d.%d %s",
                 orig_request->http_ver.major,
                 orig_request->http_ver.minor, ThisCache);
        strListAdd(&strVia, bbuf, ',');
        hdr_out->putStr(HDR_VIA, strVia.buf());
        strVia.clean();
    }

#if USE_SQUID_ESI
    {
        /* Append Surrogate-Capabilities */
        String strSurrogate (hdr_in->getList(HDR_SURROGATE_CAPABILITY));
        snprintf(bbuf, BBUF_SZ, "%s=\"Surrogate/1.0 ESI/1.0\"",
                 Config.Accel.surrogate_id);
        strListAdd(&strSurrogate, bbuf, ',');
        hdr_out->putStr(HDR_SURROGATE_CAPABILITY, strSurrogate.buf());
    }
#endif

    /* append X-Forwarded-For */
    strFwd = hdr_in->getList(HDR_X_FORWARDED_FOR);

    if (opt_forwarded_for && orig_request->client_addr.s_addr != no_addr.s_addr)
        strListAdd(&strFwd, inet_ntoa(orig_request->client_addr), ',');
    else
        strListAdd(&strFwd, "unknown", ',');

    hdr_out->putStr(HDR_X_FORWARDED_FOR, strFwd.buf());

    strFwd.clean();

    /* append Host if not there already */
    if (!hdr_out->has(HDR_HOST)) {
        if (orig_request->peer_domain) {
            hdr_out->putStr(HDR_HOST, orig_request->peer_domain);
        } else if (orig_request->port == urlDefaultPort(orig_request->protocol)) {
            /* use port# only if not default */
            hdr_out->putStr(HDR_HOST, orig_request->host);
        } else {
            httpHeaderPutStrf(hdr_out, HDR_HOST, "%s:%d",
                              orig_request->host, (int) orig_request->port);
        }
    }

    /* append Authorization if known in URL, not in header and going direct */
    if (!hdr_out->has(HDR_AUTHORIZATION)) {
        if (!request->flags.proxying && *request->login) {
            httpHeaderPutStrf(hdr_out, HDR_AUTHORIZATION, "Basic %s",
                              base64_encode(request->login));
        }
    }

    /* append Proxy-Authorization if configured for peer, and proxying */
    if (request->flags.proxying && orig_request->peer_login &&
            !hdr_out->has(HDR_PROXY_AUTHORIZATION)) {
        if (*orig_request->peer_login == '*') {
            /* Special mode, to pass the username to the upstream cache */
            char loginbuf[256];
            const char *username = "-";

            if (orig_request->extacl_user.size())
                username = orig_request->extacl_user.buf();
            else if (orig_request->auth_user_request)
                username = orig_request->auth_user_request->username();

            snprintf(loginbuf, sizeof(loginbuf), "%s%s", username, orig_request->peer_login + 1);

            httpHeaderPutStrf(hdr_out, HDR_PROXY_AUTHORIZATION, "Basic %s",
                              base64_encode(loginbuf));
        } else if (strcmp(orig_request->peer_login, "PASS") == 0) {
            if (orig_request->extacl_user.size() && orig_request->extacl_passwd.size()) {
                char loginbuf[256];
                snprintf(loginbuf, sizeof(loginbuf), "%s:%s", orig_request->extacl_user.buf(), orig_request->extacl_passwd.buf());
                httpHeaderPutStrf(hdr_out, HDR_PROXY_AUTHORIZATION, "Basic %s",
                                  base64_encode(loginbuf));
            }
        } else if (strcmp(orig_request->peer_login, "PROXYPASS") == 0) {
            /* Nothing to do */
        } else {
            httpHeaderPutStrf(hdr_out, HDR_PROXY_AUTHORIZATION, "Basic %s",
                              base64_encode(orig_request->peer_login));
        }
    }

    /* append WWW-Authorization if configured for peer */
    if (flags.originpeer && orig_request->peer_login &&
            !hdr_out->has(HDR_AUTHORIZATION)) {
        if (strcmp(orig_request->peer_login, "PASS") == 0) {
            /* No credentials to forward.. (should have been done above if available) */
        } else if (strcmp(orig_request->peer_login, "PROXYPASS") == 0) {
            /* Special mode, convert proxy authentication to WWW authentication
            * (also applies to authentication provided by external acl)
             */
            const char *auth = hdr_in->getStr(HDR_PROXY_AUTHORIZATION);

            if (auth && strncasecmp(auth, "basic ", 6) == 0) {
                hdr_out->putStr(HDR_AUTHORIZATION, auth);
            } else if (orig_request->extacl_user.size() && orig_request->extacl_passwd.size()) {
                char loginbuf[256];
                snprintf(loginbuf, sizeof(loginbuf), "%s:%s", orig_request->extacl_user.buf(), orig_request->extacl_passwd.buf());
                httpHeaderPutStrf(hdr_out, HDR_AUTHORIZATION, "Basic %s",
                                  base64_encode(loginbuf));
            }
        } else if (*orig_request->peer_login == '*') {
            /* Special mode, to pass the username to the upstream cache */
            char loginbuf[256];
            const char *username = "-";

            if (orig_request->auth_user_request)
                username = orig_request->auth_user_request->username();
            else if (orig_request->extacl_user.size())
                username = orig_request->extacl_user.buf();

            snprintf(loginbuf, sizeof(loginbuf), "%s%s", username, orig_request->peer_login + 1);

            httpHeaderPutStrf(hdr_out, HDR_AUTHORIZATION, "Basic %s",
                              base64_encode(loginbuf));
        } else {
            /* Fixed login string */
            httpHeaderPutStrf(hdr_out, HDR_AUTHORIZATION, "Basic %s",
                              base64_encode(orig_request->peer_login));
        }
    }

    /* append Cache-Control, add max-age if not there already */ {
        HttpHdrCc *cc = hdr_in->getCc();

        if (!cc)
            cc = httpHdrCcCreate();

        if (!EBIT_TEST(cc->mask, CC_MAX_AGE)) {
            const char *url =
                entry ? entry->url() : urlCanonical(orig_request);
            httpHdrCcSetMaxAge(cc, getMaxAge(url));

            if (request->urlpath.size())
                assert(strstr(url, request->urlpath.buf()));
        }

        /* Set no-cache if determined needed but not found */
        if (orig_request->flags.nocache && !hdr_in->has(HDR_PRAGMA))
            EBIT_SET(cc->mask, CC_NO_CACHE);

        /* Enforce sibling relations */
        if (flags.only_if_cached)
            EBIT_SET(cc->mask, CC_ONLY_IF_CACHED);

        hdr_out->putCc(cc);

        httpHdrCcDestroy(cc);
    }

    /* maybe append Connection: keep-alive */
    if (flags.keepalive) {
        if (flags.proxying) {
            hdr_out->putStr(HDR_PROXY_CONNECTION, "keep-alive");
        } else {
            hdr_out->putStr(HDR_CONNECTION, "keep-alive");
        }
    }

    /* append Front-End-Https */
    if (flags.front_end_https) {
        if (flags.front_end_https == 1 || request->protocol == PROTO_HTTPS)
            hdr_out->putStr(HDR_FRONT_END_HTTPS, "On");
    }

    /* Now mangle the headers. */
    if (Config2.onoff.mangle_request_headers)
        httpHdrMangleList(hdr_out, request, ROR_REQUEST);

    strConnection.clean();
}

void
copyOneHeaderFromClientsideRequestToUpstreamRequest(const HttpHeaderEntry *e, String strConnection, HttpRequest * request, HttpRequest * orig_request, HttpHeader * hdr_out, int we_do_ranges, http_state_flags flags)
{
    debugs(11, 5, "httpBuildRequestHeader: " << e->name.buf() << ": " << e->value.buf());

    if (!httpRequestHdrAllowed(e, &strConnection)) {
        debugs(11, 2, "'" << e->name.buf() << "' header denied by anonymize_headers configuration");
        return;
    }

    switch (e->id) {

    case HDR_PROXY_AUTHORIZATION:
        /* Only pass on proxy authentication to peers for which
         * authentication forwarding is explicitly enabled
         */

        if (flags.proxying && orig_request->peer_login &&
                (strcmp(orig_request->peer_login, "PASS") == 0 ||
                 strcmp(orig_request->peer_login, "PROXYPASS") == 0)) {
            hdr_out->addEntry(e->clone());
        }

        break;

    case HDR_AUTHORIZATION:
        /* Pass on WWW authentication */

        if (!flags.originpeer) {
            hdr_out->addEntry(e->clone());
        } else {
            /* In accelerators, only forward authentication if enabled
             * (see also below for proxy->server authentication)
             */

            if (orig_request->peer_login &&
                    (strcmp(orig_request->peer_login, "PASS") == 0 ||
                     strcmp(orig_request->peer_login, "PROXYPASS") == 0)) {
                hdr_out->addEntry(e->clone());
            }
        }

        break;

    case HDR_HOST:
        /*
         * Normally Squid rewrites the Host: header.
         * However, there is one case when we don't: If the URL
         * went through our redirector and the admin configured
         * 'redir_rewrites_host' to be off.
         */
	if (orig_request->peer_domain)
            hdr_out->putStr(HDR_HOST, orig_request->peer_domain);
        else if (request->flags.redirected && !Config.onoff.redir_rewrites_host)
            hdr_out->addEntry(e->clone());
        else {
            /* use port# only if not default */

            if (orig_request->port == urlDefaultPort(orig_request->protocol)) {
                hdr_out->putStr(HDR_HOST, orig_request->host);
            } else {
                httpHeaderPutStrf(hdr_out, HDR_HOST, "%s:%d",
                                  orig_request->host, (int) orig_request->port);
            }
        }

        break;

    case HDR_IF_MODIFIED_SINCE:
        /* append unless we added our own;
         * note: at most one client's ims header can pass through */

        if (!hdr_out->has(HDR_IF_MODIFIED_SINCE))
            hdr_out->addEntry(e->clone());

        break;

    case HDR_MAX_FORWARDS:
        /* pass only on TRACE or OPTIONS requests */
        if (orig_request->method == METHOD_TRACE || orig_request->method == METHOD_OPTIONS) {
            const int64_t hops = e->getInt64();

            if (hops > 0)
                hdr_out->putInt64(HDR_MAX_FORWARDS, hops - 1);
        }

        break;

    case HDR_VIA:
        /* If Via is disabled then forward any received header as-is */

        if (!Config.onoff.via)
            hdr_out->addEntry(e->clone());

        break;

    case HDR_RANGE:

    case HDR_IF_RANGE:

    case HDR_REQUEST_RANGE:
        if (!we_do_ranges)
            hdr_out->addEntry(e->clone());

        break;

    case HDR_PROXY_CONNECTION:

    case HDR_CONNECTION:

    case HDR_X_FORWARDED_FOR:

    case HDR_CACHE_CONTROL:
        /* append these after the loop if needed */
        break;

    case HDR_FRONT_END_HTTPS:
        if (!flags.front_end_https)
            hdr_out->addEntry(e->clone());

        break;

    default:
        /* pass on all other header fields */
        hdr_out->addEntry(e->clone());
    }
}

bool
HttpStateData::decideIfWeDoRanges (HttpRequest * orig_request)
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

    if (NULL == orig_request->range || !orig_request->flags.cachable
            || orig_request->range->offsetLimitExceeded())
        result = false;

        debugs(11, 8, "decideIfWeDoRanges: range specs: " <<
               orig_request->range << ", cachable: " <<
               orig_request->flags.cachable << "; we_do_ranges: " << result);

    return result;
}

/* build request prefix and append it to a given MemBuf;
 * return the length of the prefix */
mb_size_t
HttpStateData::buildRequestPrefix(HttpRequest * request,
                                  HttpRequest * orig_request,
                                  StoreEntry * entry,
                                  MemBuf * mb,
                                  http_state_flags flags)
{
    const int offset = mb->size;
    HttpVersion httpver(1, 0);
    mb->Printf("%s %s HTTP/%d.%d\r\n",
               RequestMethodStr[request->method],
               request->urlpath.size() ? request->urlpath.buf() : "/",
               httpver.major,httpver.minor);
    /* build and pack headers */
    {
        HttpHeader hdr(hoRequest);
        Packer p;
        httpBuildRequestHeader(request, orig_request, entry, &hdr, flags);
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

    debugs(11, 5, "httpSendRequest: FD " << fd << ", request " << request << ", this " << this << ".");

    commSetTimeout(fd, Config.Timeout.lifetime, httpTimeout, this);
    flags.do_next_read = 1;
    maybeReadVirginBody();

    if (orig_request->body_pipe != NULL) {
        if (!startRequestBodyFlow()) // register to receive body data
            return false;
        requestSender = HttpStateData::sentRequestBodyWrapper;
    } else {
        assert(!requestBodySource);
        requestSender = HttpStateData::SendComplete;
    }

    if (_peer != NULL) {
        if (_peer->options.originserver) {
            flags.proxying = 0;
            flags.originpeer = 1;
        } else {
            flags.proxying = 1;
            flags.originpeer = 0;
        }
    } else {
        flags.proxying = 0;
        flags.originpeer = 0;
    }

    /*
     * Is keep-alive okay for all request methods?
     */
    if (!Config.onoff.server_pconns)
        flags.keepalive = 0;
    else if (_peer == NULL)
        flags.keepalive = 1;
    else if (_peer->stats.n_keepalives_sent < 10)
        flags.keepalive = 1;
    else if ((double) _peer->stats.n_keepalives_recv /
             (double) _peer->stats.n_keepalives_sent > 0.50)
        flags.keepalive = 1;

    if (_peer) {
        if (neighborType(_peer, request) == PEER_SIBLING &&
                !_peer->options.allow_miss)
            flags.only_if_cached = 1;

        flags.front_end_https = _peer->front_end_https;
    }

    mb.init();
    buildRequestPrefix(request, orig_request, entry, &mb, flags);
    debugs(11, 6, "httpSendRequest: FD " << fd << ":\n" << mb.buf);
    comm_write_mbuf(fd, &mb, requestSender, this);

    return true;
}

void
httpStart(FwdState *fwd)
{
    debugs(11, 3, "httpStart: \"" << RequestMethodStr[fwd->request->method] << " " << fwd->entry->url() << "\"" );
    HttpStateData *httpState = new HttpStateData(fwd);

    if (!httpState->sendRequest()) {
        debugs(11, 3, "httpStart: aborted");
        delete httpState;
        return;
    }

    statCounter.server.all.requests++;
    statCounter.server.http.requests++;

    /*
     * We used to set the read timeout here, but not any more.
     * Now its set in httpSendComplete() after the full request,
     * including request body, has been written to the server.
     */
}

void
HttpStateData::doneSendingRequestBody()
{
    ACLChecklist ch;
    debugs(11,5, HERE << "doneSendingRequestBody: FD " << fd);
    ch.request = HTTPMSGLOCK(request);

    if (Config.accessList.brokenPosts)
        ch.accessList = cbdataReference(Config.accessList.brokenPosts);

    /* cbdataReferenceDone() happens in either fastCheck() or ~ACLCheckList */

    if (!Config.accessList.brokenPosts) {
        debugs(11, 5, "doneSendingRequestBody: No brokenPosts list");
        HttpStateData::SendComplete(fd, NULL, 0, COMM_OK, 0, this);
    } else if (!ch.fastCheck()) {
        debugs(11, 5, "doneSendingRequestBody: didn't match brokenPosts");
        HttpStateData::SendComplete(fd, NULL, 0, COMM_OK, 0, this);
    } else {
        debugs(11, 2, "doneSendingRequestBody: matched brokenPosts");
        comm_write(fd, "\r\n", 2, HttpStateData::SendComplete, this, NULL);
    }
}

// more origin request body data is available
void
HttpStateData::handleMoreRequestBodyAvailable()
{
    if (eof || fd < 0) {
        // XXX: we should check this condition in other callbacks then!
        // TODO: Check whether this can actually happen: We should unsubscribe
        // as a body consumer when the above condition(s) are detected.
        debugs(11, 1, HERE << "Transaction aborted while reading HTTP body");
        return;
    }

    assert(requestBodySource != NULL);

    if (requestBodySource->buf().hasContent()) {
        // XXX: why does not this trigger a debug message on every request?

        if (flags.headers_parsed && !flags.abuse_detected) {
            flags.abuse_detected = 1;
            debugs(11, 1, "http handleMoreRequestBodyAvailable: Likely proxy abuse detected '" << inet_ntoa(orig_request->client_addr) << "' -> '" << entry->url() << "'" );

            if (virginReply()->sline.status == HTTP_INVALID_HEADER) {
                comm_close(fd);
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
    // XXX: SendComplete(COMM_ERR_CLOSING) does little. Is it enough?
    SendComplete(fd, NULL, 0, COMM_ERR_CLOSING, 0, this);
}

// called when we wrote request headers(!) or a part of the body
void
HttpStateData::sentRequestBody(int fd, size_t size, comm_err_t errflag)
{
    if (size > 0)
        kb_incr(&statCounter.server.http.kbytes_out, size);

    ServerStateData::sentRequestBody(fd, size, errflag);
}

// Quickly abort the transaction
// TODO: destruction should be sufficient as the destructor should cleanup,
// including canceling close handlers
void
HttpStateData::abortTransaction(const char *reason)
{
    debugs(11,5, HERE << "aborting transaction for " << reason <<
           "; FD " << fd << ", this " << this);

    if (fd >= 0) {
        comm_close(fd);
        return;
    }

    fwd->handleUnregisteredServerEnd();
    delete this;
}

void
httpBuildVersion(HttpVersion * version, unsigned int major, unsigned int minor)
{
    version->major = major;
    version->minor = minor;
}

HttpRequest *
HttpStateData::originalRequest()
{
    return orig_request;
}
