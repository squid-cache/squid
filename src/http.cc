
/*
 * $Id: http.cc,v 1.435 2004/11/16 23:11:46 wessels Exp $
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
#include "http.h"
#include "AuthUserRequest.h"
#include "Store.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemObject.h"
#include "HttpHdrContRange.h"
#include "ACLChecklist.h"
#if DELAY_POOLS
#include "DelayPools.h"
#endif

CBDATA_TYPE(HttpStateData);


static const char *const crlf = "\r\n";

static CWCB httpSendRequestEntity;

static IOCB httpReadReply;
static void httpSendRequest(HttpStateData *);
static PF httpStateFree;
static PF httpTimeout;
static void httpCacheNegatively(StoreEntry *);
static void httpMakePrivate(StoreEntry *);
static void httpMakePublic(StoreEntry *);
static void httpMaybeRemovePublic(StoreEntry *, http_status);
static void copyOneHeaderFromClientsideRequestToUpstreamRequest(const HttpHeaderEntry *e, String strConnection, HttpRequest * request, HttpRequest * orig_request,
        HttpHeader * hdr_out, int we_do_ranges, http_state_flags);
static int decideIfWeDoRanges (HttpRequest * orig_request);


static void
httpStateFree(int fd, void *data)
{
    HttpStateData *httpState = static_cast<HttpStateData *>(data);

    if (httpState == NULL)
        return;

    storeUnlockObject(httpState->entry);

    if (httpState->reply_hdr) {
        memFree(httpState->reply_hdr, MEM_8K_BUF);
        httpState->reply_hdr = NULL;
    }

    requestUnlink(httpState->request);
    requestUnlink(httpState->orig_request);
    httpState->request = NULL;
    httpState->orig_request = NULL;
    cbdataFree(httpState);
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
    debug(11, 4) ("httpTimeout: FD %d: '%s'\n", fd, storeUrl(entry));

    if (entry->store_status == STORE_PENDING) {
        if (entry->isEmpty()) {
            fwdFail(httpState->fwd,
                    errorCon(ERR_READ_TIMEOUT, HTTP_GATEWAY_TIMEOUT));
        }
    }

    comm_close(fd);
}

/* This object can be cached for a long time */
static void
httpMakePublic(StoreEntry * entry)
{
    if (EBIT_TEST(entry->flags, ENTRY_CACHABLE))
        storeSetPublicKey(entry);
}

/* This object should never be cached at all */
static void
httpMakePrivate(StoreEntry * entry)
{
    storeExpireNow(entry);
    storeReleaseRequest(entry);	/* delete object when not used */
    /* storeReleaseRequest clears ENTRY_CACHABLE flag */
}

/* This object may be negatively cached */
static void
httpCacheNegatively(StoreEntry * entry)
{
    storeNegativeCache(entry);

    if (EBIT_TEST(entry->flags, ENTRY_CACHABLE))
        storeSetPublicKey(entry);
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
        storeRelease(pe);
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
        storeRelease(pe);
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
            storeRelease(pe);
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
#if ESI

    if (request->flags.accelerated && reply->surrogate_control) {
        HttpHdrScTarget *sctusable =
            httpHdrScGetMergedTarget(reply->surrogate_control,
                                     Config.Accel.surrogate_id);

        if (sctusable) {
            if (EBIT_TEST(sctusable->mask, SC_NO_STORE) ||
                    (Config.onoff.surrogate_is_remote
                     && EBIT_TEST(sctusable->mask, SC_NO_STORE_REMOTE))) {
                surrogateNoStore = true;
                httpMakePrivate(entry);
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
                storeTimestampsSet(entry);
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
    HttpReply const *rep = entry->getReply();
    HttpHeader const *hdr = &rep->header;
    const int cc_mask = (rep->cache_control) ? rep->cache_control->mask : 0;
    const char *v;
#if HTTP_VIOLATIONS

    const refresh_t *R = NULL;
#endif

    if (surrogateNoStore)
        return 0;

    if (!ignoreCacheControl) {
        if (EBIT_TEST(cc_mask, CC_PRIVATE)) {
#if HTTP_VIOLATIONS

            if (!R)
                R = refreshLimits(entry->mem_obj->url);

            if (R && !R->flags.ignore_private)
#endif

                return 0;
        }

        if (EBIT_TEST(cc_mask, CC_NO_CACHE)) {
#if HTTP_VIOLATIONS

            if (!R)
                R = refreshLimits(entry->mem_obj->url);

            if (R && !R->flags.ignore_no_cache)
#endif

                return 0;
        }

        if (EBIT_TEST(cc_mask, CC_NO_STORE)) {
#if HTTP_VIOLATIONS

            if (!R)
                R = refreshLimits(entry->mem_obj->url);

            if (R && !R->flags.ignore_no_store)
#endif

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
#if HTTP_VIOLATIONS

            if (!R)
                R = refreshLimits(entry->mem_obj->url);

            if (R && !R->flags.ignore_auth)
#endif

                return 0;
        }
    }

    /* Pragma: no-cache in _replies_ is not documented in HTTP,
     * but servers like "Active Imaging Webcast/2.0" sure do use it */
    if (httpHeaderHas(hdr, HDR_PRAGMA)) {
        String s = httpHeaderGetList(hdr, HDR_PRAGMA);
        const int no_cache = strListIsMember(&s, "no-cache", ',');
        s.clean();

        if (no_cache) {
#if HTTP_VIOLATIONS

            if (!R)
                R = refreshLimits(entry->mem_obj->url);

            if (R && !R->flags.ignore_no_cache)
#endif

                return 0;
        }
    }

    /*
     * The "multipart/x-mixed-replace" content type is used for
     * continuous push replies.  These are generally dynamic and
     * probably should not be cachable
     */
    if ((v = httpHeaderGetStr(hdr, HDR_CONTENT_TYPE)))
        if (!strncasecmp(v, "multipart/x-mixed-replace", 25))
            return 0;

    switch (entry->getReply()->sline.status) {
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

        if (!refreshIsCachable(entry))
            return 0;

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
        if (rep->expires > -1)
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
        return 0;

    default:			/* Unknown status code */
        debug (11,0)("HttpStateData::cacheableReply: unknown http status code in reply\n");

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
    vary = httpHeaderGetList(&reply->header, HDR_VARY);

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
        hdr = httpHeaderGetByName(&request->header, name);
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
    vary = httpHeaderGetList(&reply->header, HDR_X_ACCELERATOR_VARY);

    while (strListGetItem(&vary, ',', &item, &ilen, &pos)) {
        char *name = (char *)xmalloc(ilen + 1);
        xstrncpy(name, item, ilen + 1);
        Tolower(name);
        strListAdd(&vstr, name, ',');
        hdr = httpHeaderGetByName(&request->header, name);
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

    debug(11, 3) ("httpMakeVaryMark: %s\n", vstr.buf());
    return vstr.buf();
}

/* rewrite this later using new interfaces @?@ */
void
HttpStateData::processReplyHeader(const char *buf, int size)
{
    char *t = NULL;
    int room;
    size_t hdr_len;
    /* Creates a blank header. If this routine is made incremental, this will
     * not do 
     */
    HttpReply *reply = httpReplyCreate();
    Ctx ctx;
    debug(11, 3) ("httpProcessReplyHeader: key '%s'\n",
                  entry->getMD5Text());

    if (reply_hdr == NULL)
        reply_hdr = (char *)memAllocate(MEM_8K_BUF);

    assert(reply_hdr_state == 0);

    hdr_len = reply_hdr_size;

    room = 8191 - hdr_len;

    xmemcpy(reply_hdr + hdr_len, buf, room < size ? room : size);

    hdr_len += room < size ? room : size;

    reply_hdr[hdr_len] = '\0';

    reply_hdr_size = hdr_len;

    if (hdr_len > 4 && strncmp(reply_hdr, "HTTP/", 5)) {
        debug(11, 3) ("httpProcessReplyHeader: Non-HTTP-compliant header: '%s'\n", reply_hdr);
        reply_hdr_state += 2;
        reply->sline.version = HttpVersion(1, 0);
        reply->sline.status = HTTP_INVALID_HEADER;
        storeEntryReplaceObject (entry, reply);

        if (eof == 1) {
            fwdComplete(fwd);
            comm_close(fd);
        }

        return;
    }

    t = reply_hdr + hdr_len;
    /* headers can be incomplete only if object still arriving */

    if (!eof) {
        size_t k = headersEnd(reply_hdr, 8192);

        if (0 == k) {
            if (eof == 1) {
                fwdComplete(fwd);
                comm_close(fd);
            }

            return;		/* headers not complete */
        }

        t = reply_hdr + k;
    }

    *t = '\0';
    reply_hdr_state++;
    assert(reply_hdr_state == 1);
    ctx = ctx_enter(entry->mem_obj->url);
    reply_hdr_state++;
    debug(11, 9) ("GOT HTTP REPLY HDR:\n---------\n%s\n----------\n",
                  reply_hdr);
    /* Parse headers into reply structure */
    /* what happens if we fail to parse here? */
    httpReplyParse(reply, reply_hdr, hdr_len);

    if (reply->sline.status >= HTTP_INVALID_HEADER) {
        debug(11, 3) ("httpProcessReplyHeader: Non-HTTP-compliant header: '%s'\n", reply_hdr);
        reply->sline.version = HttpVersion(1, 0);
        reply->sline.status = HTTP_INVALID_HEADER;
        storeEntryReplaceObject (entry, reply);

        if (eof == 1) {
            fwdComplete(fwd);
            comm_close(fd);
        }

        return;
    }

    processSurrogateControl (reply);
    /* TODO: we need our own reply * in the httpState, as we probably don't want to replace
     * the storeEntry with interim headers
     */

    /* TODO: IF the reply is a 1.0 reply, AND it has a Connection: Header
     * Parse the header and remove all referenced headers
     */

    storeEntryReplaceObject(entry, reply);
    /* DO NOT USE reply now */
    reply = NULL;

    if (entry->getReply()->sline.status == HTTP_PARTIAL_CONTENT &&
            entry->getReply()->content_range)
        currentOffset = entry->getReply()->content_range->spec.offset;

    storeTimestampsSet(entry);

    /* Check if object is cacheable or not based on reply code */
    debug(11, 3) ("httpProcessReplyHeader: HTTP CODE: %d\n", entry->getReply()->sline.status);

    if (neighbors_do_private_keys)
        httpMaybeRemovePublic(entry, entry->getReply()->sline.status);

    if (httpHeaderHas(&entry->getReply()->header, HDR_VARY)
#if X_ACCELERATOR_VARY
            || httpHeaderHas(&entry->getReply()->header, HDR_X_ACCELERATOR_VARY)
#endif
       ) {
        const char *vary = httpMakeVaryMark(orig_request, entry->getReply());

        if (!vary) {
            httpMakePrivate(entry);
            goto no_cache;

        }

        entry->mem_obj->vary_headers = xstrdup(vary);
    }

    switch (cacheableReply()) {

    case 1:
        httpMakePublic(entry);
        break;

    case 0:
        httpMakePrivate(entry);
        break;

    case -1:

        if (Config.negativeTtl > 0)
            httpCacheNegatively(entry);
        else
            httpMakePrivate(entry);

        break;

    default:
        assert(0);

        break;
    }

no_cache:

    if (!ignoreCacheControl && entry->getReply()->cache_control) {
        if (EBIT_TEST(entry->getReply()->cache_control->mask, CC_PROXY_REVALIDATE))
            EBIT_SET(entry->flags, ENTRY_REVALIDATE);
        else if (EBIT_TEST(entry->getReply()->cache_control->mask, CC_MUST_REVALIDATE))
            EBIT_SET(entry->flags, ENTRY_REVALIDATE);
    }

    if (flags.keepalive)
        if (_peer)
            _peer->stats.n_keepalives_sent++;

    if (entry->getReply()->keep_alive)
        if (_peer)
            _peer->stats.n_keepalives_recv++;

    if (entry->getReply()->date > -1 && !_peer) {
        int skew = abs(entry->getReply()->date - squid_curtime);

        if (skew > 86400)
            debug(11, 3) ("%s's clock is skewed by %d seconds!\n",
                          request->host, skew);
    }

    ctx_exit(ctx);
#if HEADERS_LOG

    headersLog(1, 0, request->method, entry->getReply());
#endif

    if (eof == 1) {
        fwdComplete(fwd);
        comm_close(fd);
    }
}

HttpStateData::ConnectionStatus
HttpStateData::statusIfComplete() const
{
    HttpReply const *reply = entry->getReply();
    /* If the reply wants to close the connection, it takes precedence */

    if (httpHeaderHasConnDir(&reply->header, "close"))
        return COMPLETE_NONPERSISTENT_MSG;

    /* If we didn't send a keep-alive request header, then this
     * can not be a persistent connection.
     */
    if (!flags.keepalive)
        return COMPLETE_NONPERSISTENT_MSG;

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
    if (!reply->keep_alive)
        return COMPLETE_NONPERSISTENT_MSG;

    return COMPLETE_PERSISTENT_MSG;
}

HttpStateData::ConnectionStatus
HttpStateData::persistentConnStatus() const
{
    HttpReply const *reply = entry->getReply();
    int clen;
    debug(11, 3) ("httpPconnTransferDone: FD %d\n", fd);
    ConnectionStatus result = statusIfComplete();
    debug(11, 5) ("httpPconnTransferDone: content_length=%d\n",
                  reply->content_length);
    /* If we haven't seen the end of reply headers, we are not done */

    if (reply_hdr_state < 2)
        return INCOMPLETE_MSG;

    clen = httpReplyBodySize(request->method, reply);

    /* If there is no message body, we can be persistent */
    if (0 == clen)
        return result;

    /* If the body size is unknown we must wait for EOF */
    if (clen < 0)
        return INCOMPLETE_MSG;

    /* If the body size is known, we must wait until we've gotten all of it.  */
    if (entry->mem_obj->endOffset() < reply->content_length + reply->hdr_sz)
        return INCOMPLETE_MSG;

    /* We got it all */
    return result;
}

/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
/* XXX this function is too long! */
static void
httpReadReply(int fd, char *buf, size_t len, comm_err_t flag, int xerrno,void *data)
{
    HttpStateData *httpState = static_cast<HttpStateData *>(data);
    assert (fd == httpState->fd);
    PROF_start(HttpStateData_readReply);
    httpState->readReply (fd, buf, len, flag, xerrno, data);
    PROF_stop(HttpStateData_readReply);
}

void
HttpStateData::readReply (int fd, char *readBuf, size_t len, comm_err_t flag, int xerrno,void *data)
{
    int bin;
    int clen;
    do_next_read = 0;


    assert(buf == readBuf);

    /* Bail out early on COMM_ERR_CLOSING - close handlers will tidy up for us
    */

    if (flag == COMM_ERR_CLOSING) {
        debug (11,3)("http socket closing\n");
        return;
    }

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        maybeReadData();
        return;
    }

    errno = 0;
    /* prepare the read size for the next read (if any) */
#if DELAY_POOLS

    DelayId delayId = entry->mem_obj->mostBytesAllowed();

#endif

    debug(11, 5) ("httpReadReply: FD %d: len %d.\n", fd, (int)len);

    if (flag == COMM_OK && len > 0) {
#if DELAY_POOLS
        delayId.bytesIn(len);
#endif

        kb_incr(&statCounter.server.all.kbytes_in, len);
        kb_incr(&statCounter.server.http.kbytes_in, len);
        commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
        IOStats.Http.reads++;

        for (clen = len - 1, bin = 0; clen; bin++)
            clen >>= 1;

        IOStats.Http.read_hist[bin]++;
    }

    if (!reply_hdr && flag == COMM_OK && len > 0) {
        /* Skip whitespace */

        while (len > 0 && xisspace(*buf))
            xmemmove(buf, buf + 1, len--);

        if (len == 0) {
            /* Continue to read... */
            do_next_read = 1;
            maybeReadData();
            return;
        }
    }

    if (flag != COMM_OK || len < 0) {
        debug(50, 2) ("httpReadReply: FD %d: read failure: %s.\n",
                      fd, xstrerror());

        if (ignoreErrno(errno)) {
            do_next_read = 1;
        } else if (entry->isEmpty()) {
            ErrorState *err;
            err = errorCon(ERR_READ_ERROR, HTTP_INTERNAL_SERVER_ERROR);
            err->request = requestLink((HttpRequest *) request);
            err->xerrno = errno;
            fwdFail(fwd, err);
            do_next_read = 0;
            comm_close(fd);
        } else {
            do_next_read = 0;
            comm_close(fd);
        }
    } else if (flag == COMM_OK && len == 0 && entry->isEmpty()) {
        ErrorState *err;
        err = errorCon(ERR_ZERO_SIZE_OBJECT, HTTP_SERVICE_UNAVAILABLE);
        err->xerrno = errno;
        err->request = requestLink((HttpRequest *) request);
        fwdFail(fwd, err);
        eof = 1;
        do_next_read = 0;
        comm_close(fd);
    } else if (flag == COMM_OK && len == 0) {
        /* Connection closed; retrieval done. */
        eof = 1;

        if (reply_hdr_state < 2)
            /*
             * Yes Henrik, there is a point to doing this.  When we
             * called httpProcessReplyHeader() before, we didn't find
             * the end of headers, but now we are definately at EOF, so
             * we want to process the reply headers.
             */
            /* doesn't return */
            processReplyHeader(buf, len);
        else if (entry->getReply()->sline.status == HTTP_INVALID_HEADER && HttpVersion(0,9) != entry->getReply()->sline.version) {
            ErrorState *err;
            err = errorCon(ERR_INVALID_REQ, HTTP_BAD_GATEWAY);
            err->request = requestLink((HttpRequest *) request);
            fwdFail(fwd, err);
            do_next_read = 0;
        } else {
            fwdComplete(fwd);
            do_next_read = 0;
            comm_close(fd);
        }
    } else {
        if (reply_hdr_state < 2) {
            processReplyHeader(buf, len);

            if (reply_hdr_state == 2) {
                http_status s = entry->getReply()->sline.status;
                HttpVersion httpver = entry->getReply()->sline.version;

                if (s == HTTP_INVALID_HEADER && httpver != HttpVersion(0,9)) {
                    ErrorState *err;
                    storeEntryReset(entry);
                    err = errorCon(ERR_INVALID_REQ, HTTP_BAD_GATEWAY);
                    err->request = requestLink((HttpRequest *) request);
                    fwdFail(fwd, err);
                    comm_close(fd);
                    return;
                }

#if WIP_FWD_LOG

                fwdStatus(fwd, s);

#endif
                /*
                 * If its not a reply that we will re-forward, then
                 * allow the client to get it.
                 */

                if (!fwdReforwardableStatus(s))
                    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
            }
        }

        PROF_start(HttpStateData_processReplyData);
        processReplyData(buf, len);
        PROF_stop(HttpStateData_processReplyData);
    }
}

void
HttpStateData::processReplyData(const char *buf, size_t len)
{
    if (reply_hdr_state < 2) {
        do_next_read = 1;
        maybeReadData();
        return;
    }

    StoreIOBuffer tempBuffer;

    if (!flags.headers_pushed) {
        /* The first block needs us to skip the headers */
        /* TODO: make this cleaner. WE should push the headers, NOT the parser */
        size_t end = headersEnd (buf, len);
        /* IF len > end, we need to append data after the
         * out of band update to the store
         */

        if (len > end) {
            tempBuffer.data = (char *)buf+end;
            tempBuffer.length = len - end;
            tempBuffer.offset = currentOffset;
            currentOffset += tempBuffer.length;
            entry->write (tempBuffer);
        }

        flags.headers_pushed = 1;
    } else {
        tempBuffer.data = (char *)buf;
        tempBuffer.length = len;
        tempBuffer.offset = currentOffset;
        currentOffset += len;
        entry->write(tempBuffer);
    }

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        /*
         * the above storeAppend() call could ABORT this entry,
         * in that case, the server FD should already be closed.
         * there's nothing for us to do.
         */
        (void) 0;
    } else
        switch (persistentConnStatus()) {

        case INCOMPLETE_MSG:
            /* Wait for EOF condition */
            do_next_read = 1;
            break;

        case COMPLETE_PERSISTENT_MSG:
            /* yes we have to clear all these! */
            commSetTimeout(fd, -1, NULL, NULL);
            do_next_read = 0;

            comm_remove_close_handler(fd, httpStateFree, this);
            fwdUnregister(fd, fwd);

            if (_peer) {
                if (_peer->options.originserver)
                    pconnPush(fd, _peer->name, orig_request->port, orig_request->host);
                else
                    pconnPush(fd, _peer->name, _peer->http_port, NULL);
            } else {
                pconnPush(fd, request->host, request->port, NULL);
            }

            fwdComplete(fwd);
            fd = -1;
            httpStateFree(fd, this);
            return;

        case COMPLETE_NONPERSISTENT_MSG:
            /* close the connection ourselves */
            /* yes - same as for a complete persistent conn here */
            commSetTimeout(fd, -1, NULL, NULL);
            commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
            comm_remove_close_handler(fd, httpStateFree, this);
            fwdUnregister(fd, fwd);
            fwdComplete(fwd);
            /* TODO: check that fd is still open here */
            comm_close (fd);
            fd = -1;
            httpStateFree(fd, this);
            return;
        }

    maybeReadData();
}

void
HttpStateData::maybeReadData()
{
    if (do_next_read) {
        do_next_read = 0;
        entry->delayAwareRead(fd, buf, SQUID_TCP_SO_RCVBUF, httpReadReply, this);
    }
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
void
HttpStateData::SendComplete(int fd, char *bufnotused, size_t size, comm_err_t errflag, void *data)
{
    HttpStateData *httpState = static_cast<HttpStateData *>(data);
    StoreEntry *entry = httpState->entry;
    ErrorState *err;
    debug(11, 5) ("httpSendComplete: FD %d: size %d: errflag %d.\n",
                  fd, (int) size, errflag);
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
        err = errorCon(ERR_WRITE_ERROR, HTTP_INTERNAL_SERVER_ERROR);
        err->xerrno = errno;
        err->request = requestLink(httpState->orig_request);
        errorAppendEntry(entry, err);
        comm_close(fd);
        return;
    } else {
        /* Schedule read reply. */
        entry->delayAwareRead(fd, httpState->buf, SQUID_TCP_SO_RCVBUF, httpReadReply, httpState);
        /*
         * Set the read timeout here because it hasn't been set yet.
         * We only set the read timeout after the request has been
         * fully written to the server-side.  If we start the timeout
         * after connection establishment, then we are likely to hit
         * the timeout for POST/PUT requests that have very large
         * request bodies.
         */
        commSetTimeout(fd, Config.Timeout.read, httpTimeout, httpState);
    }
}

/*
 * build request headers and append them to a given MemBuf 
 * used by httpBuildRequestPrefix()
 * note: initialised the HttpHeader, the caller is responsible for Clean()-ing
 */
void
httpBuildRequestHeader(HttpRequest * request,
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

    if (request->lastmod > -1 && request->method == METHOD_GET)
        httpHeaderPutTime(hdr_out, HDR_IF_MODIFIED_SINCE, request->lastmod);

    bool we_do_ranges = decideIfWeDoRanges (orig_request);

    String strConnection (httpHeaderGetList(hdr_in, HDR_CONNECTION));

    while ((e = httpHeaderGetEntry(hdr_in, &pos)))
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
        strVia = httpHeaderGetList(hdr_in, HDR_VIA);
        snprintf(bbuf, BBUF_SZ, "%d.%d %s",
                 orig_request->http_ver.major,
                 orig_request->http_ver.minor, ThisCache);
        strListAdd(&strVia, bbuf, ',');
        httpHeaderPutStr(hdr_out, HDR_VIA, strVia.buf());
        strVia.clean();
    }

#if ESI
    {
        /* Append Surrogate-Capabilities */
        String strSurrogate (httpHeaderGetList(hdr_in, HDR_SURROGATE_CAPABILITY));
        snprintf(bbuf, BBUF_SZ, "%s=\"Surrogate/1.0 ESI/1.0\"",
                 Config.Accel.surrogate_id);
        strListAdd(&strSurrogate, bbuf, ',');
        httpHeaderPutStr(hdr_out, HDR_SURROGATE_CAPABILITY, strSurrogate.buf());
    }
#endif

    /* append X-Forwarded-For */
    strFwd = httpHeaderGetList(hdr_in, HDR_X_FORWARDED_FOR);

    if (opt_forwarded_for && orig_request->client_addr.s_addr != no_addr.s_addr)
        strListAdd(&strFwd, inet_ntoa(orig_request->client_addr), ',');
    else
        strListAdd(&strFwd, "unknown", ',');

    httpHeaderPutStr(hdr_out, HDR_X_FORWARDED_FOR, strFwd.buf());

    strFwd.clean();

    /* append Host if not there already */
    if (!httpHeaderHas(hdr_out, HDR_HOST)) {
        if (orig_request->peer_domain) {
            httpHeaderPutStr(hdr_out, HDR_HOST, orig_request->peer_domain);
        } else if (orig_request->port == urlDefaultPort(orig_request->protocol)) {
            /* use port# only if not default */
            httpHeaderPutStr(hdr_out, HDR_HOST, orig_request->host);
        } else {
            httpHeaderPutStrf(hdr_out, HDR_HOST, "%s:%d",
                              orig_request->host, (int) orig_request->port);
        }
    }

    /* append Authorization if known in URL, not in header and going direct */
    if (!httpHeaderHas(hdr_out, HDR_AUTHORIZATION)) {
        if (!request->flags.proxying && *request->login) {
            httpHeaderPutStrf(hdr_out, HDR_AUTHORIZATION, "Basic %s",
                              base64_encode(request->login));
        }
    }

    /* append Proxy-Authorization if configured for peer, and proxying */
    if (request->flags.proxying && orig_request->peer_login &&
            !httpHeaderHas(hdr_out, HDR_PROXY_AUTHORIZATION)) {
        if (*orig_request->peer_login == '*') {
            /* Special mode, to pass the username to the upstream cache */
            char loginbuf[256];
            const char *username = "-";

            if (orig_request->auth_user_request)
                username = orig_request->auth_user_request->username();
            else if (orig_request->extacl_user.size())
                username = orig_request->extacl_user.buf();

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
            !httpHeaderHas(hdr_out, HDR_AUTHORIZATION)) {
        if (strcmp(orig_request->peer_login, "PASS") == 0) {
            /* No credentials to forward.. (should have been done above if available) */
        } else if (strcmp(orig_request->peer_login, "PROXYPASS") == 0) {
            /* Special mode, convert proxy authentication to WWW authentication
            * (also applies to authentication provided by external acl)
             */
            const char *auth = httpHeaderGetStr(hdr_in, HDR_PROXY_AUTHORIZATION);

            if (auth && strncasecmp(auth, "basic ", 6) == 0) {
                httpHeaderPutStr(hdr_out, HDR_AUTHORIZATION, auth);
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
        HttpHdrCc *cc = httpHeaderGetCc(hdr_in);

        if (!cc)
            cc = httpHdrCcCreate();

        if (!EBIT_TEST(cc->mask, CC_MAX_AGE)) {
            const char *url =
                entry ? storeUrl(entry) : urlCanonical(orig_request);
            httpHdrCcSetMaxAge(cc, getMaxAge(url));

            if (request->urlpath.size())
                assert(strstr(url, request->urlpath.buf()));
        }

        /* Set no-cache if determined needed but not found */
        if (orig_request->flags.nocache && !httpHeaderHas(hdr_in, HDR_PRAGMA))
            EBIT_SET(cc->mask, CC_NO_CACHE);

        /* Enforce sibling relations */
        if (flags.only_if_cached)
            EBIT_SET(cc->mask, CC_ONLY_IF_CACHED);

        httpHeaderPutCc(hdr_out, cc);

        httpHdrCcDestroy(cc);
    }

    /* maybe append Connection: keep-alive */
    if (flags.keepalive) {
        if (flags.proxying) {
            httpHeaderPutStr(hdr_out, HDR_PROXY_CONNECTION, "keep-alive");
        } else {
            httpHeaderPutStr(hdr_out, HDR_CONNECTION, "keep-alive");
        }
    }

    /* append Front-End-Https */
    if (flags.front_end_https) {
        if (flags.front_end_https == 1 || request->protocol == PROTO_HTTPS)
            httpHeaderPutStr(hdr_out, HDR_FRONT_END_HTTPS, "On");
    }

    /* Now mangle the headers. */
    httpHdrMangleList(hdr_out, request);

    strConnection.clean();
}


void
copyOneHeaderFromClientsideRequestToUpstreamRequest(const HttpHeaderEntry *e, String strConnection, HttpRequest * request, HttpRequest * orig_request, HttpHeader * hdr_out, int we_do_ranges, http_state_flags flags)
{
    debug(11, 5) ("httpBuildRequestHeader: %s: %s\n",
                  e->name.buf(), e->value.buf());

    if (!httpRequestHdrAllowed(e, &strConnection)) {
        debug(11, 2) ("'%s' header denied by anonymize_headers configuration\n",+       e->name.buf());
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
            httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
        }

        break;

    case HDR_AUTHORIZATION:
        /* Pass on WWW authentication */

        if (!flags.originpeer) {
            httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
        } else {
            /* In accelerators, only forward authentication if enabled
             * (see also below for proxy->server authentication)
             */

            if (orig_request->peer_login &&
                    (strcmp(orig_request->peer_login, "PASS") == 0 ||
                     strcmp(orig_request->peer_login, "PROXYPASS") == 0)) {
                httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
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

        if (request->flags.redirected && !Config.onoff.redir_rewrites_host)
            httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
        else {
            /* use port# only if not default */

            if (orig_request->port == urlDefaultPort(orig_request->protocol)) {
                httpHeaderPutStr(hdr_out, HDR_HOST, orig_request->host);
            } else {
                httpHeaderPutStrf(hdr_out, HDR_HOST, "%s:%d",
                                  orig_request->host, (int) orig_request->port);
            }
        }

        break;

    case HDR_IF_MODIFIED_SINCE:
        /* append unless we added our own;
         * note: at most one client's ims header can pass through */

        if (!httpHeaderHas(hdr_out, HDR_IF_MODIFIED_SINCE))
            httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));

        break;

    case HDR_MAX_FORWARDS:
        if (orig_request->method == METHOD_TRACE) {
            const int hops = httpHeaderEntryGetInt(e);

            if (hops > 0)
                httpHeaderPutInt(hdr_out, HDR_MAX_FORWARDS, hops - 1);
        }

        break;

    case HDR_VIA:
        /* If Via is disabled then forward any received header as-is */

        if (!Config.onoff.via)
            httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));

        break;

    case HDR_RANGE:

    case HDR_IF_RANGE:

    case HDR_REQUEST_RANGE:
        if (!we_do_ranges)
            httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));

        break;

    case HDR_PROXY_CONNECTION:

    case HDR_CONNECTION:

    case HDR_X_FORWARDED_FOR:

    case HDR_CACHE_CONTROL:
        /* append these after the loop if needed */
        break;

    case HDR_FRONT_END_HTTPS:
        if (!flags.front_end_https)
            httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));

        break;

    default:
        /* pass on all other header fields */
        httpHeaderAddEntry(hdr_out, httpHeaderEntryClone(e));
    }
}

int
decideIfWeDoRanges (HttpRequest * orig_request)
{
    int result = 1;
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
        result = 0;

    debug(11, 8) ("decideIfWeDoRanges: range specs: %p, cachable: %d; we_do_ranges: %d\n",
                  orig_request->range, orig_request->flags.cachable, result);

    return result;
}


/* build request prefix and append it to a given MemBuf;
 * return the length of the prefix */
mb_size_t
httpBuildRequestPrefix(HttpRequest * request,
                       HttpRequest * orig_request,
                       StoreEntry * entry,
                       MemBuf * mb,
                       http_state_flags flags)
{
    const int offset = mb->size;
    HttpVersion httpver(1, 0);
    memBufPrintf(mb, "%s %s HTTP/%d.%d\r\n",
                 RequestMethodStr[request->method],
                 request->urlpath.size() ? request->urlpath.buf() : "/",
                 httpver.major,httpver.minor);
    /* build and pack headers */
    {
        HttpHeader hdr(hoRequest);
        Packer p;
        httpBuildRequestHeader(request, orig_request, entry, &hdr, flags);
        packerToMemInit(&p, mb);
        httpHeaderPackInto(&hdr, &p);
        httpHeaderClean(&hdr);
        packerClean(&p);
    }
    /* append header terminator */
    memBufAppend(mb, crlf, 2);
    return mb->size - offset;
}

/* This will be called when connect completes. Write request. */
static void
httpSendRequest(HttpStateData * httpState)
{
    MemBuf mb;
    HttpRequest *req = httpState->request;
    StoreEntry *entry = httpState->entry;
    peer *p = httpState->_peer;
    CWCB *sendHeaderDone;

    debug(11, 5) ("httpSendRequest: FD %d: httpState %p.\n", httpState->fd,
                  httpState);

    if (httpState->orig_request->body_connection.getRaw() != NULL)
        sendHeaderDone = httpSendRequestEntity;
    else
        sendHeaderDone = HttpStateData::SendComplete;

    if (p != NULL) {
        if (p->options.originserver) {
            httpState->flags.proxying = 0;
            httpState->flags.originpeer = 1;
        } else {
            httpState->flags.proxying = 1;
            httpState->flags.originpeer = 0;
        }
    } else {
        httpState->flags.proxying = 0;
        httpState->flags.originpeer = 0;
    }

    /*
     * Is keep-alive okay for all request methods?
     */
    if (!Config.onoff.server_pconns)
        httpState->flags.keepalive = 0;
    else if (p == NULL)
        httpState->flags.keepalive = 1;
    else if (p->stats.n_keepalives_sent < 10)
        httpState->flags.keepalive = 1;
    else if ((double) p->stats.n_keepalives_recv /
             (double) p->stats.n_keepalives_sent > 0.50)
        httpState->flags.keepalive = 1;

    if (httpState->_peer) {
        if (neighborType(httpState->_peer, httpState->request) == PEER_SIBLING &&
                !httpState->_peer->options.allow_miss)
            httpState->flags.only_if_cached = 1;

        httpState->flags.front_end_https = httpState->_peer->front_end_https;
    }

    memBufDefInit(&mb);
    httpBuildRequestPrefix(req,
                           httpState->orig_request,
                           entry,
                           &mb,
                           httpState->flags);
    debug(11, 6) ("httpSendRequest: FD %d:\n%s\n", httpState->fd, mb.buf);
    comm_old_write_mbuf(httpState->fd, mb, sendHeaderDone, httpState);
}

void
httpStart(FwdState * fwd)
{
    int fd = fwd->server_fd;
    HttpStateData *httpState;
    HttpRequest *proxy_req;
    HttpRequest *orig_req = fwd->request;
    debug(11, 3) ("httpStart: \"%s %s\"\n",
                  RequestMethodStr[orig_req->method],
                  storeUrl(fwd->entry));
    CBDATA_INIT_TYPE(HttpStateData);
    httpState = cbdataAlloc(HttpStateData);
    httpState->ignoreCacheControl = false;
    httpState->surrogateNoStore = false;
    storeLockObject(fwd->entry);
    httpState->fwd = fwd;
    httpState->entry = fwd->entry;
    httpState->fd = fd;

    if (fwd->servers)
        httpState->_peer = fwd->servers->_peer;		/* might be NULL */

    if (httpState->_peer) {
        const char *url;

        if (httpState->_peer->options.originserver)
            url = orig_req->urlpath.buf();
        else
            url = storeUrl(httpState->entry);

        proxy_req = requestCreate(orig_req->method,
                                  orig_req->protocol, url);

        xstrncpy(proxy_req->host, httpState->_peer->host, SQUIDHOSTNAMELEN);

        proxy_req->port = httpState->_peer->http_port;

        proxy_req->flags = orig_req->flags;

        proxy_req->lastmod = orig_req->lastmod;

        httpState->request = requestLink(proxy_req);

        httpState->orig_request = requestLink(orig_req);

        proxy_req->flags.proxying = 1;

        /*
         * This NEIGHBOR_PROXY_ONLY check probably shouldn't be here.
         * We might end up getting the object from somewhere else if,
         * for example, the request to this neighbor fails.
         */
        if (httpState->_peer->options.proxy_only)
            storeReleaseRequest(httpState->entry);

#if DELAY_POOLS

        httpState->entry->setNoDelay(httpState->_peer->options.no_delay);

#endif

    } else {
        httpState->request = requestLink(orig_req);
        httpState->orig_request = requestLink(orig_req);
    }

    /*
     * register the handler to free HTTP state data when the FD closes
     */
    comm_add_close_handler(fd, httpStateFree, httpState);

    statCounter.server.all.requests++;

    statCounter.server.http.requests++;

    httpSendRequest(httpState);

    /*
     * We used to set the read timeout here, but not any more.
     * Now its set in httpSendComplete() after the full request,
     * including request body, has been written to the server.
     */
}

static void
httpSendRequestEntityDone(int fd, void *data)
{
    HttpStateData *httpState = static_cast<HttpStateData *>(data);
    ACLChecklist ch;
    debug(11, 5) ("httpSendRequestEntityDone: FD %d\n", fd);
    ch.request = requestLink(httpState->request);
    ch.accessList = Config.accessList.brokenPosts;

    if (!Config.accessList.brokenPosts) {
        debug(11, 5) ("httpSendRequestEntityDone: No brokenPosts list\n");
        HttpStateData::SendComplete(fd, NULL, 0, COMM_OK, data);
    } else if (!ch.fastCheck()) {
        debug(11, 5) ("httpSendRequestEntityDone: didn't match brokenPosts\n");
        HttpStateData::SendComplete(fd, NULL, 0, COMM_OK, data);
    } else {
        debug(11, 2) ("httpSendRequestEntityDone: matched brokenPosts\n");
        comm_old_write(fd, "\r\n", 2, HttpStateData::SendComplete, data, NULL);
    }

    ch.accessList = NULL;
}

static void
httpRequestBodyHandler(char *buf, ssize_t size, void *data)
{
    HttpStateData *httpState = (HttpStateData *) data;

    if (size > 0) {
        comm_old_write(httpState->fd, buf, size, httpSendRequestEntity, data, memFree8K);
    } else if (size == 0) {
        /* End of body */
        memFree8K(buf);
        httpSendRequestEntityDone(httpState->fd, data);
    } else {
        /* Failed to get whole body, probably aborted */
        memFree8K(buf);
        HttpStateData::SendComplete(httpState->fd, NULL, 0, COMM_ERR_CLOSING, data);
    }
}

static void
httpSendRequestEntity(int fd, char *bufnotused, size_t size, comm_err_t errflag, void *data)
{
    HttpStateData *httpState = static_cast<HttpStateData *>(data);
    StoreEntry *entry = httpState->entry;
    ErrorState *err;
    debug(11, 5) ("httpSendRequestEntity: FD %d: size %d: errflag %d.\n",
                  fd, (int) size, errflag);

    if (size > 0) {
        fd_bytes(fd, size, FD_WRITE);
        kb_incr(&statCounter.server.all.kbytes_out, size);
        kb_incr(&statCounter.server.http.kbytes_out, size);
    }

    if (errflag == COMM_ERR_CLOSING)
        return;

    if (errflag) {
        err = errorCon(ERR_WRITE_ERROR, HTTP_INTERNAL_SERVER_ERROR);
        err->xerrno = errno;
        err->request = requestLink(httpState->orig_request);
        errorAppendEntry(entry, err);
        comm_close(fd);
        return;
    }

    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
        comm_close(fd);
        return;
    }

    clientReadBody(httpState->orig_request, (char *)memAllocate(MEM_8K_BUF), 8192, httpRequestBodyHandler, httpState);
}

void
httpBuildVersion(HttpVersion * version, unsigned int major, unsigned int minor)
{
    version->major = major;
    version->minor = minor;
}
