
/*
 * $Id: client_side_request.cc,v 1.46 2005/09/12 22:26:39 wessels Exp $
 * 
 * DEBUG: section 85    Client-side Request Routines
 * AUTHOR: Robert Collins (Originally Duane Wessels in client_side.c)
 * 
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 * 
 * Squid is the result of efforts by numerous individuals from the Internet
 * community; see the CONTRIBUTORS file for full details.   Many organizations
 * have provided support for Squid's development; see the SPONSORS file for
 * full details.  Squid is Copyrighted (C) 2001 by the Regents of the
 * University of California; see the COPYRIGHT file for full details.  Squid
 * incorporates software developed and/or copyrighted by other sources; see the
 * CREDITS file for full details.
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111, USA.
 * 
 */


/*
 * General logic of request processing:
 * 
 * We run a series of tests to determine if access will be permitted, and to do
 * any redirection. Then we call into the result clientStream to retrieve data.
 * From that point on it's up to reply management.
 */

#include "squid.h"
#include "clientStream.h"
#include "client_side_request.h"
#include "AuthUserRequest.h"
#include "HttpRequest.h"
#include "ACLChecklist.h"
#include "ACL.h"
#include "client_side.h"
#include "client_side_reply.h"
#include "Store.h"
#include "HttpReply.h"
#include "MemObject.h"

#if LINGERING_CLOSE
#define comm_close comm_lingering_close
#endif

static const char *const crlf = "\r\n";

class ClientRequestContext : public RefCountable
{

public:
    void *operator new(size_t);
    void operator delete(void *);

    ClientRequestContext();
    ClientRequestContext(ClientHttpRequest *);
    ~ClientRequestContext();

    void checkNoCache();

    ACLChecklist *acl_checklist;	/* need ptr back so we can unreg if needed */
    int redirect_state;
    ClientHttpRequest *http;

private:
    CBDATA_CLASS(ClientRequestContext);
    static void CheckNoCacheDone(int answer, void *data);
    void checkNoCacheDone(int answer);
};

CBDATA_CLASS_INIT(ClientRequestContext);

void *
ClientRequestContext::operator new (size_t size)
{
    assert (size == sizeof(ClientRequestContext));
    CBDATA_INIT_TYPE(ClientRequestContext);
    ClientRequestContext *result = cbdataAlloc(ClientRequestContext);
    return result;
}

void
ClientRequestContext::operator delete (void *address)
{
    ClientRequestContext *t = static_cast<ClientRequestContext *>(address);
    cbdataFree(t);
}

/* Local functions */
/* other */
static void clientAccessCheckDone(int, void *);
static int clientCachable(ClientHttpRequest * http);
static int clientHierarchical(ClientHttpRequest * http);
static void clientInterpretRequestHeaders(ClientHttpRequest * http);
static void clientRedirectStart(ClientRequestContext *context);
static RH clientRedirectDone;
extern "C" CSR clientGetMoreData;
extern "C" CSS clientReplyStatus;
extern "C" CSD clientReplyDetach;
static void checkFailureRatio(err_type, hier_code);

ClientRequestContext::~ClientRequestContext()
{
    if (http)
        cbdataReferenceDone(http);

    if (acl_checklist)
        delete acl_checklist;
}

ClientRequestContext::ClientRequestContext() : acl_checklist (NULL), redirect_state (REDIRECT_NONE), http(NULL)
{}

ClientRequestContext::ClientRequestContext(ClientHttpRequest *newHttp) : acl_checklist (NULL), redirect_state (REDIRECT_NONE), http(cbdataReference(newHttp))
{
    assert (newHttp != NULL);
}

CBDATA_CLASS_INIT(ClientHttpRequest);

void *
ClientHttpRequest::operator new (size_t size)
{
    assert (size == sizeof (ClientHttpRequest));
    CBDATA_INIT_TYPE(ClientHttpRequest);
    ClientHttpRequest *result = cbdataAlloc(ClientHttpRequest);
    return result;
}

void
ClientHttpRequest::operator delete (void *address)
{
    ClientHttpRequest *t = static_cast<ClientHttpRequest *>(address);
    cbdataFree(t);
}

ClientHttpRequest::ClientHttpRequest() : loggingEntry_(NULL)
{
    /* reset range iterator */
    start = current_time;
}

/*
 * returns true if client specified that the object must come from the cache
 * without contacting origin server
 */
bool
ClientHttpRequest::onlyIfCached()const
{
    assert(request);
    return request->cache_control &&
           EBIT_TEST(request->cache_control->mask, CC_ONLY_IF_CACHED);
}

/*
 * This function is designed to serve a fairly specific purpose.
 * Occasionally our vBNS-connected caches can talk to each other, but not
 * the rest of the world.  Here we try to detect frequent failures which
 * make the cache unusable (e.g. DNS lookup and connect() failures).  If
 * the failure:success ratio goes above 1.0 then we go into "hit only"
 * mode where we only return UDP_HIT or UDP_MISS_NOFETCH.  Neighbors
 * will only fetch HITs from us if they are using the ICP protocol.  We
 * stay in this mode for 5 minutes.
 * 
 * Duane W., Sept 16, 1996
 */

#define FAILURE_MODE_TIME 300

static void
checkFailureRatio(err_type etype, hier_code hcode)
{
    static double magic_factor = 100.0;
    double n_good;
    double n_bad;

    if (hcode == HIER_NONE)
        return;

    n_good = magic_factor / (1.0 + request_failure_ratio);

    n_bad = magic_factor - n_good;

    switch (etype) {

    case ERR_DNS_FAIL:

    case ERR_CONNECT_FAIL:

    case ERR_READ_ERROR:
        n_bad++;
        break;

    default:
        n_good++;
    }

    request_failure_ratio = n_bad / n_good;

    if (hit_only_mode_until > squid_curtime)
        return;

    if (request_failure_ratio < 1.0)
        return;

    debug(33, 0) ("Failure Ratio at %4.2f\n", request_failure_ratio);

    debug(33, 0) ("Going into hit-only-mode for %d minutes...\n",
                  FAILURE_MODE_TIME / 60);

    hit_only_mode_until = squid_curtime + FAILURE_MODE_TIME;

    request_failure_ratio = 0.8;	/* reset to something less than 1.0 */
}

ClientHttpRequest::~ClientHttpRequest()
{
    debug(33, 3) ("httpRequestFree: %s\n", uri);
    /* if body_connection !NULL, then ProcessBody has not
     * found the end of the body yet
     */

    if (request && request->body_connection.getRaw() != NULL) {
        clientAbortBody(request);	/* abort body transter */
        request->body_connection = NULL;
    }

    /* the ICP check here was erroneous
     * - storeReleaseRequest was always called if entry was valid 
     */
    assert(logType < LOG_TYPE_MAX);

    logRequest();

    loggingEntry(NULL);

    if (request)
        checkFailureRatio(request->errType, al.hier.code);

    freeResources();

    /* moving to the next connection is handled by the context free */
    dlinkDelete(&active, &ClientActiveRequests);
}

/* Create a request and kick it off */
/*
 * TODO: Pass in the buffers to be used in the inital Read request, as they are
 * determined by the user
 */
int				/* returns nonzero on failure */
clientBeginRequest(method_t method, char const *url, CSCB * streamcallback,
                   CSD * streamdetach, ClientStreamData streamdata, HttpHeader const *header,
                   char *tailbuf, size_t taillen)
{
    size_t url_sz;
    HttpVersion http_ver (1, 0);
    ClientHttpRequest *http = new ClientHttpRequest;
    HttpRequest *request;
    StoreIOBuffer tempBuffer;
    http->setConn(NULL);
    http->start = current_time;
    /* this is only used to adjust the connection offset in client_side.c */
    http->req_sz = 0;
    tempBuffer.length = taillen;
    tempBuffer.data = tailbuf;
    /* client stream setup */
    clientStreamInit(&http->client_stream, clientGetMoreData, clientReplyDetach,
                     clientReplyStatus, new clientReplyContext(http), streamcallback,
                     streamdetach, streamdata, tempBuffer);
    /* make it visible in the 'current acctive requests list' */
    dlinkAdd(http, &http->active, &ClientActiveRequests);
    /* Set flags */
    /* internal requests only makes sense in an
     * accelerator today. TODO: accept flags ? */
    http->flags.accel = 1;
    /* allow size for url rewriting */
    url_sz = strlen(url) + Config.appendDomainLen + 5;
    http->uri = (char *)xcalloc(url_sz, 1);
    strcpy(http->uri, url);

    if ((request = urlParse(method, http->uri)) == NULL) {
        debug(85, 5) ("Invalid URL: %s\n", http->uri);
        return -1;
    }

    /*
     * now update the headers in request with our supplied headers. urLParse
     * should return a blank header set, but we use Update to be sure of
     * correctness.
     */
    if (header)
        httpHeaderUpdate(&request->header, header, NULL);

    http->log_uri = xstrdup(urlCanonicalClean(request));

    /* http struct now ready */

    /*
     * build new header list *? TODO
     */
    request->flags.accelerated = http->flags.accel;

    request->flags.internalclient = 1;

    /* this is an internally created
     * request, not subject to acceleration
     * target overrides */
    /*
     * FIXME? Do we want to detect and handle internal requests of internal
     * objects ?
     */

    /* Internally created requests cannot have bodies today */
    request->content_length = 0;

    request->client_addr = no_addr;

    request->my_addr = no_addr;	/* undefined for internal requests */

    request->my_port = 0;

    request->http_ver = http_ver;

    http->request = requestLink(request);

    /* optional - skip the access check ? */
    clientAccessCheck(http);

    return 0;
}

/* This is the entry point for external users of the client_side routines */
void
clientAccessCheck(ClientHttpRequest *http)
{
    ClientRequestContext *context = new ClientRequestContext(http);
    context->acl_checklist =
        clientAclChecklistCreate(Config.accessList.http, http);
    context->acl_checklist->nonBlockingCheck(clientAccessCheckDone, context);
}

void
clientAccessCheckDone(int answer, void *data)
{
    ClientRequestContext *context = (ClientRequestContext *)data;

    context->acl_checklist = NULL;
    ClientHttpRequest *http_ = context->http;

    if (!cbdataReferenceValid (http_)) {
        delete context;
        return;
    }

    ClientHttpRequest *http = context->http;
    err_type page_id;
    http_status status;
    debug(85, 2) ("The request %s %s is %s, because it matched '%s'\n",
                  RequestMethodStr[http->request->method], http->uri,
                  answer == ACCESS_ALLOWED ? "ALLOWED" : "DENIED",
                  AclMatchedName ? AclMatchedName : "NO ACL's");
    char const *proxy_auth_msg = "<null>";

    if (http->getConn().getRaw() != NULL && http->getConn()->auth_user_request != NULL)
        proxy_auth_msg = http->getConn()->auth_user_request->denyMessage("<null>");
    else if (http->request->auth_user_request != NULL)
        proxy_auth_msg = http->request->auth_user_request->denyMessage("<null>");

    if (answer == ACCESS_ALLOWED) {
        safe_free(http->uri);
        http->uri = xstrdup(urlCanonical(http->request));
        assert(context->redirect_state == REDIRECT_NONE);
        context->redirect_state = REDIRECT_PENDING;
        clientRedirectStart(context);
    } else {
        /* Send an error */
        clientStreamNode *node = (clientStreamNode *)http->client_stream.tail->prev->data;
        delete context;
        debug(85, 5) ("Access Denied: %s\n", http->uri);
        debug(85, 5) ("AclMatchedName = %s\n",
                      AclMatchedName ? AclMatchedName : "<null>");
        debug(85, 5) ("Proxy Auth Message = %s\n",
                      proxy_auth_msg ? proxy_auth_msg : "<null>");
        /*
         * NOTE: get page_id here, based on AclMatchedName because if
         * USE_DELAY_POOLS is enabled, then AclMatchedName gets clobbered in
         * the clientCreateStoreEntry() call just below.  Pedro Ribeiro
         * <pribeiro@isel.pt>
         */
        page_id = aclGetDenyInfoPage(&Config.denyInfoList, AclMatchedName);
        http->logType = LOG_TCP_DENIED;

        if (answer == ACCESS_REQ_PROXY_AUTH || aclIsProxyAuth(AclMatchedName)) {
            if (!http->flags.accel) {
                /* Proxy authorisation needed */
                status = HTTP_PROXY_AUTHENTICATION_REQUIRED;
            } else {
                /* WWW authorisation needed */
                status = HTTP_UNAUTHORIZED;
            }

            if (page_id == ERR_NONE)
                page_id = ERR_CACHE_ACCESS_DENIED;
        } else {
            status = HTTP_FORBIDDEN;

            if (page_id == ERR_NONE)
                page_id = ERR_ACCESS_DENIED;
        }

        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        repContext->setReplyToError(page_id, status,
                                    http->request->method, NULL,
                                    http->getConn().getRaw() != NULL ? &http->getConn()->peer.sin_addr : &no_addr, http->request,
                                    NULL, http->getConn().getRaw() != NULL
                                    && http->getConn()->auth_user_request ? http->getConn()->
                                    auth_user_request : http->request->auth_user_request);
        node = (clientStreamNode *)http->client_stream.tail->data;
        clientStreamRead(node, http, node->readBuffer);
    }
}

static void
clientRedirectAccessCheckDone(int answer, void *data)
{
    ClientRequestContext *context = (ClientRequestContext *)data;
    ClientHttpRequest *http = context->http;
    context->acl_checklist = NULL;

    if (answer == ACCESS_ALLOWED)
        redirectStart(http, clientRedirectDone, context);
    else
        clientRedirectDone(context, NULL);
}

static void
clientRedirectStart(ClientRequestContext *context)
{
    ClientHttpRequest *http = context->http;
    debug(33, 5) ("clientRedirectStart: '%s'\n", http->uri);

    if (Config.Program.redirect == NULL) {
        clientRedirectDone(context, NULL);
        return;
    }

    if (Config.accessList.redirector) {
        context->acl_checklist = clientAclChecklistCreate(Config.accessList.redirector, http);
        context->acl_checklist->nonBlockingCheck(clientRedirectAccessCheckDone, context);
    } else
        redirectStart(http, clientRedirectDone, context);
}

static int
clientCachable(ClientHttpRequest * http)
{
    HttpRequest *req = http->request;
    method_t method = req->method;

    if (req->protocol == PROTO_HTTP)
        return httpCachable(method);

    /* FTP is always cachable */
    if (req->protocol == PROTO_WAIS)
        return 0;

    /*
     * The below looks questionable: what non HTTP protocols use connect,
     * trace, put and post? RC
     */
    if (method == METHOD_CONNECT)
        return 0;

    if (method == METHOD_TRACE)
        return 0;

    if (method == METHOD_PUT)
        return 0;

    if (method == METHOD_POST)
        return 0;

    /* XXX POST may be cached sometimes.. ignored
            		 
            		        				 * for now */
    if (req->protocol == PROTO_GOPHER)
        return gopherCachable(req);

    if (req->protocol == PROTO_CACHEOBJ)
        return 0;

    return 1;
}

static int
clientHierarchical(ClientHttpRequest * http)
{
    const char *url = http->uri;
    HttpRequest *request = http->request;
    method_t method = request->method;
    const wordlist *p = NULL;

    /*
     * IMS needs a private key, so we can use the hierarchy for IMS only if our
     * neighbors support private keys
     */

    if (request->flags.ims && !neighbors_do_private_keys)
        return 0;

    /*
     * This is incorrect: authenticating requests can be sent via a hierarchy
     * (they can even be cached if the correct headers are set on the reply
     */
    if (request->flags.auth)
        return 0;

    if (method == METHOD_TRACE)
        return 1;

    if (method != METHOD_GET)
        return 0;

    /* scan hierarchy_stoplist */
    for (p = Config.hierarchy_stoplist; p; p = p->next)
        if (strstr(url, p->key))
            return 0;

    if (request->flags.loopdetect)
        return 0;

    if (request->protocol == PROTO_HTTP)
        return httpCachable(method);

    if (request->protocol == PROTO_GOPHER)
        return gopherCachable(request);

    if (request->protocol == PROTO_WAIS)
        return 0;

    if (request->protocol == PROTO_CACHEOBJ)
        return 0;

    return 1;
}


static void
clientInterpretRequestHeaders(ClientHttpRequest * http)
{
    HttpRequest *request = http->request;
    const HttpHeader *req_hdr = &request->header;
    int no_cache = 0;
#if !(ESI) || defined(USE_USERAGENT_LOG) || defined(USE_REFERER_LOG)

    const char *str;
#endif

    request->imslen = -1;
    request->ims = httpHeaderGetTime(req_hdr, HDR_IF_MODIFIED_SINCE);

    if (request->ims > 0)
        request->flags.ims = 1;

#if ESI
    /*
     * We ignore Cache-Control as per the Edge Architecture Section 3. See
     * www.esi.org for more information.
     */
#else

    if (httpHeaderHas(req_hdr, HDR_PRAGMA)) {
        String s = httpHeaderGetList(req_hdr, HDR_PRAGMA);

        if (strListIsMember(&s, "no-cache", ','))
            no_cache++;

        s.clean();
    }

    request->cache_control = httpHeaderGetCc(req_hdr);

    if (request->cache_control)
        if (EBIT_TEST(request->cache_control->mask, CC_NO_CACHE))
            no_cache++;

    /*
    * Work around for supporting the Reload button in IE browsers when Squid
    * is used as an accelerator or transparent proxy, by turning accelerated
    * IMS request to no-cache requests. Now knows about IE 5.5 fix (is
    * actually only fixed in SP1, but we can't tell whether we are talking to
    * SP1 or not so all 5.5 versions are treated 'normally').
    */
    if (Config.onoff.ie_refresh) {
        if (http->flags.accel && request->flags.ims) {
            if ((str = httpHeaderGetStr(req_hdr, HDR_USER_AGENT))) {
                if (strstr(str, "MSIE 5.01") != NULL)
                    no_cache++;
                else if (strstr(str, "MSIE 5.0") != NULL)
                    no_cache++;
                else if (strstr(str, "MSIE 4.") != NULL)
                    no_cache++;
                else if (strstr(str, "MSIE 3.") != NULL)
                    no_cache++;
            }
        }
    }

#endif
    if (no_cache) {
#if HTTP_VIOLATIONS

        if (Config.onoff.reload_into_ims)
            request->flags.nocache_hack = 1;
        else if (refresh_nocache_hack)
            request->flags.nocache_hack = 1;
        else
#endif

            request->flags.nocache = 1;
    }

    /* ignore range header in non-GETs */
    if (request->method == METHOD_GET) {
        request->range = httpHeaderGetRange(req_hdr);

        if (request->range) {
            request->flags.range = 1;
            clientStreamNode *node = (clientStreamNode *)http->client_stream.tail->data;
            /* XXX: This is suboptimal. We should give the stream the range set,
             * and thereby let the top of the stream set the offset when the
             * size becomes known. As it is, we will end up requesting from 0 
             * for evey -X range specification.
             * RBC - this may be somewhat wrong. We should probably set the range
             * iter up at this point.
             */
            node->readBuffer.offset = request->range->lowestOffset(0);
            http->range_iter.pos = request->range->begin();
            http->range_iter.valid = true;
        }
    }

    if (httpHeaderHas(req_hdr, HDR_AUTHORIZATION))
        request->flags.auth = 1;

    if (request->login[0] != '\0')
        request->flags.auth = 1;

    if (httpHeaderHas(req_hdr, HDR_VIA)) {
        String s = httpHeaderGetList(req_hdr, HDR_VIA);
        /*
         * ThisCache cannot be a member of Via header, "1.0 ThisCache" can.
         * Note ThisCache2 has a space prepended to the hostname so we don't
         * accidentally match super-domains.
         */

        if (strListIsSubstr(&s, ThisCache2, ',')) {
            debugObj(33, 1, "WARNING: Forwarding loop detected for:\n",
                     request, (ObjPackMethod) & httpRequestPack);
            request->flags.loopdetect = 1;
        }

#if FORW_VIA_DB
        fvdbCountVia(s.buf());

#endif

        s.clean();
    }

#if USE_USERAGENT_LOG
    if ((str = httpHeaderGetStr(req_hdr, HDR_USER_AGENT)))
        logUserAgent(fqdnFromAddr(http->getConn().getRaw() ? http->getConn()->log_addr : no_addr), str);

#endif
#if USE_REFERER_LOG

    if ((str = httpHeaderGetStr(req_hdr, HDR_REFERER)))
        logReferer(fqdnFromAddr(http->getConn().getRaw() ? http->getConn()->log_addr : no_addr), str, http->log_uri);

#endif
#if FORW_VIA_DB

    if (httpHeaderHas(req_hdr, HDR_X_FORWARDED_FOR)) {
        String s = httpHeaderGetList(req_hdr, HDR_X_FORWARDED_FOR);
        fvdbCountForw(s.buf());
        s.clean();
    }

#endif
    if (request->method == METHOD_TRACE) {
        request->max_forwards = httpHeaderGetInt(req_hdr, HDR_MAX_FORWARDS);
    }

    if (clientCachable(http))
        request->flags.cachable = 1;

    if (clientHierarchical(http))
        request->flags.hierarchical = 1;

    debug(85, 5) ("clientInterpretRequestHeaders: REQ_NOCACHE = %s\n",
                  request->flags.nocache ? "SET" : "NOT SET");

    debug(85, 5) ("clientInterpretRequestHeaders: REQ_CACHABLE = %s\n",
                  request->flags.cachable ? "SET" : "NOT SET");

    debug(85, 5) ("clientInterpretRequestHeaders: REQ_HIERARCHICAL = %s\n",
                  request->flags.hierarchical ? "SET" : "NOT SET");
}

void
clientRedirectDone(void *data, char *result)
{
    ClientRequestContext *context = (ClientRequestContext *)data;
    ClientHttpRequest *http_ = context->http;

    if (!cbdataReferenceValid (http_)) {
        delete context;
        return;
    }

    ClientHttpRequest *http = context->http;
    HttpRequest *new_request = NULL;
    HttpRequest *old_request = http->request;
    debug(85, 5) ("clientRedirectDone: '%s' result=%s\n", http->uri,
                  result ? result : "NULL");
    assert(context->redirect_state == REDIRECT_PENDING);
    context->redirect_state = REDIRECT_DONE;

    if (result) {
        http_status status = (http_status) atoi(result);

        if (status == HTTP_MOVED_PERMANENTLY
                || status == HTTP_MOVED_TEMPORARILY
                || status == HTTP_SEE_OTHER
                || status == HTTP_TEMPORARY_REDIRECT) {
            char *t = result;

            if ((t = strchr(result, ':')) != NULL) {
                http->redirect.status = status;
                http->redirect.location = xstrdup(t + 1);
            } else {
                debug(85, 1) ("clientRedirectDone: bad input: %s\n", result);
            }
        }

        if (strcmp(result, http->uri))
            new_request = urlParse(old_request->method, result);
    }

    if (new_request) {
        safe_free(http->uri);
        http->uri = xstrdup(urlCanonical(new_request));
        new_request->http_ver = old_request->http_ver;
        httpHeaderAppend(&new_request->header, &old_request->header);
        new_request->client_addr = old_request->client_addr;
        new_request->client_port = old_request->client_port;
        new_request->my_addr = old_request->my_addr;
        new_request->my_port = old_request->my_port;
        new_request->flags = old_request->flags;
        new_request->flags.redirected = 1;

        if (old_request->auth_user_request) {
            new_request->auth_user_request = old_request->auth_user_request;

            new_request->auth_user_request->lock()

            ;
        }

        if (old_request->body_connection.getRaw() != NULL) {
            new_request->body_connection = old_request->body_connection;
            old_request->body_connection = NULL;
        }

        new_request->content_length = old_request->content_length;
        new_request->extacl_user = old_request->extacl_user;
        new_request->extacl_passwd = old_request->extacl_passwd;
        new_request->flags.proxy_keepalive = old_request->flags.proxy_keepalive;
        requestUnlink(old_request);
        http->request = requestLink(new_request);
    }

    clientInterpretRequestHeaders(http);
#if HEADERS_LOG

    headersLog(0, 1, request->method, request);
#endif
    /* FIXME PIPELINE: This is innacurate during pipelining */

    if (http->getConn().getRaw() != NULL)
        fd_note(http->getConn()->fd, http->uri);

    assert(http->uri);

    context->checkNoCache();
}

void
ClientRequestContext::checkNoCache()
{
    if (Config.accessList.noCache && http->request->flags.cachable) {
        acl_checklist =
            clientAclChecklistCreate(Config.accessList.noCache, http);
        acl_checklist->nonBlockingCheck(CheckNoCacheDone, cbdataReference(this));
    } else {
        CheckNoCacheDone(http->request->flags.cachable, cbdataReference(this));
    }
}

void
ClientRequestContext::CheckNoCacheDone(int answer, void *data)
{
    void *temp;
#ifndef PURIFY

    bool valid =
#endif
        cbdataReferenceValidDone(data, &temp);
    /* acl NB calls cannot invalidate cbdata in the normal course of things */
    assert (valid);
    ClientRequestContext *context = (ClientRequestContext *)temp;
    context->checkNoCacheDone(answer);
}

void
ClientRequestContext::checkNoCacheDone(int answer)
{
    acl_checklist = NULL;
    ClientHttpRequest *http_ = http;

    if (!cbdataReferenceValid (http_)) {
        delete this;
        return;
    }

    delete this;
    http_->request->flags.cachable = answer;
    http_->processRequest();
}

/*
 * Identify requests that do not go through the store and client side stream
 * and forward them to the appropriate location. All other requests, request
 * them.
 */
void
ClientHttpRequest::processRequest()
{
    debug(85, 4) ("clientProcessRequest: %s '%s'\n",
                  RequestMethodStr[request->method], uri);

    if (request->method == METHOD_CONNECT) {
        logType = LOG_TCP_MISS;
        sslStart(this, &out.size, &al.http.code);
        return;
    }

    httpStart();
}

void
ClientHttpRequest::httpStart()
{
    logType = LOG_TAG_NONE;
    debug(85, 4) ("ClientHttpRequest::httpStart: %s for '%s'\n",
                  log_tags[logType], uri);
    /* no one should have touched this */
    assert(out.offset == 0);
    /* Use the Stream Luke */
    clientStreamNode *node = (clientStreamNode *)client_stream.tail->data;
    clientStreamRead(node, this, node->readBuffer);
}

bool
ClientHttpRequest::gotEnough() const
{
    /** TODO: should be querying the stream. */
    int contentLength =
        httpReplyBodySize(request->method, memObject()->getReply());
    assert(contentLength >= 0);

    if (out.offset < contentLength)
        return false;

    return true;
}

void
ClientHttpRequest::maxReplyBodySize(ssize_t clen)
{
    maxReplyBodySize_ = clen;
}

ssize_t
ClientHttpRequest::maxReplyBodySize() const
{
    return maxReplyBodySize_;
}

bool
ClientHttpRequest::isReplyBodyTooLarge(ssize_t clen) const
{
    if (0 == maxReplyBodySize())
        return 0;	/* disabled */

    if (clen < 0)
        return 0;	/* unknown */

    return clen > maxReplyBodySize();
}

void
ClientHttpRequest::storeEntry(StoreEntry *newEntry)
{
    entry_ = newEntry;
}

void
ClientHttpRequest::loggingEntry(StoreEntry *newEntry)
{
    if (loggingEntry_)
        storeUnlockObject(loggingEntry_);

    loggingEntry_ = newEntry;

    if (loggingEntry_)
        storeLockObject(loggingEntry_);
}

#ifndef _USE_INLINE_
#include "client_side_request.cci"
#endif
