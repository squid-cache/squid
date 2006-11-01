
/*
 * $Id: client_side_request.cc,v 1.77 2006/10/31 23:30:57 wessels Exp $
 * 
 * DEBUG: section 85    Client-side Request Routines
 * AUTHOR: Robert Collins (Originally Duane Wessels in client_side.c)
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
#include "ClientRequestContext.h"
#include "SquidTime.h"
#include "wordlist.h"

#if ICAP_CLIENT
#include "ICAP/ICAPClientReqmodPrecache.h"
#include "ICAP/ICAPElements.h"
#include "ICAP/ICAPConfig.h"
static void icapAclCheckDoneWrapper(ICAPServiceRep::Pointer service, void *data);
extern ICAPConfig TheICAPConfig;
#endif

#if LINGERING_CLOSE
#define comm_close comm_lingering_close
#endif

static const char *const crlf = "\r\n";

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
static void clientAccessCheckDoneWrapper(int, void *);
static int clientHierarchical(ClientHttpRequest * http);
static void clientInterpretRequestHeaders(ClientHttpRequest * http);
static RH clientRedirectDoneWrapper;
static PF checkNoCacheDoneWrapper;
extern "C" CSR clientGetMoreData;
extern "C" CSS clientReplyStatus;
extern "C" CSD clientReplyDetach;
static void checkFailureRatio(err_type, hier_code);

ClientRequestContext::~ClientRequestContext()
{
    /*
     * Release our "lock" on our parent, ClientHttpRequest, if we
     * still have one
     */

    if (http)
        cbdataReferenceDone(http);

    if (acl_checklist) {
        if (acl_checklist->asyncInProgress()) {
            acl_checklist->markDeleteWhenDone();
        } else {
            delete acl_checklist;
        }
    }

    debugs(85,3, HERE << this << " ClientHttpRequest destructed");
}

ClientRequestContext::ClientRequestContext(ClientHttpRequest *anHttp) : http(cbdataReference(anHttp)), acl_checklist (NULL), redirect_state (REDIRECT_NONE)
{
    http_access_done = false;
    redirect_done = false;
    no_cache_done = false;
    interpreted_req_hdrs = false;
    debugs(85,3, HERE << this << " ClientRequestContext constructed");
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

ClientHttpRequest::ClientHttpRequest(ConnStateData::Pointer aConn) : loggingEntry_(NULL)
{
    start = current_time;
    setConn(aConn);
    dlinkAdd(this, &active, &ClientActiveRequests);
#if ICAP_CLIENT

    request_satisfaction_mode = false;
#endif
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
    PROF_start(httpRequestFree);
    /* if body_connection !NULL, then ProcessBody has not
     * found the end of the body yet
     */

    if (request && request->body_reader != NULL) {
        request->body_reader = NULL;	// refcounted, triggers abort if needed.
        debugs(32, 3, HERE << "setting body_reader = NULL for request " << request);
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

#if ICAP_CLIENT
    if (icap)
        delete icap;
#endif
    if (calloutContext)
        delete calloutContext;

    /* moving to the next connection is handled by the context free */
    dlinkDelete(&active, &ClientActiveRequests);
    PROF_stop(httpRequestFree);
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
    ClientHttpRequest *http = new ClientHttpRequest(NULL);
    HttpRequest *request;
    StoreIOBuffer tempBuffer;
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
    /* Set flags */
    /* internal requests only makes sense in an
     * accelerator today. TODO: accept flags ? */
    http->flags.accel = 1;
    /* allow size for url rewriting */
    url_sz = strlen(url) + Config.appendDomainLen + 5;
    http->uri = (char *)xcalloc(url_sz, 1);
    strcpy(http->uri, url);

    if ((request = HttpRequest::CreateFromUrlAndMethod(http->uri, method)) == NULL) {
        debug(85, 5) ("Invalid URL: %s\n", http->uri);
        return -1;
    }

    /*
     * now update the headers in request with our supplied headers. urLParse
     * should return a blank header set, but we use Update to be sure of
     * correctness.
     */
    if (header)
        request->header.update(header, NULL);

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

    http->request = HTTPMSGLOCK(request);

    /* optional - skip the access check ? */
    http->calloutContext = new ClientRequestContext(http);

    http->calloutContext->http_access_done = false;

    http->calloutContext->redirect_done = true;

    http->calloutContext->no_cache_done = true;

    http->doCallouts();

    return 0;
}

bool
ClientRequestContext::httpStateIsValid()
{
    ClientHttpRequest *http_ = http;

    if (cbdataReferenceValid(http_))
        return true;

    http = NULL;

    cbdataReferenceDone(http_);

    return false;
}

/* This is the entry point for external users of the client_side routines */
void
ClientRequestContext::clientAccessCheck()
{
    acl_checklist =
        clientAclChecklistCreate(Config.accessList.http, http);
    acl_checklist->nonBlockingCheck(clientAccessCheckDoneWrapper, this);
}

void
clientAccessCheckDoneWrapper(int answer, void *data)
{
    ClientRequestContext *calloutContext = (ClientRequestContext *) data;

    if (!calloutContext->httpStateIsValid())
        return;

    calloutContext->clientAccessCheckDone(answer);
}

void
ClientRequestContext::clientAccessCheckDone(int answer)
{
    acl_checklist = NULL;
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

    if (answer != ACCESS_ALLOWED) {
        /* Send an error */
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

        clientStreamNode *node = (clientStreamNode *)http->client_stream.tail->prev->data;
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
        return;
    }

    /* ACCESS_ALLOWED continues here ... */
    safe_free(http->uri);

    http->uri = xstrdup(urlCanonical(http->request));

    http->doCallouts();
}

#if ICAP_CLIENT
void
ClientRequestContext::icapAccessCheck()
{
    ICAPAccessCheck *icap_access_check;

    icap_access_check = new ICAPAccessCheck(ICAP::methodReqmod, ICAP::pointPreCache, http->request, NULL, icapAclCheckDoneWrapper, this);

    if (icap_access_check != NULL) {
        icap_access_check->check();
        return;
    }

    http->doCallouts();
}

static void
icapAclCheckDoneWrapper(ICAPServiceRep::Pointer service, void *data)
{
    ClientRequestContext *calloutContext = (ClientRequestContext *)data;

    if (!calloutContext->httpStateIsValid())
        return;

    calloutContext->icapAclCheckDone(service);
}

void
ClientRequestContext::icapAclCheckDone(ICAPServiceRep::Pointer service)
{
    debugs(93,3,HERE << this << " icapAclCheckDone called");
    /*
     * No matching ICAP service in the config file
     */

    if (service == NULL) {
        http->doCallouts();
        return;
    }

    /*
     * Setup ICAP state and such.  If successful, just return.
     * We'll get back to doCallouts() after REQMOD is done.
     */
    assert(http);

    if (0 == http->doIcap(service))
        return;

    /*
     * If doIcap() fails, then we have to either return an error
     * to the user, or keep going without ICAP.
     */
    fatal("Fix this case in ClientRequestContext::icapAclCheckDone()");
    // And when fixed, check whether the service is down in doIcap and
    // if it is, abort early, without creating ICAPClientReqmodPrecache.
    // See Server::startIcap() and its use.

    http->doCallouts();
}

#endif

static void
clientRedirectAccessCheckDone(int answer, void *data)
{
    ClientRequestContext *context = (ClientRequestContext *)data;
    ClientHttpRequest *http = context->http;
    context->acl_checklist = NULL;

    if (answer == ACCESS_ALLOWED)
        redirectStart(http, clientRedirectDoneWrapper, context);
    else
        context->clientRedirectDone(NULL);
}

void
ClientRequestContext::clientRedirectStart()
{
    debug(33, 5) ("clientRedirectStart: '%s'\n", http->uri);

    if (Config.accessList.redirector) {
        acl_checklist = clientAclChecklistCreate(Config.accessList.redirector, http);
        acl_checklist->nonBlockingCheck(clientRedirectAccessCheckDone, this);
    } else
        redirectStart(http, clientRedirectDoneWrapper, this);
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
     * (they can even be cached if the correct headers are set on the reply)
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
    HttpHeader *req_hdr = &request->header;
    int no_cache = 0;
#if !(ESI) || defined(USE_USERAGENT_LOG) || defined(USE_REFERER_LOG)

    const char *str;
#endif

    request->imslen = -1;
    request->ims = req_hdr->getTime(HDR_IF_MODIFIED_SINCE);

    if (request->ims > 0)
        request->flags.ims = 1;

#if ESI
    /*
     * We ignore Cache-Control as per the Edge Architecture Section 3. See
     * www.esi.org for more information.
     */
#else

    if (req_hdr->has(HDR_PRAGMA)) {
        String s = req_hdr->getList(HDR_PRAGMA);

        if (strListIsMember(&s, "no-cache", ','))
            no_cache++;

        s.clean();
    }

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
            if ((str = req_hdr->getStr(HDR_USER_AGENT))) {
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

    /* ignore range header in non-GETs or non-HEADs */
    if (request->method == METHOD_GET || request->method == METHOD_HEAD) {
        request->range = req_hdr->getRange();

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

    /* Only HEAD and GET requests permit a Range or Request-Range header.
     * If these headers appear on any other type of request, delete them now.
     */
    else {
        req_hdr->delById(HDR_RANGE);
        req_hdr->delById(HDR_REQUEST_RANGE);
        request->range = NULL;
    }

    if (req_hdr->has(HDR_AUTHORIZATION))
        request->flags.auth = 1;

    if (request->login[0] != '\0')
        request->flags.auth = 1;

    if (req_hdr->has(HDR_VIA)) {
        String s = req_hdr->getList(HDR_VIA);
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
    if ((str = req_hdr->getStr(HDR_USER_AGENT)))
        logUserAgent(fqdnFromAddr(http->getConn().getRaw() ? http->getConn()->log_addr : no_addr), str);

#endif
#if USE_REFERER_LOG

    if ((str = req_hdr->getStr(HDR_REFERER)))
        logReferer(fqdnFromAddr(http->getConn().getRaw() ? http->getConn()->log_addr : no_addr), str, http->log_uri);

#endif
#if FORW_VIA_DB

    if (req_hdr->has(HDR_X_FORWARDED_FOR)) {
        String s = req_hdr->getList(HDR_X_FORWARDED_FOR);
        fvdbCountForw(s.buf());
        s.clean();
    }

#endif
    if (request->method == METHOD_TRACE) {
        request->max_forwards = req_hdr->getInt(HDR_MAX_FORWARDS);
    }

    request->flags.cachable = http->request->cacheable();

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
clientRedirectDoneWrapper(void *data, char *result)
{
    ClientRequestContext *calloutContext = (ClientRequestContext *)data;

    if (!calloutContext->httpStateIsValid())
        return;

    calloutContext->clientRedirectDone(result);
}

void
ClientRequestContext::clientRedirectDone(char *result)
{
    HttpRequest *new_request = NULL;
    HttpRequest *old_request = http->request;
    debug(85, 5) ("clientRedirectDone: '%s' result=%s\n", http->uri,
                  result ? result : "NULL");
    assert(redirect_state == REDIRECT_PENDING);
    redirect_state = REDIRECT_DONE;

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
        } else if (strcmp(result, http->uri))
            new_request = HttpRequest::CreateFromUrlAndMethod(result, old_request->method);
    }

    if (new_request) {
        safe_free(http->uri);
        http->uri = xstrdup(urlCanonical(new_request));
        new_request->http_ver = old_request->http_ver;
        new_request->header.append(&old_request->header);
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

        if (old_request->body_reader != NULL) {
            new_request->body_reader = old_request->body_reader;
            old_request->body_reader = NULL;
            debugs(0,0,HERE << "setting body_reader = NULL for request " << old_request);
        }

        new_request->content_length = old_request->content_length;
        new_request->extacl_user = old_request->extacl_user;
        new_request->extacl_passwd = old_request->extacl_passwd;
        new_request->flags.proxy_keepalive = old_request->flags.proxy_keepalive;
        HTTPMSGUNLOCK(old_request);
        http->request = HTTPMSGLOCK(new_request);
    }

    /* FIXME PIPELINE: This is innacurate during pipelining */

    if (http->getConn().getRaw() != NULL)
        fd_note(http->getConn()->fd, http->uri);

    assert(http->uri);

    http->doCallouts();
}

void
ClientRequestContext::checkNoCache()
{
    acl_checklist = clientAclChecklistCreate(Config.accessList.noCache, http);
    acl_checklist->nonBlockingCheck(checkNoCacheDoneWrapper, this);
}

static void
checkNoCacheDoneWrapper(int answer, void *data)
{
    ClientRequestContext *calloutContext = (ClientRequestContext *) data;

    if (!calloutContext->httpStateIsValid())
        return;

    calloutContext->checkNoCacheDone(answer);
}

void
ClientRequestContext::checkNoCacheDone(int answer)
{
    acl_checklist = NULL;
    http->request->flags.cachable = answer;
    http->doCallouts();
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

    if (request->method == METHOD_CONNECT && !redirect.status) {
        logType = LOG_TCP_MISS;
        sslStart(this, &out.size, &al.http.code);
        return;
    }

    httpStart();
}

void
ClientHttpRequest::httpStart()
{
    PROF_start(httpStart);
    logType = LOG_TAG_NONE;
    debug(85, 4) ("ClientHttpRequest::httpStart: %s for '%s'\n",
                  log_tags[logType], uri);
    /* no one should have touched this */
    assert(out.offset == 0);
    /* Use the Stream Luke */
    clientStreamNode *node = (clientStreamNode *)client_stream.tail->data;
    clientStreamRead(node, this, node->readBuffer);
    PROF_stop(httpStart);
}

bool
ClientHttpRequest::gotEnough() const
{
    /** TODO: should be querying the stream. */
    int contentLength =
        memObject()->getReply()->bodySize(request->method);
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
        loggingEntry_->unlock();

    loggingEntry_ = newEntry;

    if (loggingEntry_)
        loggingEntry_->lock()

        ;
}

/*
 * doCallouts() - This function controls the order of "callout"
 * executions, including non-blocking access control checks, the
 * redirector, and ICAP.  Previously, these callouts were chained
 * together such that "clientAccessCheckDone()" would call
 * "clientRedirectStart()" and so on.
 *
 * The ClientRequestContext (aka calloutContext) class holds certain
 * state data for the callout/callback operations.  Previously
 * ClientHttpRequest would sort of hand off control to ClientRequestContext
 * for a short time.  ClientRequestContext would then delete itself
 * and pass control back to ClientHttpRequest when all callouts
 * were finished.
 *
 * This caused some problems for ICAP because we want to make the
 * ICAP callout after checking ACLs, but before checking the no_cache
 * list.  We can't stuff the ICAP state into the ClientRequestContext
 * class because we still need the ICAP state after ClientRequestContext
 * goes away.
 *
 * Note that ClientRequestContext is created before the first call
 * to doCallouts().
 *
 * If one of the callouts notices that ClientHttpRequest is no
 * longer valid, it should call cbdataReferenceDone() so that
 * ClientHttpRequest's reference count goes to zero and it will get
 * deleted.  ClientHttpRequest will then delete ClientRequestContext.
 *
 * Note that we set the _done flags here before actually starting
 * the callout.  This is strictly for convenience.
 */

void
ClientHttpRequest::doCallouts()
{
    assert(calloutContext);

    if (!calloutContext->http_access_done) {
        calloutContext->http_access_done = true;
        calloutContext->clientAccessCheck();
        return;
    }

#if ICAP_CLIENT
    if (TheICAPConfig.onoff && !calloutContext->icap_acl_check_done) {
        calloutContext->icap_acl_check_done = true;
        calloutContext->icapAccessCheck();
        return;
    }

#endif

    if (!calloutContext->redirect_done) {
        calloutContext->redirect_done = true;
        assert(calloutContext->redirect_state == REDIRECT_NONE);

        if (Config.Program.redirect) {
            calloutContext->redirect_state = REDIRECT_PENDING;
            calloutContext->clientRedirectStart();
            return;
        }
    }

    if (!calloutContext->interpreted_req_hdrs) {
        calloutContext->interpreted_req_hdrs = 1;
        clientInterpretRequestHeaders(this);
    }

    if (!calloutContext->no_cache_done) {
        calloutContext->no_cache_done = true;

        if (Config.accessList.noCache && request->flags.cachable) {
            calloutContext->checkNoCache();
            return;
        }
    }

    cbdataReferenceDone(calloutContext->http);
    delete calloutContext;
    calloutContext = NULL;
#if HEADERS_LOG

    headersLog(0, 1, request->method, request);
#endif

    processRequest();
}

#ifndef _USE_INLINE_
#include "client_side_request.cci"
#endif

#if ICAP_CLIENT
/*
 * Initiate an ICAP transaction.  Return 0 if all is well, or -1 upon error.
 * Caller will handle error condition by generating a Squid error message
 * or take other action.
 */
int
ClientHttpRequest::doIcap(ICAPServiceRep::Pointer service)
{
    debugs(85, 3, HERE << this << " ClientHttpRequest::doIcap() called");
    assert(NULL == icap);
    icap = new ICAPClientReqmodPrecache(service);
    icap->startReqMod(this, request);

    if (request->body_reader == NULL) {
        debugs(32, 3, HERE << "client request hasnt body...");
        icap->doneSending();

    }

    return 0;
}

/*
 * icapSendRequestBodyWrapper
 *
 * A callback wrapper for ::icapSendRequestBody()
 *
 * icapSendRequestBodyWrapper is of type CBCB
 */
void
ClientHttpRequest::icapSendRequestBodyWrapper(MemBuf &mb, void *data)
{
    ClientHttpRequest *chr = static_cast<ClientHttpRequest*>(data);
    chr->icapSendRequestBody(mb);
}


/*
 * icapSendRequestBody
 *
 * Sends some chunk of a request body to the ICAP side.  Must make sure
 * that the ICAP-side can accept the data we have.  If there is more
 * body data to read, then schedule another BodyReader callback.
 */
void
ClientHttpRequest::icapSendRequestBody(MemBuf &mb)
{
    ssize_t size_to_send  = mb.contentSize();
    debugs(32,3,HERE << "have " << mb.contentSize() << " bytes in mb");

    if (size_to_send == 0) {
        /*
         * An error occurred during this transaction.  Tell ICAP that we're done.
         */

        if (icap)
            icap->doneSending();

        return;
    }

    debugs(32,3,HERE << "icap->potentialSpaceSize() = " << icap->potentialSpaceSize());

    if (size_to_send > icap->potentialSpaceSize())
        size_to_send = icap->potentialSpaceSize();

    if (size_to_send) {
        debugs(32,3,HERE << "sending " << size_to_send << " body bytes to ICAP");
        StoreIOBuffer sbuf(size_to_send, 0, mb.content());
        icap->sendMoreData(sbuf);
        icap->body_reader->consume(size_to_send);
        icap->body_reader->bytes_read += size_to_send;
        debugs(32,3," HTTP client body bytes_read=" << icap->body_reader->bytes_read);
    } else {
        debugs(32,2,HERE << "cannot send body data to ICAP");
        debugs(32,2,HERE << "\tBodyReader MemBuf has " << mb.contentSize());
        debugs(32,2,HERE << "\tbut icap->potentialSpaceSize() is " << icap->potentialSpaceSize());
        return;
    }

    /*
     * If we sent some data this time, and there is more data to
     * read, then schedule another read request via BodyReader.
     */
    if (size_to_send && icap->body_reader->remaining()) {
        debugs(32,3,HERE << "calling body_reader->read()");
        icap->body_reader->read(icapSendRequestBodyWrapper, this);
    } else {
        debugs(32,3,HERE << "No more request body bytes to send");
        icap->doneSending();
    }
}

/*
 * Called by ICAPAnchor when it has space available for us.
 */
void
ClientHttpRequest::icapSpaceAvailable()
{
    debugs(85,3,HERE << this << " ClientHttpRequest::icapSpaceAvailable() called\n");

    if (request->body_reader != NULL && icap->body_reader == NULL) {
        debugs(32,3,HERE << "reassigning HttpRequest->body_reader to ICAP");
        /*
         * ICAP hooks on to the BodyReader that gets data from
         * ConnStateData.  We'll make a new BodyReader that
         * HttpStateData can use if the adapted response has a
         * request body.  See ICAPClientReqmodPrecache::noteSourceStart()
         */
        icap->body_reader = request->body_reader;
        request->body_reader = NULL;
    }

    if (icap->body_reader == NULL)
        return;

    if (icap->body_reader->callbackPending())
        return;

    debugs(32,3,HERE << "Calling read() for body data");

    icap->body_reader->read(icapSendRequestBodyWrapper, this);
}

void
ClientHttpRequest::takeAdaptedHeaders(HttpMsg *msg)
{
    debug(85,3)("ClientHttpRequest::takeAdaptedHeaders() called\n");
    assert(cbdataReferenceValid(this));		// indicates bug

    if (HttpRequest *new_req = dynamic_cast<HttpRequest*>(msg)) {
        /*
         * Replace the old request with the new request.  First,
         * Move the "body_connection" over, then unlink old and
         * link new to the http state.
         */
        HTTPMSGUNLOCK(request);
        request = HTTPMSGLOCK(new_req);
        /*
         * Store the new URI for logging
         */
        xfree(uri);
        uri = xstrdup(urlCanonical(request));
        setLogUri(this, urlCanonicalClean(request));
        assert(request->method);
    } else if (HttpReply *new_rep = dynamic_cast<HttpReply*>(msg)) {
        debugs(85,3,HERE << "REQMOD reply is HTTP reply");

        clientStreamNode *node = (clientStreamNode *)client_stream.tail->prev->data;
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        repContext->createStoreEntry(request->method, request->flags);

        EBIT_CLR(storeEntry()->flags, ENTRY_FWD_HDR_WAIT);
        request_satisfaction_mode = true;
        request_satisfaction_offset = 0;
        storeEntry()->replaceHttpReply(new_rep);
        clientGetMoreData(node, this);
    }

    if (!request_satisfaction_mode)
        doCallouts();

    debug(85,3)("ClientHttpRequest::takeAdaptedHeaders() finished\n");
}

void
ClientHttpRequest::takeAdaptedBody(MemBuf *buf)
{
    debug(85,3)("ClientHttpRequest::takeAdaptedBody() called\n");

    if (request_satisfaction_mode) {
        storeEntry()->write(StoreIOBuffer(buf, request_satisfaction_offset));
        request_satisfaction_offset += buf->contentSize();
        buf->consume(buf->contentSize()); // consume everything written
    } else {
        debug(85,0)("Unexpected call to takeAdaptedBody when "
                    "not in request_satisfaction_mode");
    }
}

void
ClientHttpRequest::doneAdapting()
{
    debug(85,3)("ClientHttpRequest::doneAdapting() called\n");
}

void
ClientHttpRequest::abortAdapting()
{
    debug(85,3)("ClientHttpRequest::abortAdapting() called\n");

    if ((NULL == storeEntry()) || storeEntry()->isEmpty()) {
        debug(85,3)("WARNING: ICAP REQMOD callout failed, proceeding with original request\n");

        if (calloutContext)
            doCallouts();

#if ICAP_HARD_ERROR

        clientStreamNode *node = (clientStreamNode *)client_stream.tail->prev->data;

        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());

        assert (repContext);

        // Note if this code is ever used, clientBuildError() should be modified to
        // accept an errno arg
        repContext->setReplyToError(ERR_ICAP_FAILURE, HTTP_INTERNAL_SERVER_ERROR,
                                    request->method, NULL,
                                    getConn().getRaw() != NULL ? &getConn()->peer.sin_addr : &no_addr, request,
                                    NULL, getConn().getRaw() != NULL
                                    && getConn()->auth_user_request ? getConn()->
                                    auth_user_request : request->auth_user_request, errno);

        node = (clientStreamNode *)client_stream.tail->data;

        clientStreamRead(node, this, node->readBuffer);

#endif

        return;
    }

    debug(0,0)("write me at %s:%d\n", __FILE__,__LINE__);
}

#endif
