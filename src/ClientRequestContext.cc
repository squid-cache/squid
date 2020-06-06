/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 85    Client-side Request Routines */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "cbdata.h"
#include "client_side_reply.h"
#include "client_side_request.h"
#include "ClientRequestContext.h"
#include "comm/forward.h"
#include "errorpage.h"
#include "fd.h"
#include "helper/ResultCode.h"
#include "http/Stream.h"
#include "redirect.h"
#include "SquidConfig.h"

CBDATA_CLASS_INIT(ClientRequestContext);

static void clientRedirectDoneWrapper(void *data, const Helper::Reply &result);
static void clientStoreIdDoneWrapper(void *data, const Helper::Reply &result);

ClientRequestContext::~ClientRequestContext()
{
    /*
     * Release our "lock" on our parent, ClientHttpRequest, if we
     * still have one
     */

    cbdataReferenceDone(http);

    delete error;
    debugs(85,3, "ClientRequestContext destructed, this=" << this);
}

ClientRequestContext::ClientRequestContext(ClientHttpRequest *anHttp) :
    http(cbdataReference(anHttp))
{
    debugs(85, 3, "ClientRequestContext constructed, this=" << this);
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

void
ClientRequestContext::hostHeaderIpVerify(const ipcache_addrs* ia, const Dns::LookupDetails &dns)
{
    Comm::ConnectionPointer clientConn = http->getConn()->clientConnection;

    // note the DNS details for the transaction stats.
    http->request->recordLookup(dns);

    // Is the NAT destination IP in DNS?
    if (ia && ia->have(clientConn->local)) {
        debugs(85, 3, "validate IP " << clientConn->local << " possible from Host:");
        http->request->flags.hostVerified = true;
        http->doCallouts();
        return;
    }
    debugs(85, 3, HERE << "FAIL: validate IP " << clientConn->local << " possible from Host:");
    hostHeaderVerifyFailed("local IP", "any domain IP");
}

static void
hostHeaderIpVerifyWrapper(const ipcache_addrs *ia, const Dns::LookupDetails &dns, void *data)
{
    ClientRequestContext *c = static_cast<ClientRequestContext *>(data);
    c->hostHeaderIpVerify(ia, dns);
}

void
ClientRequestContext::hostHeaderVerify()
{
    // Require a Host: header.
    const char *host = http->request->header.getStr(Http::HdrType::HOST);

    if (!host) {
        // TODO: dump out the HTTP/1.1 error about missing host header.
        // otherwise this is fine, can't forge a header value when its not even set.
        debugs(85, 3, HERE << "validate skipped with no Host: header present.");
        http->doCallouts();
        return;
    }

    if (http->request->flags.internal) {
        // TODO: kill this when URL handling allows partial URLs out of accel mode
        //       and we no longer screw with the URL just to add our internal host there
        debugs(85, 6, HERE << "validate skipped due to internal composite URL.");
        http->doCallouts();
        return;
    }

    // Locate if there is a port attached, strip ready for IP lookup
    char *portStr = NULL;
    char *hostB = xstrdup(host);
    host = hostB;
    if (host[0] == '[') {
        // IPv6 literal.
        portStr = strchr(hostB, ']');
        if (portStr && *(++portStr) != ':') {
            portStr = NULL;
        }
    } else {
        // Domain or IPv4 literal with port
        portStr = strrchr(hostB, ':');
    }

    uint16_t port = 0;
    if (portStr) {
        *portStr = '\0'; // strip the ':'
        if (*(++portStr) != '\0') {
            char *end = NULL;
            int64_t ret = strtoll(portStr, &end, 10);
            if (end == portStr || *end != '\0' || ret < 1 || ret > 0xFFFF) {
                // invalid port details. Replace the ':'
                *(--portStr) = ':';
                portStr = NULL;
            } else
                port = (ret & 0xFFFF);
        }
    }

    debugs(85, 3, "validate host=" << host << ", port=" << port << ", portStr=" << (portStr?portStr:"NULL"));
    if (http->request->flags.intercepted || http->request->flags.interceptTproxy) {
        // verify the Host: port (if any) matches the apparent destination
        if (portStr && port != http->getConn()->clientConnection->local.port()) {
            debugs(85, 3, "FAIL on validate port " << http->getConn()->clientConnection->local.port() <<
                   " matches Host: port " << port << " (" << portStr << ")");
            hostHeaderVerifyFailed("intercepted port", portStr);
        } else {
            // XXX: match the scheme default port against the apparent destination

            // verify the destination DNS is one of the Host: headers IPs
            ipcache_nbgethostbyname(host, hostHeaderIpVerifyWrapper, this);
        }
    } else if (!Config.onoff.hostStrictVerify) {
        debugs(85, 3, "validate skipped.");
        http->doCallouts();
    } else if (strlen(host) != strlen(http->request->url.host())) {
        // Verify forward-proxy requested URL domain matches the Host: header
        debugs(85, 3, "FAIL on validate URL domain length " << http->request->url.host() << " matches Host: " << host);
        hostHeaderVerifyFailed(host, http->request->url.host());
    } else if (matchDomainName(host, http->request->url.host()) != 0) {
        // Verify forward-proxy requested URL domain matches the Host: header
        debugs(85, 3, "FAIL on validate URL domain " << http->request->url.host() << " matches Host: " << host);
        hostHeaderVerifyFailed(host, http->request->url.host());
    } else if (portStr && port != http->request->url.port()) {
        // Verify forward-proxy requested URL domain matches the Host: header
        debugs(85, 3, "FAIL on validate URL port " << http->request->url.port() << " matches Host: port " << portStr);
        hostHeaderVerifyFailed("URL port", portStr);
    } else if (!portStr && http->request->method != Http::METHOD_CONNECT && http->request->url.port() != http->request->url.getScheme().defaultPort()) {
        // Verify forward-proxy requested URL domain matches the Host: header
        // Special case: we don't have a default-port to check for CONNECT. Assume URL is correct.
        debugs(85, 3, "FAIL on validate URL port " << http->request->url.port() << " matches Host: default port " << http->request->url.getScheme().defaultPort());
        hostHeaderVerifyFailed("URL port", "default port");
    } else {
        // Okay no problem.
        debugs(85, 3, "validate passed.");
        http->request->flags.hostVerified = true;
        http->doCallouts();
    }
    safe_free(hostB);
}

#if FOLLOW_X_FORWARDED_FOR
/**
 * clientFollowXForwardedForCheck() checks the content of X-Forwarded-For:
 * against the followXFF ACL, or cleans up and passes control to
 * clientAccessCheck().
 *
 * The trust model here is a little ambiguous. So to clarify the logic:
 * - we may always use the direct client address as the client IP.
 * - these trust tests merey tell whether we trust given IP enough to believe the
 *   IP string which it appended to the X-Forwarded-For: header.
 * - if at any point we don't trust what an IP adds we stop looking.
 * - at that point the current contents of indirect_client_addr are the value set
 *   by the last previously trusted IP.
 * ++ indirect_client_addr contains the remote direct client from the trusted peers viewpoint.
 */
static void
clientFollowXForwardedForCheck(Acl::Answer answer, void *data)
{
    ClientRequestContext *calloutContext = (ClientRequestContext *)data;

    if (!calloutContext->httpStateIsValid())
        return;

    ClientHttpRequest *http = calloutContext->http;
    HttpRequest *request = http->request;

    if (answer.allowed() && request->x_forwarded_for_iterator.size() != 0) {

        /*
         * Remove the last comma-delimited element from the
         * x_forwarded_for_iterator and use it to repeat the cycle.
         */
        const char *p;
        const char *asciiaddr;
        int l;
        Ip::Address addr;
        p = request->x_forwarded_for_iterator.termedBuf();
        l = request->x_forwarded_for_iterator.size();

        /*
        * XXX x_forwarded_for_iterator should really be a list of
        * IP addresses, but it's a String instead.  We have to
        * walk backwards through the String, biting off the last
        * comma-delimited part each time.  As long as the data is in
        * a String, we should probably implement and use a variant of
        * strListGetItem() that walks backwards instead of forwards
        * through a comma-separated list.  But we don't even do that;
        * we just do the work in-line here.
        */
        /* skip trailing space and commas */
        while (l > 0 && (p[l - 1] == ',' || xisspace(p[l - 1])))
            --l;
        request->x_forwarded_for_iterator.cut(l);
        /* look for start of last item in list */
        while (l > 0 && !(p[l - 1] == ',' || xisspace(p[l - 1])))
            --l;
        asciiaddr = p + l;
        if ((addr = asciiaddr)) {
            request->indirect_client_addr = addr;
            request->x_forwarded_for_iterator.cut(l);
            calloutContext->acl_checklist = clientAclChecklistCreate(Config.accessList.followXFF, http);
            if (!Config.onoff.acl_uses_indirect_client) {
                /* override the default src_addr tested if we have to go deeper than one level into XFF */
                Filled(calloutContext->acl_checklist)->src_addr = request->indirect_client_addr;
            }
            calloutContext->acl_checklist->nonBlockingCheck(clientFollowXForwardedForCheck, data);
            return;
        }
    }

    /* clean up, and pass control to clientAccessCheck */
    if (Config.onoff.log_uses_indirect_client) {
        /*
        * Ensure that the access log shows the indirect client
        * instead of the direct client.
        */
        http->al->cache.caddr = request->indirect_client_addr;
        if (ConnStateData *conn = http->getConn())
            conn->log_addr = request->indirect_client_addr;
    }
    request->x_forwarded_for_iterator.clean();
    request->flags.done_follow_x_forwarded_for = true;

    if (answer.conflicted()) {
        debugs(28, DBG_CRITICAL, "ERROR: Processing X-Forwarded-For. Stopping at IP address: " << request->indirect_client_addr);
    }

    /* process actual access ACL as normal. */
    calloutContext->clientAccessCheck();
}
#endif /* FOLLOW_X_FORWARDED_FOR */

static void
clientAccessCheckDoneWrapper(Acl::Answer answer, void *data)
{
    ClientRequestContext *calloutContext = (ClientRequestContext *)data;

    if (!calloutContext->httpStateIsValid())
        return;

    calloutContext->clientAccessCheckDone(answer);
}

/* This is the entry point for external users of the client_side routines */
void
ClientRequestContext::clientAccessCheck()
{
#if FOLLOW_X_FORWARDED_FOR
    if (!http->request->flags.doneFollowXff() &&
            Config.accessList.followXFF &&
            http->request->header.has(Http::HdrType::X_FORWARDED_FOR)) {

        /* we always trust the direct client address for actual use */
        http->request->indirect_client_addr = http->request->client_addr;
        http->request->indirect_client_addr.port(0);

        /* setup the XFF iterator for processing */
        http->request->x_forwarded_for_iterator = http->request->header.getList(Http::HdrType::X_FORWARDED_FOR);

        /* begin by checking to see if we trust direct client enough to walk XFF */
        acl_checklist = clientAclChecklistCreate(Config.accessList.followXFF, http);
        acl_checklist->nonBlockingCheck(clientFollowXForwardedForCheck, this);
        return;
    }
#endif

    if (Config.accessList.http) {
        acl_checklist = clientAclChecklistCreate(Config.accessList.http, http);
        acl_checklist->nonBlockingCheck(clientAccessCheckDoneWrapper, this);
    } else {
        debugs(0, DBG_CRITICAL, "No http_access configuration found. This will block ALL traffic");
        clientAccessCheckDone(ACCESS_DENIED);
    }
}

/**
 * Identical in operation to clientAccessCheck() but performed later using different configured ACL list.
 * The default here is to allow all. Since the earlier http_access should do a default deny all.
 * This check is just for a last-minute denial based on adapted request headers.
 */
void
ClientRequestContext::clientAccessCheck2()
{
    if (Config.accessList.adapted_http) {
        acl_checklist = clientAclChecklistCreate(Config.accessList.adapted_http, http);
        acl_checklist->nonBlockingCheck(clientAccessCheckDoneWrapper, this);
    } else {
        debugs(85, 2, HERE << "No adapted_http_access configuration. default: ALLOW");
        clientAccessCheckDone(ACCESS_ALLOWED);
    }
}

void
ClientRequestContext::hostHeaderVerifyFailed(const char *A, const char *B)
{
    // IP address validation for Host: failed. Admin wants to ignore them.
    // NP: we do not yet handle CONNECT tunnels well, so ignore for them
    if (!Config.onoff.hostStrictVerify && http->request->method != Http::METHOD_CONNECT) {
        debugs(85, 3, "SECURITY ALERT: Host header forgery detected on " << http->getConn()->clientConnection <<
               " (" << A << " does not match " << B << ") on URL: " << http->request->effectiveRequestUri());

        // NP: it is tempting to use 'flags.noCache' but that is all about READing cache data.
        // The problems here are about WRITE for new cache content, which means flags.cachable
        http->request->flags.cachable = false; // MUST NOT cache (for now)
        // XXX: when we have updated the cache key to base on raw-IP + URI this cacheable limit can go.
        http->request->flags.hierarchical = false; // MUST NOT pass to peers (for now)
        // XXX: when we have sorted out the best way to relay requests properly to peers this hierarchical limit can go.
        http->doCallouts();
        return;
    }

    debugs(85, DBG_IMPORTANT, "SECURITY ALERT: Host header forgery detected on " <<
           http->getConn()->clientConnection << " (" << A << " does not match " << B << ")");
    if (const char *ua = http->request->header.getStr(Http::HdrType::USER_AGENT))
        debugs(85, DBG_IMPORTANT, "SECURITY ALERT: By user agent: " << ua);
    debugs(85, DBG_IMPORTANT, "SECURITY ALERT: on URL: " << http->request->effectiveRequestUri());

    // IP address validation for Host: failed. reject the connection.
    clientStreamNode *node = (clientStreamNode *)http->client_stream.tail->prev->data;
    clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
    assert (repContext);
    repContext->setReplyToError(ERR_CONFLICT_HOST, Http::scConflict,
                                http->request->method, NULL,
                                http->getConn()->clientConnection->remote,
                                http->request,
                                NULL,
#if USE_AUTH
                                http->getConn() != NULL && http->getConn()->getAuth() != NULL ?
                                http->getConn()->getAuth() : http->request->auth_user_request);
#else
                                NULL);
#endif
    node = (clientStreamNode *)http->client_stream.tail->data;
    clientStreamRead(node, http, node->readBuffer);
}

void
ClientRequestContext::clientAccessCheckDone(const Acl::Answer &answer)
{
    acl_checklist = NULL;
    err_type page_id;
    Http::StatusCode status;
    debugs(85, 2, "The request " << http->request->method << ' ' <<
           http->uri << " is " << answer <<
           "; last ACL checked: " << (AclMatchedName ? AclMatchedName : "[none]"));

#if USE_AUTH
    char const *proxy_auth_msg = "<null>";
    if (http->getConn() != NULL && http->getConn()->getAuth() != NULL)
        proxy_auth_msg = http->getConn()->getAuth()->denyMessage("<null>");
    else if (http->request->auth_user_request != NULL)
        proxy_auth_msg = http->request->auth_user_request->denyMessage("<null>");
#endif

    if (!answer.allowed()) {
        // auth has a grace period where credentials can be expired but okay not to challenge.

        /* Send an auth challenge or error */
        // XXX: do we still need aclIsProxyAuth() ?
        bool auth_challenge = (answer == ACCESS_AUTH_REQUIRED || aclIsProxyAuth(AclMatchedName));
        debugs(85, 5, "Access Denied: " << http->uri);
        debugs(85, 5, "AclMatchedName = " << (AclMatchedName ? AclMatchedName : "<null>"));
#if USE_AUTH
        if (auth_challenge)
            debugs(33, 5, "Proxy Auth Message = " << (proxy_auth_msg ? proxy_auth_msg : "<null>"));
#endif

        /*
         * NOTE: get page_id here, based on AclMatchedName because if
         * USE_DELAY_POOLS is enabled, then AclMatchedName gets clobbered in
         * the clientCreateStoreEntry() call just below.  Pedro Ribeiro
         * <pribeiro@isel.pt>
         */
        page_id = aclGetDenyInfoPage(&Config.denyInfoList, AclMatchedName, answer != ACCESS_AUTH_REQUIRED);

        http->logType.update(LOG_TCP_DENIED);

        if (auth_challenge) {
#if USE_AUTH
            if (http->request->flags.sslBumped) {
                /*SSL Bumped request, authentication is not possible*/
                status = Http::scForbidden;
            } else if (!http->flags.accel) {
                /* Proxy authorisation needed */
                status = Http::scProxyAuthenticationRequired;
            } else {
                /* WWW authorisation needed */
                status = Http::scUnauthorized;
            }
#else
            // need auth, but not possible to do.
            status = Http::scForbidden;
#endif
            if (page_id == ERR_NONE)
                page_id = ERR_CACHE_ACCESS_DENIED;
        } else {
            status = Http::scForbidden;

            if (page_id == ERR_NONE)
                page_id = ERR_ACCESS_DENIED;
        }

        Ip::Address tmpnoaddr;
        tmpnoaddr.setNoAddr();
        error = new ErrorState(page_id, status,
                               NULL,
                               http->getConn() != NULL ? http->getConn()->clientConnection->remote : tmpnoaddr,
                               http->request, http->al);

#if USE_AUTH
        error->auth_user_request =
            http->getConn() != NULL && http->getConn()->getAuth() != NULL ?
            http->getConn()->getAuth() : http->request->auth_user_request;
#endif

        readNextRequest = true;
    }

    /* ACCESS_ALLOWED continues here ... */
    xfree(http->uri);
    http->uri = SBufToCstring(http->request->effectiveRequestUri());
    http->doCallouts();
}

static void
clientRedirectAccessCheckDone(Acl::Answer answer, void *data)
{
    ClientRequestContext *context = (ClientRequestContext *)data;
    ClientHttpRequest *http = context->http;
    context->acl_checklist = NULL;

    if (answer.allowed())
        redirectStart(http, clientRedirectDoneWrapper, context);
    else {
        Helper::Reply const nilReply(Helper::Error);
        context->clientRedirectDone(nilReply);
    }
}

void
ClientRequestContext::clientRedirectStart()
{
    debugs(33, 5, HERE << "'" << http->uri << "'");
    http->al->syncNotes(http->request);
    if (Config.accessList.redirector) {
        acl_checklist = clientAclChecklistCreate(Config.accessList.redirector, http);
        acl_checklist->nonBlockingCheck(clientRedirectAccessCheckDone, this);
    } else
        redirectStart(http, clientRedirectDoneWrapper, this);
}

static void
clientStoreIdDoneWrapper(void *data, const Helper::Reply &result)
{
    ClientRequestContext *calloutContext = (ClientRequestContext *)data;

    if (!calloutContext->httpStateIsValid())
        return;

    calloutContext->clientStoreIdDone(result);
}

static void
clientRedirectDoneWrapper(void *data, const Helper::Reply &result)
{
    ClientRequestContext *calloutContext = (ClientRequestContext *)data;

    if (!calloutContext->httpStateIsValid())
        return;

    calloutContext->clientRedirectDone(result);
}

/**
 * This methods handles Access checks result of StoreId access list.
 * Will handle as "ERR" (no change) in a case Access is not allowed.
 */
static void
clientStoreIdAccessCheckDone(Acl::Answer answer, void *data)
{
    ClientRequestContext *context = static_cast<ClientRequestContext *>(data);
    ClientHttpRequest *http = context->http;
    context->acl_checklist = NULL;

    if (answer.allowed())
        storeIdStart(http, clientStoreIdDoneWrapper, context);
    else {
        debugs(85, 3, "access denied expected ERR reply handling: " << answer);
        Helper::Reply const nilReply(Helper::Error);
        context->clientStoreIdDone(nilReply);
    }
}

/**
 * Start locating an alternative storage ID string (if any) from admin
 * configured helper program. This is an asynchronous operation terminating in
 * ClientRequestContext::clientStoreIdDone() when completed.
 */
void
ClientRequestContext::clientStoreIdStart()
{
    debugs(33, 5,"'" << http->uri << "'");

    if (Config.accessList.store_id) {
        acl_checklist = clientAclChecklistCreate(Config.accessList.store_id, http);
        acl_checklist->nonBlockingCheck(clientStoreIdAccessCheckDone, this);
    } else
        storeIdStart(http, clientStoreIdDoneWrapper, this);
}

void
ClientRequestContext::clientRedirectDone(const Helper::Reply &reply)
{
    HttpRequest *old_request = http->request;
    debugs(85, 5, HERE << "'" << http->uri << "' result=" << reply);
    assert(redirect_state == REDIRECT_PENDING);
    redirect_state = REDIRECT_DONE;

    // Put helper response Notes into the transaction state record (ALE) eventually
    // do it early to ensure that no matter what the outcome the notes are present.
    if (http->al)
        http->al->syncNotes(old_request);

    UpdateRequestNotes(http->getConn(), *old_request, reply.notes);

    switch (reply.result) {
    case Helper::TimedOut:
        if (Config.onUrlRewriteTimeout.action != toutActBypass) {
            http->calloutsError(ERR_GATEWAY_FAILURE, ERR_DETAIL_REDIRECTOR_TIMEDOUT);
            debugs(85, DBG_IMPORTANT, "ERROR: URL rewrite helper: Timedout");
        }
        break;

    case Helper::Unknown:
    case Helper::TT:
        // Handler in redirect.cc should have already mapped Unknown
        // IF it contained valid entry for the old URL-rewrite helper protocol
        debugs(85, DBG_IMPORTANT, "ERROR: URL rewrite helper returned invalid result code. Wrong helper? " << reply);
        break;

    case Helper::BrokenHelper:
        debugs(85, DBG_IMPORTANT, "ERROR: URL rewrite helper: " << reply);
        break;

    case Helper::Error:
        // no change to be done.
        break;

    case Helper::Okay: {
        // #1: redirect with a specific status code    OK status=NNN url="..."
        // #2: redirect with a default status code     OK url="..."
        // #3: re-write the URL                        OK rewrite-url="..."

        const char *statusNote = reply.notes.findFirst("status");
        const char *urlNote = reply.notes.findFirst("url");

        if (urlNote != NULL) {
            // HTTP protocol redirect to be done.

            // TODO: change default redirect status for appropriate requests
            // Squid defaults to 302 status for now for better compatibility with old clients.
            // HTTP/1.0 client should get 302 (Http::scFound)
            // HTTP/1.1 client contacting reverse-proxy should get 307 (Http::scTemporaryRedirect)
            // HTTP/1.1 client being diverted by forward-proxy should get 303 (Http::scSeeOther)
            Http::StatusCode status = Http::scFound;
            if (statusNote != NULL) {
                const char * result = statusNote;
                status = static_cast<Http::StatusCode>(atoi(result));
            }

            if (status == Http::scMovedPermanently
                    || status == Http::scFound
                    || status == Http::scSeeOther
                    || status == Http::scPermanentRedirect
                    || status == Http::scTemporaryRedirect) {
                http->redirect.status = status;
                http->redirect.location = xstrdup(urlNote);
                // TODO: validate the URL produced here is RFC 2616 compliant absolute URI
            } else {
                debugs(85, DBG_CRITICAL, "ERROR: URL-rewrite produces invalid " << status << " redirect Location: " << urlNote);
            }
        } else {
            // URL-rewrite wanted. Ew.
            urlNote = reply.notes.findFirst("rewrite-url");

            // prevent broken helpers causing too much damage. If old URL == new URL skip the re-write.
            if (urlNote != NULL && strcmp(urlNote, http->uri)) {
                AnyP::Uri tmpUrl;
                if (tmpUrl.parse(old_request->method, SBuf(urlNote))) {
                    HttpRequest *new_request = old_request->clone();
                    new_request->url = tmpUrl;
                    debugs(61, 2, "URL-rewriter diverts URL from " << old_request->effectiveRequestUri() << " to " << new_request->effectiveRequestUri());

                    // update the new request to flag the re-writing was done on it
                    new_request->flags.redirected = true;

                    // unlink bodypipe from the old request. Not needed there any longer.
                    if (old_request->body_pipe != NULL) {
                        old_request->body_pipe = NULL;
                        debugs(61,2, HERE << "URL-rewriter diverts body_pipe " << new_request->body_pipe <<
                               " from request " << old_request << " to " << new_request);
                    }

                    http->resetRequest(new_request);
                    old_request = nullptr;
                } else {
                    debugs(85, DBG_CRITICAL, "ERROR: URL-rewrite produces invalid request: " <<
                           old_request->method << " " << urlNote << " " << old_request->http_ver);
                }
            }
        }
    }
    break;
    }

    /* FIXME PIPELINE: This is inaccurate during pipelining */

    if (http->getConn() != NULL && Comm::IsConnOpen(http->getConn()->clientConnection))
        fd_note(http->getConn()->clientConnection->fd, http->uri);

    assert(http->uri);

    http->doCallouts();
}

/**
 * This method handles the different replies from StoreID helper.
 */
void
ClientRequestContext::clientStoreIdDone(const Helper::Reply &reply)
{
    HttpRequest *old_request = http->request;
    debugs(85, 5, "'" << http->uri << "' result=" << reply);
    assert(store_id_state == REDIRECT_PENDING);
    store_id_state = REDIRECT_DONE;

    // Put helper response Notes into the transaction state record (ALE) eventually
    // do it early to ensure that no matter what the outcome the notes are present.
    if (http->al)
        http->al->syncNotes(old_request);

    UpdateRequestNotes(http->getConn(), *old_request, reply.notes);

    switch (reply.result) {
    case Helper::Unknown:
    case Helper::TT:
        // Handler in redirect.cc should have already mapped Unknown
        // IF it contained valid entry for the old helper protocol
        debugs(85, DBG_IMPORTANT, "ERROR: storeID helper returned invalid result code. Wrong helper? " << reply);
        break;

    case Helper::TimedOut:
    // Timeouts for storeID are not implemented
    case Helper::BrokenHelper:
        debugs(85, DBG_IMPORTANT, "ERROR: storeID helper: " << reply);
        break;

    case Helper::Error:
        // no change to be done.
        break;

    case Helper::Okay: {
        const char *urlNote = reply.notes.findFirst("store-id");

        // prevent broken helpers causing too much damage. If old URL == new URL skip the re-write.
        if (urlNote != NULL && strcmp(urlNote, http->uri) ) {
            // Debug section required for some very specific cases.
            debugs(85, 9, "Setting storeID with: " << urlNote );
            http->request->store_id = urlNote;
            http->store_id = urlNote;
        }
    }
    break;
    }

    http->doCallouts();
}

static void
checkNoCacheDoneWrapper(Acl::Answer answer, void *data)
{
    ClientRequestContext *calloutContext = (ClientRequestContext *) data;

    if (!calloutContext->httpStateIsValid())
        return;

    calloutContext->checkNoCacheDone(answer);
}

/** Test cache allow/deny configuration
 *  Sets flags.cachable=1 if caching is not denied.
 */
void
ClientRequestContext::checkNoCache()
{
    if (Config.accessList.noCache) {
        acl_checklist = clientAclChecklistCreate(Config.accessList.noCache, http);
        acl_checklist->nonBlockingCheck(checkNoCacheDoneWrapper, this);
    } else {
        /* unless otherwise specified, we try to cache. */
        checkNoCacheDone(ACCESS_ALLOWED);
    }
}

void
ClientRequestContext::checkNoCacheDone(const Acl::Answer &answer)
{
    acl_checklist = NULL;
    if (answer.denied()) {
        http->request->flags.noCache = true; // do not read reply from cache
        http->request->flags.cachable = false; // do not store reply into cache
    }
    http->doCallouts();
}

#if USE_OPENSSL
/**
 * A wrapper function to use the ClientRequestContext::sslBumpAccessCheckDone method
 * as ACLFilledChecklist callback
 */
static void
sslBumpAccessCheckDoneWrapper(Acl::Answer answer, void *data)
{
    ClientRequestContext *calloutContext = static_cast<ClientRequestContext *>(data);

    if (!calloutContext->httpStateIsValid())
        return;
    calloutContext->sslBumpAccessCheckDone(answer);
}

bool
ClientRequestContext::sslBumpAccessCheck()
{
    if (!http->getConn()) {
        http->al->ssl.bumpMode = Ssl::bumpEnd; // SslBump does not apply; log -
        return false;
    }

    const Ssl::BumpMode bumpMode = http->getConn()->sslBumpMode;
    if (http->request->flags.forceTunnel) {
        debugs(85, 5, "not needed; already decided to tunnel " << http->getConn());
        if (bumpMode != Ssl::bumpEnd)
            http->al->ssl.bumpMode = bumpMode; // inherited from bumped connection
        return false;
    }

    // If SSL connection tunneling or bumping decision has been made, obey it.
    if (bumpMode != Ssl::bumpEnd) {
        debugs(85, 5, HERE << "SslBump already decided (" << bumpMode <<
               "), " << "ignoring ssl_bump for " << http->getConn());

        // We need the following "if" for transparently bumped TLS connection,
        // because in this case we are running ssl_bump access list before
        // the doCallouts runs. It can be removed after the bug #4340 fixed.
        // We do not want to proceed to bumping steps:
        //  - if the TLS connection with the client is already established
        //    because we are accepting normal HTTP requests on TLS port,
        //    or because of the client-first bumping mode
        //  - When the bumping is already started
        if (!http->getConn()->switchedToHttps() &&
                !http->getConn()->serverBump())
            http->sslBumpNeed(bumpMode); // for processRequest() to bump if needed and not already bumped
        http->al->ssl.bumpMode = bumpMode; // inherited from bumped connection
        return false;
    }

    // If we have not decided yet, decide whether to bump now.

    // Bumping here can only start with a CONNECT request on a bumping port
    // (bumping of intercepted SSL conns is decided before we get 1st request).
    // We also do not bump redirected CONNECT requests.
    if (http->request->method != Http::METHOD_CONNECT || http->redirect.status ||
            !Config.accessList.ssl_bump ||
            !http->getConn()->port->flags.tunnelSslBumping) {
        http->al->ssl.bumpMode = Ssl::bumpEnd; // SslBump does not apply; log -
        debugs(85, 5, HERE << "cannot SslBump this request");
        return false;
    }

    // Do not bump during authentication: clients would not proxy-authenticate
    // if we delay a 407 response and respond with 200 OK to CONNECT.
    if (error && error->httpStatus == Http::scProxyAuthenticationRequired) {
        http->al->ssl.bumpMode = Ssl::bumpEnd; // SslBump does not apply; log -
        debugs(85, 5, HERE << "no SslBump during proxy authentication");
        return false;
    }

    if (error) {
        debugs(85, 5, "SslBump applies. Force bump action on error " << errorTypeName(error->type));
        http->sslBumpNeed(Ssl::bumpBump);
        http->al->ssl.bumpMode = Ssl::bumpBump;
        return false;
    }

    debugs(85, 5, HERE << "SslBump possible, checking ACL");

    ACLFilledChecklist *aclChecklist = clientAclChecklistCreate(Config.accessList.ssl_bump, http);
    aclChecklist->nonBlockingCheck(sslBumpAccessCheckDoneWrapper, this);
    return true;
}

void
ClientRequestContext::sslBumpAccessCheckDone(const Acl::Answer &answer)
{
    if (!httpStateIsValid())
        return;

    const Ssl::BumpMode bumpMode = answer.allowed() ?
                                   static_cast<Ssl::BumpMode>(answer.kind) : Ssl::bumpSplice;
    http->sslBumpNeed(bumpMode); // for processRequest() to bump if needed
    http->al->ssl.bumpMode = bumpMode; // for logging

    if (bumpMode == Ssl::bumpTerminate) {
        const Comm::ConnectionPointer clientConn = http->getConn() ? http->getConn()->clientConnection : nullptr;
        if (Comm::IsConnOpen(clientConn)) {
            debugs(85, 3, "closing after Ssl::bumpTerminate ");
            clientConn->close();
        }
        return;
    }

    http->doCallouts();
}
#endif

