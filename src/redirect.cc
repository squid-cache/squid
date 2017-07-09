/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 61    Redirector */

#include "squid.h"
#include "acl/Checklist.h"
#include "cache_cf.h"
#include "client_side.h"
#include "client_side_reply.h"
#include "client_side_request.h"
#include "comm/Connection.h"
#include "fde.h"
#include "format/Format.h"
#include "globals.h"
#include "helper.h"
#include "helper/Reply.h"
#include "http/Stream.h"
#include "HttpRequest.h"
#include "mgr/Registration.h"
#include "redirect.h"
#include "rfc1738.h"
#include "sbuf/SBuf.h"
#include "SquidConfig.h"
#include "Store.h"
#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_OPENSSL
#include "ssl/support.h"
#endif

/// url maximum lengh + extra informations passed to redirector
#define MAX_REDIRECTOR_REQUEST_STRLEN (MAX_URL + 1024)

class RedirectStateData
{
    CBDATA_CLASS(RedirectStateData);

public:
    explicit RedirectStateData(const char *url);
    ~RedirectStateData();

    void *data;
    SBuf orig_url;

    HLPCB *handler;
};

static HLPCB redirectHandleReply;
static HLPCB storeIdHandleReply;
static helper *redirectors = NULL;
static helper *storeIds = NULL;
static OBJH redirectStats;
static OBJH storeIdStats;
static int redirectorBypassed = 0;
static int storeIdBypassed = 0;
static Format::Format *redirectorExtrasFmt = NULL;
static Format::Format *storeIdExtrasFmt = NULL;

CBDATA_CLASS_INIT(RedirectStateData);

RedirectStateData::RedirectStateData(const char *url) :
    data(NULL),
    orig_url(url),
    handler(NULL)
{
}

RedirectStateData::~RedirectStateData()
{
}

static void
redirectHandleReply(void *data, const Helper::Reply &reply)
{
    RedirectStateData *r = static_cast<RedirectStateData *>(data);
    debugs(61, 5, HERE << "reply=" << reply);

    // XXX: This function is now kept only to check for and display the garbage use-case
    // and to map the old helper response format(s) into new format result code and key=value pairs
    // it can be removed when the helpers are all updated to the normalized "OK/ERR kv-pairs" format

    if (reply.result == Helper::Unknown) {
        // BACKWARD COMPATIBILITY 2012-06-15:
        // Some nasty old helpers send back the entire input line including extra format keys.
        // This is especially bad for simple perl search-replace filter scripts.
        //
        // * trim all but the first word off the response.
        // * warn once every 50 responses that this will stop being fixed-up soon.
        //
        if (reply.other().hasContent()) {
            const char * res = reply.other().content();
            size_t replySize = 0;
            if (const char *t = strchr(res, ' ')) {
                static int warn = 0;
                debugs(61, (!(warn++%50)? DBG_CRITICAL:2), "UPGRADE WARNING: URL rewriter reponded with garbage '" << t <<
                       "'. Future Squid will treat this as part of the URL.");
                replySize = t - res;
            } else
                replySize = reply.other().contentSize();

            // if we still have anything in other() after all that
            // parse it into status=, url= and rewrite-url= keys
            if (replySize) {
                MemBuf replyBuffer;
                replyBuffer.init(replySize, replySize);
                replyBuffer.append(reply.other().content(), reply.other().contentSize());
                char * result = replyBuffer.content();

                Helper::Reply newReply;
                // BACKWARD COMPATIBILITY 2012-06-15:
                // We got Helper::Unknown reply result but new
                // RedirectStateData handlers require Helper::Okay,
                // else will drop the helper reply
                newReply.result = Helper::Okay;
                newReply.notes.append(&reply.notes);

                // check and parse for obsoleted Squid-2 urlgroup feature
                if (*result == '!') {
                    static int urlgroupWarning = 0;
                    if (!urlgroupWarning++)
                        debugs(85, DBG_IMPORTANT, "UPGRADE WARNING: URL rewriter using obsolete Squid-2 urlgroup feature needs updating.");
                    if (char *t = strchr(result+1, '!')) {
                        *t = '\0';
                        newReply.notes.add("urlgroup", result+1);
                        result = t + 1;
                    }
                }

                const Http::StatusCode status = static_cast<Http::StatusCode>(atoi(result));

                if (status == Http::scMovedPermanently
                        || status == Http::scFound
                        || status == Http::scSeeOther
                        || status == Http::scPermanentRedirect
                        || status == Http::scTemporaryRedirect) {

                    if (const char *t = strchr(result, ':')) {
                        char statusBuf[4];
                        snprintf(statusBuf, sizeof(statusBuf),"%3u",status);
                        newReply.notes.add("status", statusBuf);
                        ++t;
                        // TODO: validate the URL produced here is RFC 2616 compliant URI
                        newReply.notes.add("url", t);
                    } else {
                        debugs(85, DBG_CRITICAL, "ERROR: URL-rewrite produces invalid " << status << " redirect Location: " << result);
                    }
                } else {
                    // status code is not a redirect code (or does not exist)
                    // treat as a re-write URL request
                    // TODO: validate the URL produced here is RFC 2616 compliant URI
                    if (*result)
                        newReply.notes.add("rewrite-url", result);
                }

                void *cbdata;
                if (cbdataReferenceValidDone(r->data, &cbdata))
                    r->handler(cbdata, newReply);

                delete r;
                return;
            }
        }
    }

    void *cbdata;
    if (cbdataReferenceValidDone(r->data, &cbdata))
        r->handler(cbdata, reply);

    delete r;
}

static void
storeIdHandleReply(void *data, const Helper::Reply &reply)
{
    RedirectStateData *r = static_cast<RedirectStateData *>(data);
    debugs(61, 5,"StoreId helper: reply=" << reply);

    // XXX: This function is now kept only to check for and display the garbage use-case
    // and to map the old helper response format(s) into new format result code and key=value pairs
    // it can be removed when the helpers are all updated to the normalized "OK/ERR kv-pairs" format
    void *cbdata;
    if (cbdataReferenceValidDone(r->data, &cbdata))
        r->handler(cbdata, reply);

    delete r;
}

static void
redirectStats(StoreEntry * sentry)
{
    if (redirectors == NULL) {
        storeAppendPrintf(sentry, "No redirectors defined\n");
        return;
    }

    redirectors->packStatsInto(sentry, "Redirector Statistics");

    if (Config.onoff.redirector_bypass)
        storeAppendPrintf(sentry, "\nNumber of requests bypassed "
                          "because all redirectors were busy: %d\n", redirectorBypassed);
}

static void
storeIdStats(StoreEntry * sentry)
{
    if (storeIds == NULL) {
        storeAppendPrintf(sentry, "No StoreId helpers defined\n");
        return;
    }

    storeIds->packStatsInto(sentry, "StoreId helper Statistics");

    if (Config.onoff.store_id_bypass)
        storeAppendPrintf(sentry, "\nNumber of requests bypassed "
                          "because all StoreId helpers were busy: %d\n", storeIdBypassed);
}

static void
constructHelperQuery(const char *name, helper *hlp, HLPCB *replyHandler, ClientHttpRequest * http, HLPCB *handler, void *data, Format::Format *requestExtrasFmt)
{
    char buf[MAX_REDIRECTOR_REQUEST_STRLEN];
    int sz;
    Http::StatusCode status;

    /** TODO: create a standalone method to initialize
     * the RedirectStateData for all the helpers.
     */
    RedirectStateData *r = new RedirectStateData(http->uri);
    r->handler = handler;
    r->data = cbdataReference(data);

    static MemBuf requestExtras;
    requestExtras.reset();
    if (requestExtrasFmt)
        requestExtrasFmt->assemble(requestExtras, http->al, 0);

    sz = snprintf(buf, MAX_REDIRECTOR_REQUEST_STRLEN, "%s%s%s\n",
                  r->orig_url.c_str(),
                  requestExtras.hasContent() ? " " : "",
                  requestExtras.hasContent() ? requestExtras.content() : "");

    if ((sz<=0) || (sz>=MAX_REDIRECTOR_REQUEST_STRLEN)) {
        if (sz<=0) {
            status = Http::scInternalServerError;
            debugs(61, DBG_CRITICAL, "ERROR: Gateway Failure. Can not build request to be passed to " << name << ". Request ABORTED.");
        } else {
            status = Http::scUriTooLong;
            debugs(61, DBG_CRITICAL, "ERROR: Gateway Failure. Request passed to " << name << " exceeds MAX_REDIRECTOR_REQUEST_STRLEN (" << MAX_REDIRECTOR_REQUEST_STRLEN << "). Request ABORTED.");
        }

        clientStreamNode *node = (clientStreamNode *)http->client_stream.tail->prev->data;
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        Ip::Address tmpnoaddr;
        tmpnoaddr.setNoAddr();
        repContext->setReplyToError(ERR_GATEWAY_FAILURE, status,
                                    http->request->method, NULL,
                                    http->getConn() != NULL && http->getConn()->clientConnection != NULL ?
                                    http->getConn()->clientConnection->remote : tmpnoaddr,
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
        return;
    }

    debugs(61,6, HERE << "sending '" << buf << "' to the " << name << " helper");
    helperSubmit(hlp, buf, replyHandler, r);
}

/**** PUBLIC FUNCTIONS ****/

void
redirectStart(ClientHttpRequest * http, HLPCB * handler, void *data)
{
    assert(http);
    assert(handler);
    debugs(61, 5, "redirectStart: '" << http->uri << "'");

    // TODO: Deprecate Config.onoff.redirector_bypass in favor of either
    // onPersistentOverload or a new onOverload option that applies to all helpers.
    if (Config.onoff.redirector_bypass && redirectors->willOverload()) {
        /* Skip redirector if the queue is full */
        ++redirectorBypassed;
        Helper::Reply bypassReply;
        bypassReply.result = Helper::Okay;
        bypassReply.notes.add("message","URL rewrite/redirect queue too long. Bypassed.");
        handler(data, bypassReply);
        return;
    }

    constructHelperQuery("redirector", redirectors, redirectHandleReply, http, handler, data, redirectorExtrasFmt);
}

/**
 * Handles the StoreID feature helper starting.
 * For now it cannot be done using the redirectStart method.
 */
void
storeIdStart(ClientHttpRequest * http, HLPCB * handler, void *data)
{
    assert(http);
    assert(handler);
    debugs(61, 5, "storeIdStart: '" << http->uri << "'");

    if (Config.onoff.store_id_bypass && storeIds->willOverload()) {
        /* Skip StoreID Helper if the queue is full */
        ++storeIdBypassed;
        Helper::Reply bypassReply;

        bypassReply.result = Helper::Okay;

        bypassReply.notes.add("message","StoreId helper queue too long. Bypassed.");
        handler(data, bypassReply);
        return;
    }

    constructHelperQuery("storeId helper", storeIds, storeIdHandleReply, http, handler, data, storeIdExtrasFmt);
}

void
redirectInit(void)
{
    static bool init = false;

    if (!init) {
        Mgr::RegisterAction("redirector", "URL Redirector Stats", redirectStats, 0, 1);
        Mgr::RegisterAction("store_id", "StoreId helper Stats", storeIdStats, 0, 1);
    }

    if (Config.Program.redirect) {

        if (redirectors == NULL)
            redirectors = new helper("redirector");

        redirectors->cmdline = Config.Program.redirect;

        // BACKWARD COMPATIBILITY:
        // if redirectot_bypass is set then use queue_size=0 as default size
        if (Config.onoff.redirector_bypass && Config.redirectChildren.defaultQueueSize)
            Config.redirectChildren.queue_size = 0;

        redirectors->childs.updateLimits(Config.redirectChildren);

        redirectors->ipc_type = IPC_STREAM;

        redirectors->timeout = Config.Timeout.urlRewrite;

        redirectors->retryTimedOut = (Config.onUrlRewriteTimeout.action == toutActRetry);
        redirectors->retryBrokenHelper = true; // XXX: make this configurable ?
        redirectors->onTimedOutResponse.clear();
        if (Config.onUrlRewriteTimeout.action == toutActUseConfiguredResponse)
            redirectors->onTimedOutResponse.assign(Config.onUrlRewriteTimeout.response);

        helperOpenServers(redirectors);
    }

    if (Config.Program.store_id) {

        if (storeIds == NULL)
            storeIds = new helper("store_id");

        storeIds->cmdline = Config.Program.store_id;

        // BACKWARD COMPATIBILITY:
        // if store_id_bypass is set then use queue_size=0 as default size
        if (Config.onoff.store_id_bypass && Config.storeIdChildren.defaultQueueSize)
            Config.storeIdChildren.queue_size = 0;

        storeIds->childs.updateLimits(Config.storeIdChildren);

        storeIds->ipc_type = IPC_STREAM;

        storeIds->retryBrokenHelper = true; // XXX: make this configurable ?

        helperOpenServers(storeIds);
    }

    if (Config.redirector_extras) {
        delete redirectorExtrasFmt;
        redirectorExtrasFmt = new ::Format::Format("url_rewrite_extras");
        (void)redirectorExtrasFmt->parse(Config.redirector_extras);
    }

    if (Config.storeId_extras) {
        delete storeIdExtrasFmt;
        storeIdExtrasFmt = new ::Format::Format("store_id_extras");
        (void)storeIdExtrasFmt->parse(Config.storeId_extras);
    }

    init = true;
}

void
redirectShutdown(void)
{
    /** FIXME: Temporary unified helpers Shutdown
     * When and if needed for more helpers a separated shutdown
     * method will be added for each of them.
     */
    if (redirectors)
        helperShutdown(redirectors);

    if (storeIds)
        helperShutdown(storeIds);

    if (!shutting_down)
        return;

    delete redirectors;
    redirectors = NULL;

    delete storeIds;
    storeIds = NULL;

    delete redirectorExtrasFmt;
    redirectorExtrasFmt = NULL;

    delete storeIdExtrasFmt;
    storeIdExtrasFmt = NULL;
}

