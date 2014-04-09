/*
 * DEBUG: section 61    Redirector
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
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "client_side.h"
#include "client_side_reply.h"
#include "client_side_request.h"
#include "comm/Connection.h"
#include "fde.h"
#include "fqdncache.h"
#include "globals.h"
#include "HttpRequest.h"
#include "mgr/Registration.h"
#include "redirect.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "Store.h"
#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_SSL
#include "ssl/support.h"
#endif

/// url maximum lengh + extra informations passed to redirector
#define MAX_REDIRECTOR_REQUEST_STRLEN (MAX_URL + 1024)

typedef struct {
    void *data;
    char *orig_url;

    Ip::Address client_addr;
    const char *client_ident;
    const char *method_s;
    HLPCB *handler;
} redirectStateData;

static HLPCB redirectHandleReply;
static HLPCB storeIdHandleReply;
static void redirectStateFree(redirectStateData * r);
static helper *redirectors = NULL;
static helper *storeIds = NULL;
static OBJH redirectStats;
static OBJH storeIdStats;
static int redirectorBypassed = 0;
static int storeIdBypassed = 0;
CBDATA_TYPE(redirectStateData);

static void
redirectHandleReply(void *data, const HelperReply &reply)
{
    redirectStateData *r = static_cast<redirectStateData *>(data);
    debugs(61, 5, HERE << "reply=" << reply);

    // XXX: This function is now kept only to check for and display the garbage use-case
    // and to map the old helper response format(s) into new format result code and key=value pairs
    // it can be removed when the helpers are all updated to the normalized "OK/ERR kv-pairs" format

    if (reply.result == HelperReply::Unknown) {
        // BACKWARD COMPATIBILITY 2012-06-15:
        // Some nasty old helpers send back the entire input line including extra format keys.
        // This is especially bad for simple perl search-replace filter scripts.
        //
        // * trim all but the first word off the response.
        // * warn once every 50 responses that this will stop being fixed-up soon.
        //
        if (const char * res = reply.other().content()) {
            if (const char *t = strchr(res, ' ')) {
                static int warn = 0;
                debugs(61, (!(warn++%50)? DBG_CRITICAL:2), "UPGRADE WARNING: URL rewriter reponded with garbage '" << t <<
                       "'. Future Squid will treat this as part of the URL.");
                const mb_size_t garbageLength = reply.other().contentSize() - (t-res);
                reply.modifiableOther().truncate(garbageLength);
            }
            if (reply.other().hasContent() && *res == '\0')
                reply.modifiableOther().clean(); // drop the whole buffer of garbage.

            // if we still have anything in other() after all that
            // parse it into status=, url= and rewrite-url= keys
            if (reply.other().hasContent()) {
                /* 2012-06-28: This cast is due to urlParse() truncating too-long URLs itself.
                 * At this point altering the helper buffer in that way is not harmful, but annoying.
                 * When Bug 1961 is resolved and urlParse has a const API, this needs to die.
                 */
                const char * result = reply.other().content();
                const Http::StatusCode status = static_cast<Http::StatusCode>(atoi(result));

                HelperReply newReply;
                // BACKWARD COMPATIBILITY 2012-06-15:
                // We got HelperReply::Unknown reply result but new
                // redirectStateData handlers require HelperReply::Okay,
                // else will drop the helper reply
                newReply.result = HelperReply::Okay;
                newReply.notes.append(&reply.notes);

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
                    newReply.notes.add("rewrite-url", reply.other().content());
                }

                void *cbdata;
                if (cbdataReferenceValidDone(r->data, &cbdata))
                    r->handler(cbdata, newReply);

                redirectStateFree(r);
                return;
            }
        }
    }

    void *cbdata;
    if (cbdataReferenceValidDone(r->data, &cbdata))
        r->handler(cbdata, reply);

    redirectStateFree(r);
}

static void
storeIdHandleReply(void *data, const HelperReply &reply)
{
    redirectStateData *r = static_cast<redirectStateData *>(data);
    debugs(61, 5,"StoreId helper: reply=" << reply);

    // XXX: This function is now kept only to check for and display the garbage use-case
    // and to map the old helper response format(s) into new format result code and key=value pairs
    // it can be removed when the helpers are all updated to the normalized "OK/ERR kv-pairs" format
    void *cbdata;
    if (cbdataReferenceValidDone(r->data, &cbdata))
        r->handler(cbdata, reply);

    redirectStateFree(r);
}

static void
redirectStateFree(redirectStateData * r)
{
    safe_free(r->orig_url);
    cbdataFree(r);
}

static void
redirectStats(StoreEntry * sentry)
{
    if (redirectors == NULL) {
        storeAppendPrintf(sentry, "No redirectors defined\n");
        return;
    }

    helperStats(sentry, redirectors, "Redirector Statistics");

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

    helperStats(sentry, storeIds, "StoreId helper Statistics");

    if (Config.onoff.store_id_bypass)
        storeAppendPrintf(sentry, "\nNumber of requests bypassed "
                          "because all StoreId helpers were busy: %d\n", storeIdBypassed);
}

static void
constructHelperQuery(const char *name, helper *hlp, HLPCB *replyHandler, ClientHttpRequest * http, HLPCB *handler, void *data)
{
    ConnStateData * conn = http->getConn();
    const char *fqdn;
    char buf[MAX_REDIRECTOR_REQUEST_STRLEN];
    int sz;
    Http::StatusCode status;
    char claddr[MAX_IPSTRLEN];
    char myaddr[MAX_IPSTRLEN];

    /** TODO: create a standalone method to initialize
     * the cbdata\redirectStateData for all the helpers.
     */
    redirectStateData *r = cbdataAlloc(redirectStateData);
    r->orig_url = xstrdup(http->uri);
    if (conn != NULL)
        r->client_addr = conn->log_addr;
    else
        r->client_addr.setNoAddr();
    r->client_ident = NULL;
#if USE_AUTH
    if (http->request->auth_user_request != NULL) {
        r->client_ident = http->request->auth_user_request->username();
        debugs(61, 5, HERE << "auth-user=" << (r->client_ident?r->client_ident:"NULL"));
    }
#endif

    // HttpRequest initializes with null_string. So we must check both defined() and size()
    if (!r->client_ident && http->request->extacl_user.defined() && http->request->extacl_user.size()) {
        r->client_ident = http->request->extacl_user.termedBuf();
        debugs(61, 5, HERE << "acl-user=" << (r->client_ident?r->client_ident:"NULL"));
    }

    if (!r->client_ident && conn != NULL && conn->clientConnection != NULL && conn->clientConnection->rfc931[0]) {
        r->client_ident = conn->clientConnection->rfc931;
        debugs(61, 5, HERE << "ident-user=" << (r->client_ident?r->client_ident:"NULL"));
    }

#if USE_SSL

    if (!r->client_ident && conn != NULL && Comm::IsConnOpen(conn->clientConnection)) {
        r->client_ident = sslGetUserEmail(fd_table[conn->clientConnection->fd].ssl);
        debugs(61, 5, HERE << "ssl-user=" << (r->client_ident?r->client_ident:"NULL"));
    }
#endif

    if (!r->client_ident)
        r->client_ident = dash_str;

    r->method_s = RequestMethodStr(http->request->method);

    r->handler = handler;

    r->data = cbdataReference(data);

    if ((fqdn = fqdncache_gethostbyaddr(r->client_addr, 0)) == NULL)
        fqdn = dash_str;

    sz = snprintf(buf, MAX_REDIRECTOR_REQUEST_STRLEN, "%s %s/%s %s %s myip=%s myport=%d\n",
                  r->orig_url,
                  r->client_addr.toStr(claddr,MAX_IPSTRLEN),
                  fqdn,
                  r->client_ident[0] ? rfc1738_escape(r->client_ident) : dash_str,
                  r->method_s,
                  http->request->my_addr.toStr(myaddr,MAX_IPSTRLEN),
                  http->request->my_addr.port());

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

    if (Config.onoff.redirector_bypass && redirectors->stats.queue_size) {
        /* Skip redirector if there is one request queued */
        ++redirectorBypassed;
        HelperReply bypassReply;
        bypassReply.result = HelperReply::Okay;
        bypassReply.notes.add("message","URL rewrite/redirect queue too long. Bypassed.");
        handler(data, bypassReply);
        return;
    }

    constructHelperQuery("redirector", redirectors, redirectHandleReply, http, handler, data);
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

    if (Config.onoff.store_id_bypass && storeIds->stats.queue_size) {
        /* Skip StoreID Helper if there is one request queued */
        ++storeIdBypassed;
        HelperReply bypassReply;

        bypassReply.result = HelperReply::Okay;

        bypassReply.notes.add("message","StoreId helper queue too long. Bypassed.");
        handler(data, bypassReply);
        return;
    }

    constructHelperQuery("storeId helper", storeIds, storeIdHandleReply, http, handler, data);
}

static void
redirectRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("redirector", "URL Redirector Stats", redirectStats, 0, 1);
    Mgr::RegisterAction("store_id", "StoreId helper Stats", storeIdStats, 0, 1); /* registering the new StoreID statistics in Mgr*/
}

void
redirectInit(void)
{
    static int init = 0;

    redirectRegisterWithCacheManager();

    /** FIXME: Temporary unified helpers startup
     * When and if needed for more helpers a separated startup
     * method will be added for each of them.
     */
    if (!Config.Program.redirect && !Config.Program.store_id)
        return;

    if (Config.Program.redirect) {

        if (redirectors == NULL)
            redirectors = new helper("redirector");

        redirectors->cmdline = Config.Program.redirect;

        redirectors->childs.updateLimits(Config.redirectChildren);

        redirectors->ipc_type = IPC_STREAM;

        helperOpenServers(redirectors);
    }

    if (Config.Program.store_id) {

        if (storeIds == NULL)
            storeIds = new helper("store_id");

        storeIds->cmdline = Config.Program.store_id;

        storeIds->childs.updateLimits(Config.storeIdChildren);

        storeIds->ipc_type = IPC_STREAM;

        helperOpenServers(storeIds);
    }

    if (!init) {
        init = 1;
        CBDATA_INIT_TYPE(redirectStateData);
    }
}

void
redirectShutdown(void)
{
    /** FIXME: Temporary unified helpers Shutdown
     * When and if needed for more helpers a separated shutdown
     * method will be added for each of them.
     */
    if (!storeIds && !redirectors)
        return;

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

}
