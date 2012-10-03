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
#include "helper.h"
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
    RH *handler;
} redirectStateData;

static HLPCB redirectHandleReply;
static void redirectStateFree(redirectStateData * r);
static helper *redirectors = NULL;
static OBJH redirectStats;
static int n_bypassed = 0;
CBDATA_TYPE(redirectStateData);

static void
redirectHandleReply(void *data, char *reply)
{
    redirectStateData *r = static_cast<redirectStateData *>(data);
    char *t;
    void *cbdata;
    debugs(61, 5, "redirectHandleRead: {" << (reply && *reply != '\0' ? reply : "<NULL>") << "}");

    if (reply) {
        if ((t = strchr(reply, ' ')))
            *t = '\0';

        if (*reply == '\0')
            reply = NULL;
    }

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
                          "because all redirectors were busy: %d\n", n_bypassed);
}

/**** PUBLIC FUNCTIONS ****/

void
redirectStart(ClientHttpRequest * http, RH * handler, void *data)
{
    ConnStateData * conn = http->getConn();
    redirectStateData *r = NULL;
    const char *fqdn;
    char buf[MAX_REDIRECTOR_REQUEST_STRLEN];
    int sz;
    http_status status;
    char claddr[MAX_IPSTRLEN];
    char myaddr[MAX_IPSTRLEN];
    assert(http);
    assert(handler);
    debugs(61, 5, "redirectStart: '" << http->uri << "'");

    if (Config.onoff.redirector_bypass && redirectors->stats.queue_size) {
        /* Skip redirector if there is one request queued */
        ++n_bypassed;
        handler(data, NULL);
        return;
    }

    r = cbdataAlloc(redirectStateData);
    r->orig_url = xstrdup(http->uri);
    if (conn != NULL)
        r->client_addr = conn->log_addr;
    else
        r->client_addr.SetNoAddr();
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
                  r->client_addr.NtoA(claddr,MAX_IPSTRLEN),
                  fqdn,
                  r->client_ident[0] ? rfc1738_escape(r->client_ident) : dash_str,
                  r->method_s,
                  http->request->my_addr.NtoA(myaddr,MAX_IPSTRLEN),
                  http->request->my_addr.GetPort());

    if ((sz<=0) || (sz>=MAX_REDIRECTOR_REQUEST_STRLEN)) {
        if (sz<=0) {
            status = HTTP_INTERNAL_SERVER_ERROR;
            debugs(61, DBG_CRITICAL, "ERROR: Gateway Failure. Can not build request to be passed to redirector. Request ABORTED.");
        } else {
            status = HTTP_REQUEST_URI_TOO_LARGE;
            debugs(61, DBG_CRITICAL, "ERROR: Gateway Failure. Request passed to redirector exceeds MAX_REDIRECTOR_REQUEST_STRLEN (" << MAX_REDIRECTOR_REQUEST_STRLEN << "). Request ABORTED.");
        }

        clientStreamNode *node = (clientStreamNode *)http->client_stream.tail->prev->data;
        clientReplyContext *repContext = dynamic_cast<clientReplyContext *>(node->data.getRaw());
        assert (repContext);
        Ip::Address tmpnoaddr;
        tmpnoaddr.SetNoAddr();
        repContext->setReplyToError(ERR_GATEWAY_FAILURE, status,
                                    http->request->method, NULL,
                                    http->getConn() != NULL && http->getConn()->clientConnection != NULL ?
                                    http->getConn()->clientConnection->remote : tmpnoaddr,
                                    http->request,
                                    NULL,
#if USE_AUTH
                                    http->getConn() != NULL && http->getConn()->auth_user_request != NULL ?
                                    http->getConn()->auth_user_request : http->request->auth_user_request);
#else
                                    NULL);
#endif

        node = (clientStreamNode *)http->client_stream.tail->data;
        clientStreamRead(node, http, node->readBuffer);
        return;
    }

    debugs(61,6, HERE << "sending '" << buf << "' to the helper");
    helperSubmit(redirectors, buf, redirectHandleReply, r);
}

static void
redirectRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("redirector", "URL Redirector Stats", redirectStats, 0, 1);
}

void
redirectInit(void)
{
    static int init = 0;

    redirectRegisterWithCacheManager();

    if (!Config.Program.redirect)
        return;

    if (redirectors == NULL)
        redirectors = new helper("redirector");

    redirectors->cmdline = Config.Program.redirect;

    redirectors->childs.updateLimits(Config.redirectChildren);

    redirectors->ipc_type = IPC_STREAM;

    helperOpenServers(redirectors);

    if (!init) {
        init = 1;
        CBDATA_INIT_TYPE(redirectStateData);
    }
}

void
redirectShutdown(void)
{
    if (!redirectors)
        return;

    helperShutdown(redirectors);

    if (!shutting_down)
        return;

    delete redirectors;
    redirectors = NULL;
}
