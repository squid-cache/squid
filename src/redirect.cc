
/*
 * $Id$
 *
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
#include "auth/UserRequest.h"
#include "CacheManager.h"
#include "Store.h"
#include "fde.h"
#include "client_side_request.h"
#include "acl/Checklist.h"
#include "HttpRequest.h"
#include "client_side.h"
#include "helper.h"
#include "rfc1738.h"

typedef struct {
    void *data;
    char *orig_url;

    IpAddress client_addr;
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
    char buf[8192];
    char claddr[MAX_IPSTRLEN];
    char myaddr[MAX_IPSTRLEN];
    assert(http);
    assert(handler);
    debugs(61, 5, "redirectStart: '" << http->uri << "'");

    if (Config.onoff.redirector_bypass && redirectors->stats.queue_size) {
        /* Skip redirector if there is one request queued */
        n_bypassed++;
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

    if (http->request->auth_user_request)
        r->client_ident = http->request->auth_user_request->username();
    else if (http->request->extacl_user.defined()) {
        r->client_ident = http->request->extacl_user.termedBuf();
    }

    if (!r->client_ident && (conn != NULL && conn->rfc931[0]))
        r->client_ident = conn->rfc931;

#if USE_SSL

    if (!r->client_ident && conn != NULL)
        r->client_ident = sslGetUserEmail(fd_table[conn->fd].ssl);

#endif

    if (!r->client_ident)
        r->client_ident = dash_str;

    r->method_s = RequestMethodStr(http->request->method);

    r->handler = handler;

    r->data = cbdataReference(data);

    if ((fqdn = fqdncache_gethostbyaddr(r->client_addr, 0)) == NULL)
        fqdn = dash_str;

    snprintf(buf, 8192, "%s %s/%s %s %s myip=%s myport=%d\n",
             r->orig_url,
             r->client_addr.NtoA(claddr,MAX_IPSTRLEN),
             fqdn,
             r->client_ident[0] ? rfc1738_escape(r->client_ident) : dash_str,
             r->method_s,
             http->request->my_addr.NtoA(myaddr,MAX_IPSTRLEN),
             http->request->my_addr.GetPort());

    helperSubmit(redirectors, buf, redirectHandleReply, r);
}

static void
redirectRegisterWithCacheManager(void)
{
    CacheManager::GetInstance()->
    registerAction("redirector", "URL Redirector Stats", redirectStats, 0, 1);
}

void
redirectInit(void)
{
    static int init = 0;

    redirectRegisterWithCacheManager();

    if (!Config.Program.redirect)
        return;

    if (redirectors == NULL)
        redirectors = helperCreate("redirector");

    redirectors->cmdline = Config.Program.redirect;

    redirectors->n_to_start = Config.redirectChildren;

    redirectors->concurrency = Config.redirectConcurrency;

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

    helperFree(redirectors);

    redirectors = NULL;
}
