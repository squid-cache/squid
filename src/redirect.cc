
/*
 * $Id: redirect.cc,v 1.89 2002/04/04 23:59:25 hno Exp $
 *
 * DEBUG: section 29    Redirector
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

typedef struct {
    void *data;
    char *orig_url;
    struct in_addr client_addr;
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
    redirectStateData *r = data;
    int valid;
    char *t;
    debug(29, 5) ("redirectHandleRead: {%s}\n", reply ? reply : "<NULL>");
    if (reply) {
	if ((t = strchr(reply, ' ')))
	    *t = '\0';
	if (*reply == '\0')
	    reply = NULL;
    }
    valid = cbdataValid(r->data);
    cbdataUnlock(r->data);
    if (valid)
	r->handler(r->data, reply);
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
    storeAppendPrintf(sentry, "Redirector Statistics:\n");
    helperStats(sentry, redirectors);
    if (Config.onoff.redirector_bypass)
	storeAppendPrintf(sentry, "\nNumber of requests bypassed "
	    "because all redirectors were busy: %d\n", n_bypassed);
}

/**** PUBLIC FUNCTIONS ****/

void
redirectStart(clientHttpRequest * http, RH * handler, void *data)
{
    ConnStateData *conn = http->conn;
    redirectStateData *r = NULL;
    const char *fqdn;
    char buf[8192];
    assert(http);
    assert(handler);
    debug(29, 5) ("redirectStart: '%s'\n", http->uri);
    if (Config.Program.redirect == NULL) {
	handler(data, NULL);
	return;
    }
    if (Config.accessList.redirector) {
	aclCheck_t ch;
	memset(&ch, '\0', sizeof(ch));
	ch.src_addr = http->conn->peer.sin_addr;
	ch.my_addr = http->conn->me.sin_addr;
	ch.my_port = ntohs(http->conn->me.sin_port);
	ch.request = http->request;
	if (!aclCheckFast(Config.accessList.redirector, &ch)) {
	    /* denied -- bypass redirector */
	    handler(data, NULL);
	    return;
	}
    }
    if (Config.onoff.redirector_bypass && redirectors->stats.queue_size) {
	/* Skip redirector if there is one request queued */
	n_bypassed++;
	handler(data, NULL);
	return;
    }
    r = cbdataAlloc(redirectStateData);
    r->orig_url = xstrdup(http->uri);
    r->client_addr = conn->log_addr;
    if (http->request->auth_user_request)
	r->client_ident = authenticateUserRequestUsername(http->request->auth_user_request);
    else if (conn->rfc931[0]) {
	r->client_ident = conn->rfc931;
    } else {
	r->client_ident = dash_str;
    }
    r->method_s = RequestMethodStr[http->request->method];
    r->handler = handler;
    r->data = data;
    cbdataLock(r->data);
    if ((fqdn = fqdncache_gethostbyaddr(r->client_addr, 0)) == NULL)
	fqdn = dash_str;
    snprintf(buf, 8192, "%s %s/%s %s %s\n",
	r->orig_url,
	inet_ntoa(r->client_addr),
	fqdn,
	r->client_ident,
	r->method_s);
    helperSubmit(redirectors, buf, redirectHandleReply, r);
}

void
redirectInit(void)
{
    static int init = 0;
    if (!Config.Program.redirect)
	return;
    if (redirectors == NULL)
	redirectors = helperCreate("redirector");
    redirectors->cmdline = Config.Program.redirect;
    redirectors->n_to_start = Config.redirectChildren;
    redirectors->ipc_type = IPC_STREAM;
    helperOpenServers(redirectors);
    if (!init) {
	cachemgrRegister("redirector",
	    "URL Redirector Stats",
	    redirectStats, 0, 1);
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
