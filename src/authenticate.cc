
/*
 * $Id: authenticate.cc,v 1.12 2000/03/06 16:23:28 wessels Exp $
 *
 * DEBUG: section 29    Authenticator
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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
    acl_proxy_auth_user *auth_user;
    RH *handler;
} authenticateStateData;

static HLPCB authenticateHandleReply;
static void authenticateStateFree(authenticateStateData * r);
static helper *authenticators = NULL;

static void
authenticateHandleReply(void *data, char *reply)
{
    authenticateStateData *r = data;
    int valid;
    char *t = NULL;
    debug(29, 5) ("authenticateHandleReply: {%s}\n", reply ? reply : "<NULL>");
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
    authenticateStateFree(r);
}

static void
authenticateStateFree(authenticateStateData * r)
{
    cbdataFree(r);
}

static void
authenticateStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "Authenticator Statistics:\n");
    helperStats(sentry, authenticators);
}

/**** PUBLIC FUNCTIONS ****/


void
authenticateStart(acl_proxy_auth_user * auth_user, RH * handler, void *data)
{
    authenticateStateData *r = NULL;
    char buf[8192];
    assert(auth_user);
    assert(handler);
    debug(29, 5) ("authenticateStart: '%s:%s'\n", auth_user->user,
	auth_user->passwd);
    if (Config.Program.authenticate == NULL) {
	handler(data, NULL);
	return;
    }
    r = xcalloc(1, sizeof(authenticateStateData));
    cbdataAdd(r, cbdataXfree, 0);
    r->handler = handler;
    cbdataLock(data);
    r->data = data;
    r->auth_user = auth_user;
    snprintf(buf, 8192, "%s %s\n", r->auth_user->user, r->auth_user->passwd);
    helperSubmit(authenticators, buf, authenticateHandleReply, r);
}

void
authenticateInit(void)
{
    static int init = 0;
    if (!Config.Program.authenticate)
	return;
    if (authenticators == NULL)
	authenticators = helperCreate("authenticator");
    authenticators->cmdline = Config.Program.authenticate;
    authenticators->n_to_start = Config.authenticateChildren;
    authenticators->ipc_type = IPC_TCP_SOCKET;
    helperOpenServers(authenticators);
    if (!init) {
	cachemgrRegister("authenticator",
	    "User Authenticator Stats",
	    authenticateStats, 0, 1);
	init++;
    }
}

void
authenticateShutdown(void)
{
    if (!authenticators)
	return;
    helperShutdown(authenticators);
    if (!shutting_down)
	return;
    helperFree(authenticators);
    authenticators = NULL;
}
