
/*
 * $Id: client_db.cc,v 1.15 1997/07/26 04:48:24 wessels Exp $
 *
 * DEBUG: section 0     Client Database
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

typedef struct _client_info {
    char *key;
    struct client_info *next;
    struct in_addr addr;
    struct {
	int result_hist[ERR_MAX];
	int n_requests;
    } Http, Icp;
} ClientInfo;

static hash_table *client_table = NULL;
static ClientInfo *clientdbAdd _PARAMS((struct in_addr addr));

static ClientInfo *
clientdbAdd(struct in_addr addr)
{
    ClientInfo *c;
    c = xcalloc(1, sizeof(ClientInfo));
    c->key = xstrdup(inet_ntoa(addr));
    c->addr = addr;
    hash_join(client_table, (hash_link *) c);
    meta_data.client_info++;
    return c;
}

void
clientdbInit(void)
{
    if (client_table)
	return;
    client_table = hash_create((int (*)_PARAMS((const char *, const char *))) strcmp,
	229,
	hash_string);
    client_info_sz = sizeof(ClientInfo);
}

void
clientdbUpdate(struct in_addr addr, log_type log_type, protocol_t p)
{
    char *key;
    ClientInfo *c;
    if (!Config.onoff.client_db)
	return;
    key = inet_ntoa(addr);
    c = (ClientInfo *) hash_lookup(client_table, key);
    if (c == NULL)
	c = clientdbAdd(addr);
    if (c == NULL)
	debug_trap("clientdbUpdate: Failed to add entry");
    if (p == PROTO_HTTP) {
	c->Http.n_requests++;
	c->Http.result_hist[log_type]++;
    } else if (p == PROTO_ICP) {
	c->Icp.n_requests++;
	c->Icp.result_hist[log_type]++;
    }
}

int
clientdbDeniedPercent(struct in_addr addr)
{
    char *key;
    int n = 100;
    ClientInfo *c;
    if (!Config.onoff.client_db)
	return 0;
    key = inet_ntoa(addr);
    c = (ClientInfo *) hash_lookup(client_table, key);
    if (c == NULL)
	return 0;
    if (c->Icp.n_requests > 100)
	n = c->Icp.n_requests;
    return 100 * c->Icp.result_hist[ICP_OP_DENIED] / n;
}

void
clientdbDump(StoreEntry * sentry)
{
    ClientInfo *c;
    log_type l;
    storeAppendPrintf(sentry, "{Cache Clients:\n");
    c = (ClientInfo *) hash_first(client_table);
    while (c) {
	storeAppendPrintf(sentry, "{Address: %s}\n", c->key);
	storeAppendPrintf(sentry, "{Name: %s}\n", fqdnFromAddr(c->addr));
	storeAppendPrintf(sentry, "{    ICP Requests %d}\n",
	    c->Icp.n_requests);
	for (l = LOG_TAG_NONE; l < ERR_MAX; l++) {
	    if (c->Icp.result_hist[l] == 0)
		continue;
	    storeAppendPrintf(sentry,
		"{        %-20.20s %7d %3d%%}\n",
		log_tags[l],
		c->Icp.result_hist[l],
		percent(c->Icp.result_hist[l], c->Icp.n_requests));
	}
	storeAppendPrintf(sentry, "{    HTTP Requests %d}\n",
	    c->Http.n_requests);
	for (l = LOG_TAG_NONE; l < ERR_MAX; l++) {
	    if (c->Http.result_hist[l] == 0)
		continue;
	    storeAppendPrintf(sentry,
		"{        %-20.20s %7d %3d%%}\n",
		log_tags[l],
		c->Http.result_hist[l],
		percent(c->Http.result_hist[l], c->Http.n_requests));
	}
	storeAppendPrintf(sentry, "{}\n");
	c = (ClientInfo *) hash_next(client_table);
    }
    storeAppendPrintf(sentry, close_bracket);
}
