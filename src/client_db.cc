
/*
 * $Id: client_db.cc,v 1.23 1998/03/06 22:19:30 wessels Exp $
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

static hash_table *client_table = NULL;
static ClientInfo *clientdbAdd(struct in_addr addr);

static ClientInfo *
clientdbAdd(struct in_addr addr)
{
    ClientInfo *c;
    c = memAllocate(MEM_CLIENT_INFO);
    c->key = xstrdup(inet_ntoa(addr));
    c->addr = addr;
    hash_join(client_table, (hash_link *) c);
    return c;
}

void
clientdbInit(void)
{
    if (client_table)
	return;
    client_table = hash_create((HASHCMP *) strcmp, 229, hash_string);
    cachemgrRegister("client_list",
	"Cache Client List",
	clientdbDump,
	0);
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

#define CUTOFF_SECONDS 3600
int
clientdbCutoffDenied(struct in_addr addr)
{
    char *key;
    int NR;
    int ND;
    double p;
    ClientInfo *c;
    if (!Config.onoff.client_db)
	return 0;
    key = inet_ntoa(addr);
    c = (ClientInfo *) hash_lookup(client_table, key);
    if (c == NULL)
	return 0;
    /*
     * If we are in a cutoff window, we don't send a reply
     */
    if (squid_curtime - c->cutoff.time < CUTOFF_SECONDS)
	return 1;
    /*
     * Calculate the percent of DENIED replies since the last
     * cutoff time.
     */
    NR = c->Icp.n_requests - c->cutoff.n_req;
    if (NR < 150)
	NR = 150;
    ND = c->Icp.result_hist[LOG_UDP_DENIED] - c->cutoff.n_denied;
    p = 100.0 * ND / NR;
    if (p < 95.0)
	return 0;
    debug(1, 0) ("WARNING: Probable misconfigured neighbor at %s\n", key);
    debug(1, 0) ("WARNING: %d of the last %d ICP replies are DENIED\n", ND, NR);
    debug(1, 0) ("WARNING: No replies will be sent for the next %d seconds\n",
	CUTOFF_SECONDS);
    c->cutoff.time = squid_curtime;
    c->cutoff.n_req = c->Icp.n_requests;
    c->cutoff.n_denied = c->Icp.result_hist[LOG_UDP_DENIED];
    return 1;
}


void
clientdbDump(StoreEntry * sentry)
{
    ClientInfo *c;
    log_type l;
    storeAppendPrintf(sentry, "Cache Clients:\n");
    c = (ClientInfo *) hash_first(client_table);
    while (c) {
	storeAppendPrintf(sentry, "Address: %s\n", c->key);
	storeAppendPrintf(sentry, "Name: %s\n", fqdnFromAddr(c->addr));
	storeAppendPrintf(sentry, "    ICP Requests %d\n",
	    c->Icp.n_requests);
	for (l = LOG_TAG_NONE; l < LOG_TYPE_MAX; l++) {
	    if (c->Icp.result_hist[l] == 0)
		continue;
	    storeAppendPrintf(sentry,
		"        %-20.20s %7d %3d%%\n",
		log_tags[l],
		c->Icp.result_hist[l],
		percent(c->Icp.result_hist[l], c->Icp.n_requests));
	}
	storeAppendPrintf(sentry, "    HTTP Requests %d\n",
	    c->Http.n_requests);
	for (l = LOG_TAG_NONE; l < LOG_TYPE_MAX; l++) {
	    if (c->Http.result_hist[l] == 0)
		continue;
	    storeAppendPrintf(sentry,
		"        %-20.20s %7d %3d%%\n",
		log_tags[l],
		c->Http.result_hist[l],
		percent(c->Http.result_hist[l], c->Http.n_requests));
	}
	storeAppendPrintf(sentry, "\n");
	c = (ClientInfo *) hash_next(client_table);
    }
}
