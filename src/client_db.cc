
/*
 * $Id: client_db.cc,v 1.35 1998/06/08 17:29:16 wessels Exp $
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
static FREE clientdbFreeItem;

static ClientInfo *
clientdbAdd(struct in_addr addr)
{
    ClientInfo *c;
    c = memAllocate(MEM_CLIENT_INFO);
    c->key = xstrdup(inet_ntoa(addr));
    c->addr = addr;
    hash_join(client_table, (hash_link *) c);
    Counter.client_http.clients++;
    return c;
}

void
clientdbInit(void)
{
    if (client_table)
	return;
    client_table = hash_create((HASHCMP *) strcmp, 467, hash_string);
    cachemgrRegister("client_list",
	"Cache Client List",
	clientdbDump,
	0);
}

void
clientdbUpdate(struct in_addr addr, log_type log_type, protocol_t p, size_t size)
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
	kb_incr(&c->Http.kbytes_out, size);
	if (isTcpHit(log_type))
	    kb_incr(&c->Http.hit_kbytes_out, size);
    } else if (p == PROTO_ICP) {
	c->Icp.n_requests++;
	c->Icp.result_hist[log_type]++;
	kb_incr(&c->Icp.kbytes_out, size);
	if (LOG_UDP_HIT == log_type)
	    kb_incr(&c->Icp.hit_kbytes_out, size);
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
    int icp_total = 0;
    int icp_hits = 0;
    int http_total = 0;
    int http_hits = 0;
    storeAppendPrintf(sentry, "Cache Clients:\n");
    hash_first(client_table);
    while ((c = (ClientInfo *) hash_next(client_table))) {
	storeAppendPrintf(sentry, "Address: %s\n", c->key);
	storeAppendPrintf(sentry, "Name: %s\n", fqdnFromAddr(c->addr));
	storeAppendPrintf(sentry, "    ICP Requests %d\n",
	    c->Icp.n_requests);
	for (l = LOG_TAG_NONE; l < LOG_TYPE_MAX; l++) {
	    if (c->Icp.result_hist[l] == 0)
		continue;
	    icp_total += c->Icp.result_hist[l];
	    if (LOG_UDP_HIT == l)
		icp_hits += c->Icp.result_hist[l];
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
	    http_total += c->Http.result_hist[l];
	    if (isTcpHit(l))
		http_hits += c->Http.result_hist[l];
	    storeAppendPrintf(sentry,
		"        %-20.20s %7d %3d%%\n",
		log_tags[l],
		c->Http.result_hist[l],
		percent(c->Http.result_hist[l], c->Http.n_requests));
	}
	storeAppendPrintf(sentry, "\n");
    }
    storeAppendPrintf(sentry, "TOTALS\n");
    storeAppendPrintf(sentry, "ICP : %d Queries, %d Hits (%3d%%)\n",
	icp_total, icp_hits, percent(icp_hits, icp_total));
    storeAppendPrintf(sentry, "HTTP: %d Requests, %d Hits (%3d%%)\n",
	http_total, http_hits, percent(http_hits, http_total));
}

static void
clientdbFreeItem(void *data)
{
    ClientInfo *c = data;
    safe_free(c->key);
    memFree(MEM_CLIENT_INFO, c);
}

void
clientdbFreeMemory(void)
{
    hashFreeItems(client_table, clientdbFreeItem);
    hashFreeMemory(client_table);
    client_table = NULL;
}

#if SQUID_SNMP
int
meshCtblGetRowFn(oid * New, oid * Oid)
{
    ClientInfo *c = NULL;

    if (!Oid[0] && !Oid[1] && !Oid[2] && !Oid[3]) {
	hash_first(client_table);
	c = (ClientInfo *) hash_next(client_table);
    } else {
	char key[15];
	snprintf(key, sizeof(key), "%d.%d.%d.%d", Oid[0], Oid[1], Oid[2], Oid[3]);
	c = (ClientInfo *) hash_lookup(client_table, key);
	if (NULL != c)
	    c = c->next;
    }
    if (!c)
	return 0;
    addr2oid(c->addr, New);
    return 1;
}


variable_list *
snmp_meshCtblFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer;
    static char key[15];
    ClientInfo *c = NULL;
    int aggr = 0;
    log_type l;

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    snprintf(key, sizeof(key), "%d.%d.%d.%d", Var->name[11], Var->name[12],
	Var->name[13], Var->name[14]);
    debug(49, 5) ("snmp_meshCtblFn: [%s] requested!\n", key);
    c = (ClientInfo *) hash_lookup(client_table, key);
    if (c == NULL) {
	debug(49, 5) ("snmp_meshCtblFn: not found.\n");
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    switch (Var->name[10]) {
    case MESH_CTBL_ADDR:
	Answer->type = SMI_IPADDRESS;
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	*(Answer->val.integer) = (snint) c->addr.s_addr;
	break;
    case MESH_CTBL_HTBYTES:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (snint) c->Http.kbytes_out.kb;
	break;
    case MESH_CTBL_HTREQ:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (snint) c->Http.n_requests;
	break;
    case MESH_CTBL_HTHITS:
	aggr = 0;
	for (l = 0; l < LOG_TYPE_MAX; l++) {
	    if (isTcpHit(l))
		aggr += c->Http.result_hist[l];
	}
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (snint) aggr;
	break;
    case MESH_CTBL_HTHITBYTES:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (snint) c->Http.hit_kbytes_out.kb;
	break;
    case MESH_CTBL_ICPBYTES:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (snint) c->Icp.kbytes_out.kb;
	break;
    case MESH_CTBL_ICPREQ:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (snint) c->Icp.n_requests;
	break;
    case MESH_CTBL_ICPHITS:
	aggr = c->Icp.result_hist[LOG_UDP_HIT];
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (snint) aggr;
	break;
    case MESH_CTBL_ICPHITBYTES:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (snint) c->Icp.hit_kbytes_out.kb;
	break;

    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	debug(49, 5) ("snmp_meshCtblFn: illegal column.\n");
	return (NULL);
    }
    return Answer;
}

#endif
