
/*
 * $Id: client_db.cc,v 1.26 1998/03/25 09:21:43 kostas Exp $
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
	kb_incr(&(c->Http.kbytes_out), size);
	c->Http.result_hist[log_type]++;
    } else if (p == PROTO_ICP) {
	c->Icp.n_requests++;
	kb_incr(&(c->Icp.kbytes_out), size);
	c->Icp.result_hist[log_type]++;
    }
    switch (log_type) {
    case LOG_TCP_HIT:
    case LOG_TCP_REFRESH_HIT:
    case LOG_TCP_REFRESH_FAIL_HIT:
    case LOG_TCP_IMS_HIT:
    case LOG_TCP_NEGATIVE_HIT:
    case LOG_TCP_MEM_HIT:
    case LOG_UDP_HIT:
	if (p==PROTO_ICP)
		kb_incr(&(c->Icp.hit_kbytes_out), size);
	else
		kb_incr(&(c->Http.hit_kbytes_out),size);
	break;
    default:
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

void
clientdbFreeMemory(void)
{
    ClientInfo *c;
    ClientInfo **C;
    int i = 0;
    int j;
    int n = memInUse(MEM_CLIENT_INFO);
    C = xcalloc(n, sizeof(ClientInfo *));
    c = (ClientInfo *) hash_first(client_table);
    while (c && i < n) {
        *(C + i) = c;
        i++;
        c = (ClientInfo *) hash_next(client_table);
    }
    for (j = 0; j < i; j++) {
        c = *(C + j);
        memFree(MEM_CLIENT_INFO, c);
    }
    xfree(C);
    hashFreeMemory(client_table);
    client_table = NULL;
}

#if SQUID_SNMP
int meshCtblGetRowFn(oid *New,oid *Oid)
{
        ClientInfo *c = NULL;
	static char key[15];

        if (!Oid[0]&&!Oid[1]&&!Oid[2]&&!Oid[3])
        	c = (ClientInfo *)hash_first(client_table);
        else {
		snprintf(key,15,"%d.%d.%d.%d", Oid[0], Oid[1],Oid[2],Oid[3]);
    		c = (ClientInfo *) hash_lookup(client_table, key);
		if (!c) return 0;
		c= (ClientInfo *)hash_next(client_table);
	}
	if (!c) return 0;
        addr2oid(c->addr, New);
 	return 1;
}


variable_list *
snmp_meshCtblFn(variable_list * Var, snint *ErrP)
{
    variable_list *Answer;
    static char key[15];
    ClientInfo *c = NULL;
    int aggr=0;
#if 0
    int cnt;
#endif

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    snprintf(key,15,"%d.%d.%d.%d", Var->name[11], Var->name[12],
			Var->name[13],Var->name[14]);
    debug(49, 5) ("snmp_meshCtblFn: [%s] requested!\n", key);
    c = (ClientInfo *) hash_lookup(client_table, key);
#if 0
    c=(ClientInfo *)hash_first(client_table);
    cnt = Var->name[11];
    debug(49, 5) ("snmp_meshCtblFn: we want .x.%d\n", Var->name[10]);
    while (--cnt)
        if (!(c = (ClientInfo *) hash_next(client_table)));
#endif
    if (c == NULL) {
	debug(49,5)("snmp_meshCtblFn: not found.\n");
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
        aggr= c->Http.result_hist[LOG_TCP_HIT] + 
		c->Http.result_hist[LOG_TCP_REFRESH_HIT] + 
		c->Http.result_hist[LOG_TCP_REFRESH_FAIL_HIT] +
	  	c->Http.result_hist[LOG_TCP_REFRESH_FAIL_HIT] + 
		c->Http.result_hist[LOG_TCP_IMS_HIT] + 
		c->Http.result_hist[LOG_TCP_NEGATIVE_HIT] +
	  	c->Http.result_hist[LOG_TCP_MEM_HIT] + 
		c->Http.result_hist[LOG_UDP_HIT];
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
        *(Answer->val.integer) = (snint ) c->Icp.kbytes_out.kb;
        break;
    case MESH_CTBL_ICPREQ:
        Answer->val_len = sizeof(snint);
        Answer->val.integer = xmalloc(Answer->val_len);
        Answer->type = ASN_INTEGER;
        *(Answer->val.integer) = (snint) c->Icp.n_requests;
        break;
    case MESH_CTBL_ICPHITS:
        aggr= c->Icp.result_hist[LOG_TCP_HIT] + 
                c->Icp.result_hist[LOG_TCP_REFRESH_HIT] + 
                c->Icp.result_hist[LOG_TCP_REFRESH_FAIL_HIT] +
                c->Icp.result_hist[LOG_TCP_REFRESH_FAIL_HIT] + 
                c->Icp.result_hist[LOG_TCP_IMS_HIT] + 
                c->Icp.result_hist[LOG_TCP_NEGATIVE_HIT] +
                c->Icp.result_hist[LOG_TCP_MEM_HIT] + 
                c->Icp.result_hist[LOG_UDP_HIT];
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
	debug(49,5)("snmp_meshCtblFn: illegal column.\n");
        return (NULL);
    }
    return Answer;
}

#endif
