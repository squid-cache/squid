
/*
 * $Id: snmp_agent.cc,v 1.67 1999/04/23 02:57:31 wessels Exp $
 * $Id: snmp_agent.cc,v 1.67 1999/04/23 02:57:31 wessels Exp $
 *
 * DEBUG: section 49     SNMP Interface
 * AUTHOR: Kostas Anagnostakis
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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
#include "cache_snmp.h"

extern StatCounters *snmpStatGet(int);

/************************************************************************

 SQUID MIB Implementation

 ************************************************************************/

variable_list *
snmp_sysFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer;

    debug(49, 5) ("snmp_sysFn: Processing request:\n", Var->name[LEN_SQ_SYS]);
    snmpDebugOid(5, Var->name, Var->name_length);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_SYS]) {
    case SYSVMSIZ:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = store_mem_size;
	break;
    case SYSSTOR:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = store_swap_size;
	break;
    case SYS_UPTIME:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = SMI_TIMETICKS;
	*(Answer->val.integer) = tvSubDsec(squid_start, current_time) * 100;
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return Answer;
}

variable_list *
snmp_confFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer;
    char *cp = NULL;
    char *pp = NULL;
    debug(49, 5) ("snmp_confFn: Processing request with magic %d!\n", Var->name[8]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_CONF]) {
    case CONF_ADMIN:
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(Config.adminEmail);
	Answer->val.string = (u_char *) xstrdup(Config.adminEmail);
	break;
    case CONF_VERSION:
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(appname);
	Answer->val.string = (u_char *) xstrdup(appname);
	break;
    case CONF_VERSION_ID:
	pp = SQUID_VERSION;
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(pp);
	Answer->val.string = (u_char *) xstrdup(pp);
	break;
    case CONF_STORAGE:
	switch (Var->name[LEN_SQ_CONF + 1]) {
	case CONF_ST_MMAXSZ:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (snint) Config.memMaxSize;
	    break;
	case CONF_ST_SWMAXSZ:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (snint) Config.Swap.maxSize;
	    break;
	case CONF_ST_SWHIWM:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (snint) Config.Swap.highWaterMark;
	    break;
	case CONF_ST_SWLOWM:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (snint) Config.Swap.lowWaterMark;
	    break;
	default:
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
	break;
    case CONF_LOG_FAC:
	if (!(cp = Config.debugOptions))
	    cp = "None";
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(cp);
	Answer->val.string = (u_char *) xstrdup(cp);
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return Answer;
}

variable_list *
snmp_meshPtblFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer;
    struct in_addr *laddr;
    char *cp = NULL;
    peer *p = NULL;
    int cnt = 0;
    debug(49, 5) ("snmp_meshPtblFn: peer %d requested!\n", Var->name[LEN_SQ_MESH + 3]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    laddr = oid2addr(&Var->name[LEN_SQ_MESH + 3]);

    for (p = Config.peers; p != NULL; p = p->next, cnt++)
	if (p->in_addr.sin_addr.s_addr == laddr->s_addr)
	    break;

    if (p == NULL) {
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    switch (Var->name[LEN_SQ_MESH + 2]) {
    case MESH_PTBL_NAME:
	cp = p->host;
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(cp);
	Answer->val.string = (u_char *) xstrdup(cp);
	break;
    case MESH_PTBL_IP:
	Answer->type = SMI_IPADDRESS;
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	*(Answer->val.integer) = (snint) (p->in_addr.sin_addr.s_addr);
	break;
    case MESH_PTBL_HTTP:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (snint) p->http_port;
	break;
    case MESH_PTBL_ICP:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (snint) p->icp.port;
	break;
    case MESH_PTBL_TYPE:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (snint) p->type;
	break;
    case MESH_PTBL_STATE:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = (snint) neighborUp(p);
	break;
    case MESH_PTBL_SENT:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = SMI_COUNTER32;
	*(Answer->val.integer) = p->stats.pings_sent;
	break;
    case MESH_PTBL_PACKED:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = SMI_COUNTER32;
	*(Answer->val.integer) = p->stats.pings_acked;
	break;
    case MESH_PTBL_FETCHES:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = SMI_COUNTER32;
	*(Answer->val.integer) = p->stats.fetches;
	break;
    case MESH_PTBL_RTT:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = p->stats.rtt;
	break;
    case MESH_PTBL_IGN:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = SMI_COUNTER32;
	*(Answer->val.integer) = p->stats.ignored_replies;
	break;
    case MESH_PTBL_KEEPAL_S:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = SMI_COUNTER32;
	*(Answer->val.integer) = p->stats.n_keepalives_sent;
	break;
    case MESH_PTBL_KEEPAL_R:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = SMI_COUNTER32;
	*(Answer->val.integer) = p->stats.n_keepalives_recv;
	break;

    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return Answer;
}

variable_list *
snmp_prfSysFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer;
    static struct rusage rusage;

    debug(49, 5) ("snmp_prfSysFn: Processing request with magic %d!\n", Var->name[LEN_SQ_PRF + 1]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;
    Answer->val_len = sizeof(snint);
    Answer->val.integer = xmalloc(Answer->val_len);
    Answer->type = ASN_INTEGER;

    switch (Var->name[LEN_SQ_PRF + 1]) {
    case PERF_SYS_PF:
	squid_getrusage(&rusage);
	*(Answer->val.integer) = rusage_pagefaults(&rusage);
	Answer->type = SMI_COUNTER32;
	break;
    case PERF_SYS_NUMR:
	*(Answer->val.integer) = IOStats.Http.reads;
	Answer->type = SMI_COUNTER32;
	break;
    case PERF_SYS_DEFR:	/* XXX unused, remove me */
	Answer->type = SMI_COUNTER32;
	*(Answer->val.integer) = 0;
	break;
    case PERF_SYS_MEMUSAGE:
	*(Answer->val.integer) = (snint) memTotalAllocated() >> 10;
	break;
    case PERF_SYS_CPUUSAGE:
	squid_getrusage(&rusage);
	*(Answer->val.integer) = (snint) rusage_cputime(&rusage);
	break;
    case PERF_SYS_MAXRESSZ:
	squid_getrusage(&rusage);
	*(Answer->val.integer) = (snint) rusage_maxrss(&rusage);
	break;
    case PERF_SYS_CURLRUEXP:
	Answer->type = SMI_TIMETICKS;
	*(Answer->val.integer) = (snint) (storeExpiredReferenceAge() * 100);
	break;
    case PERF_SYS_CURUNLREQ:
	*(Answer->val.integer) = (snint) Counter.unlink.requests;
	Answer->type = SMI_COUNTER32;
	break;
    case PERF_SYS_CURUNUSED_FD:
	*(Answer->val.integer) = (snint) Squid_MaxFD - Number_FD;
	Answer->type = SMI_GAUGE32;
	break;
    case PERF_SYS_CURRESERVED_FD:
	*(Answer->val.integer) = (snint) Number_FD;
	Answer->type = SMI_GAUGE32;
	break;
    case PERF_SYS_NUMOBJCNT:
	*(Answer->val.integer) = (snint) memInUse(MEM_STOREENTRY);
	Answer->type = SMI_COUNTER32;
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return Answer;
}

variable_list *
snmp_prfProtoFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer;
    static StatCounters *f = NULL;
    static StatCounters *l = NULL;
    double x;
    int minutes;

    debug(49, 5) ("snmp_prfProtoFn: Processing request with magic %d!\n", Var->name[LEN_SQ_PRF]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_PRF + 1]) {
    case PERF_PROTOSTAT_AGGR:	/* cacheProtoAggregateStats */
	Answer->type = SMI_COUNTER32;
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	switch (Var->name[LEN_SQ_PRF + 2]) {
	case PERF_PROTOSTAT_AGGR_HTTP_REQ:
	    *(Answer->val.integer) = (snint) Counter.client_http.requests;
	    break;
	case PERF_PROTOSTAT_AGGR_HTTP_HITS:
	    *(Answer->val.integer) = (snint) Counter.client_http.hits;
	    break;
	case PERF_PROTOSTAT_AGGR_HTTP_ERRORS:
	    *(Answer->val.integer) = (snint) Counter.client_http.errors;
	    break;
	case PERF_PROTOSTAT_AGGR_HTTP_KBYTES_IN:
	    *(Answer->val.integer) = (snint) Counter.client_http.kbytes_in.kb;
	    break;
	case PERF_PROTOSTAT_AGGR_HTTP_KBYTES_OUT:
	    *(Answer->val.integer) = (snint) Counter.client_http.kbytes_out.kb;
	    break;
	case PERF_PROTOSTAT_AGGR_ICP_S:
	    *(Answer->val.integer) = (snint) Counter.icp.pkts_sent;
	    break;
	case PERF_PROTOSTAT_AGGR_ICP_R:
	    *(Answer->val.integer) = (snint) Counter.icp.pkts_recv;
	    break;
	case PERF_PROTOSTAT_AGGR_ICP_SKB:
	    *(Answer->val.integer) = (snint) Counter.icp.kbytes_sent.kb;
	    break;
	case PERF_PROTOSTAT_AGGR_ICP_RKB:
	    *(Answer->val.integer) = (snint) Counter.icp.kbytes_recv.kb;
	    break;
	case PERF_PROTOSTAT_AGGR_REQ:
	    *(Answer->val.integer) = (snint) Counter.server.all.requests;
	    Answer->type = SMI_INTEGER;
	    break;
	case PERF_PROTOSTAT_AGGR_ERRORS:
	    *(Answer->val.integer) = (snint) Counter.server.all.errors;
	    Answer->type = SMI_INTEGER;
	    break;
	case PERF_PROTOSTAT_AGGR_KBYTES_IN:
	    *(Answer->val.integer) = (snint) Counter.server.all.kbytes_in.kb;
	    break;
	case PERF_PROTOSTAT_AGGR_KBYTES_OUT:
	    *(Answer->val.integer) = (snint) Counter.server.all.kbytes_out.kb;
	    break;
	case PERF_PROTOSTAT_AGGR_CURSWAP:
	    *(Answer->val.integer) = (snint) store_swap_size;
	    break;
	case PERF_PROTOSTAT_AGGR_CLIENTS:
	    *(Answer->val.integer) = (snint) Counter.client_http.clients;
	    break;
	default:
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
	return Answer;
    case PERF_PROTOSTAT_MEDIAN:

	minutes = Var->name[LEN_SQ_PRF + 4];

	f = snmpStatGet(0);
	l = snmpStatGet(minutes);

	debug(49, 8) ("median: min= %d, %d l= %x , f = %x\n", minutes,
	    Var->name[LEN_SQ_PRF + 3], l, f);
	Answer->type = SMI_INTEGER;
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);

	debug(49, 8) ("median: l= %x , f = %x\n", l, f);
	switch (Var->name[LEN_SQ_PRF + 3]) {
	case PERF_MEDIAN_TIME:
	    x = minutes;
	    break;
	case PERF_MEDIAN_HTTP_ALL:
	    x = statHistDeltaMedian(&l->client_http.all_svc_time,
		&f->client_http.all_svc_time);
	    break;
	case PERF_MEDIAN_HTTP_MISS:
	    x = statHistDeltaMedian(&l->client_http.miss_svc_time,
		&f->client_http.miss_svc_time);
	    break;
	case PERF_MEDIAN_HTTP_NM:
	    x = statHistDeltaMedian(&l->client_http.nm_svc_time,
		&f->client_http.nm_svc_time);
	    break;
	case PERF_MEDIAN_HTTP_HIT:
	    x = statHistDeltaMedian(&l->client_http.hit_svc_time,
		&f->client_http.hit_svc_time);
	    break;
	case PERF_MEDIAN_ICP_QUERY:
	    x = statHistDeltaMedian(&l->icp.query_svc_time, &f->icp.query_svc_time);
	    break;
	case PERF_MEDIAN_ICP_REPLY:
	    x = statHistDeltaMedian(&l->icp.reply_svc_time, &f->icp.reply_svc_time);
	    break;
	case PERF_MEDIAN_DNS:
	    x = statHistDeltaMedian(&l->dns.svc_time, &f->dns.svc_time);
	    break;
	case PERF_MEDIAN_RHR:
	    x = statRequestHitRatio(minutes);
	    break;
	case PERF_MEDIAN_BHR:
	    x = statByteHitRatio(minutes);
	    break;
	default:
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
	*(Answer->val.integer) = (snint) x;
	return Answer;
    }
    *ErrP = SNMP_ERR_NOSUCHNAME;
    snmp_var_free(Answer);
    return (NULL);
}
