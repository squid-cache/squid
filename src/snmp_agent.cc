
/*
 * $Id: snmp_agent.cc,v 1.52 1998/07/23 03:13:11 wessels Exp $
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

#include "snmp.h"
#include "snmp_impl.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_vars.h"
#include "snmp_oidlist.h"
#include "cache_snmp.h"

extern StatCounters *snmpStatGet(int);


/************************************************************************

 SQUID MIB Implementation

 ************************************************************************/

variable_list *
snmp_basicFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer;
    char *pp;
    oid object_id[LEN_SQUID_OBJ_ID] = {SQUID_OBJ_ID};

    debug(49, 5) ("snmp_basicFn: Processing request with magic %d!\n", Var->name[7]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[7]) {
    case SYS_DESCR:
	pp = SQUID_SYS_DESCR;
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(pp);
	Answer->val.string = (u_char *) xstrdup(pp);
	break;
    case SYS_OBJECT_ID:
	Answer->type = ASN_OBJECT_ID;
        Answer->val_len = sizeof(object_id);
        Answer->val.objid = oiddup(object_id, LEN_SQUID_OBJ_ID);
	break;
    case SYS_UPTIME:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = SMI_TIMETICKS;
	*(Answer->val.integer) = (snint) (tvSubDsec(squid_start, current_time));
	break;
    case SYS_CONTACT:
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(Config.adminEmail);
	Answer->val.string = (u_char *) xstrdup(Config.adminEmail);
	break;
    case SYS_NAME:
	if ((pp = Config.visibleHostname) == NULL)
	    pp = (char *) getMyHostname();
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(pp);
	Answer->val.string = (u_char *) xstrdup(pp);
	break;
    case SYS_LOCATION:
	pp = "Cyberspace";
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(pp);
	Answer->val.string = (u_char *) xstrdup(pp);
	break;
    case SYS_SERVICES:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = ASN_INTEGER;
	*(Answer->val.integer) = 72;
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    return (Answer);
}

variable_list *
snmp_sysFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer;
    static fde *f = NULL;
    int num = 1, cnt = 0;
    static char addrbuf[16];
    static struct in_addr addr;
    static snint snint_return;

    debug(49, 5) ("snmp_sysFn: Processing request:\n", Var->name[8]);
    snmpDebugOid(5, Var->name, Var->name_length);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[8]) {
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
    case SYSCONNTBL:
	snprintf(addrbuf, 16, "%d.%d.%d.%d", Var->name[11], Var->name[12],
	    Var->name[13], Var->name[14]);

	debug(49, 9) ("snmp_sysFn: CONN Table, [%s]\n", addrbuf);

	while (cnt < Squid_MaxFD) {
	    f = &fd_table[cnt++];
	    if (!f->open)
		continue;
	    if (f->type == FD_SOCKET && !strcmp(f->ipaddr, addrbuf) &&
		f->remote_port == Var->name[15])
		break;
	}
	if (!f || cnt == Squid_MaxFD) {
	    debug(49, 9) ("snmp_sysFn: no such name. %x\n", f);
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
	switch (Var->name[10]) {
	case SYS_CONN_FDNUM:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = Var->name[11];
	    break;
	case SYS_CONN_PORT:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = f->remote_port;
	    break;
	case SYS_CONN_READ:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (snint) f->bytes_read;
	    break;
	case SYS_CONN_WRITE:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (snint) f->bytes_written;
	    break;
	case SYS_CONN_ADDR:
	    safe_inet_addr(f->ipaddr, &addr);
	    snint_return = (snint) addr.s_addr;
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = SMI_IPADDRESS;
	    *(Answer->val.integer) = (snint) snint_return;
	    break;
	case SYS_CONN_NAME:
	    Answer->type = ASN_OCTET_STR;
	    Answer->val_len = strlen(f->desc);
	    Answer->val.string = (u_char *) xstrdup(f->desc);
	    break;
	default:
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
	break;			/* end SYSCONNTBL */
    case SYSFDTBL:
	num = Var->name[11];
	debug(49, 9) ("snmp_sysFn: FD Table, num=%d\n", num);
	while (num && cnt < Squid_MaxFD) {
	    f = &fd_table[cnt++];
	    if (!f->open)
		continue;
	    if (f->type != FD_SOCKET)
		num--;
	}
	if (num != 0 || !f) {
	    debug(49, 9) ("snmp_sysFn: no such name. %x\n", f);
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
	switch (Var->name[10]) {
	case SYS_FD_NUMBER:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = Var->name[11];
	    break;
#if UNIMPLEMENTED
	case SYS_FD_TYPE:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = f->type;
	    break;

	case SYS_FD_TOUT:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (snint) (f->timeout_handler ? (f->timeout - squid_curtime) / 60 : 0);
	    break;
#endif
	case SYS_FD_NREAD:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (snint) f->bytes_read;
	    break;
	case SYS_FD_NWRITE:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (snint) f->bytes_written;
	    break;
	case SYS_FD_NAME:
	    Answer->type = ASN_OCTET_STR;
	    Answer->val_len = strlen(f->desc);
	    Answer->val.string = (u_char *) xstrdup(f->desc);
	    break;
	default:
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
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

    switch (Var->name[8]) {
    case CONF_ADMIN:
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(Config.adminEmail);
	Answer->val.string = (u_char *) xstrdup(Config.adminEmail);
	break;
    case CONF_UPTIME:
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	Answer->type = SMI_TIMETICKS;
	*(Answer->val.integer) = tvSubDsec(squid_start, current_time);
	break;
    case CONF_VERSION:
	pp = "Squid";
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(pp);
	Answer->val.string = (u_char *) xstrdup(pp);
	break;
    case CONF_VERSION_ID:
	pp = SQUID_VERSION;
	Answer->type = ASN_OCTET_STR;
	Answer->val_len = strlen(pp);
	Answer->val.string = (u_char *) xstrdup(pp);
	break;
    case CONF_STORAGE:
	switch (Var->name[9]) {
	case CONF_ST_MMAXSZ:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (snint) Config.Mem.maxSize;
	    break;
	case CONF_ST_MHIWM:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (snint) Config.Mem.highWaterMark;
	    break;
	case CONF_ST_MLOWM:
	    Answer->val_len = sizeof(snint);
	    Answer->val.integer = xmalloc(Answer->val_len);
	    Answer->type = ASN_INTEGER;
	    *(Answer->val.integer) = (snint) Config.Mem.lowWaterMark;
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
    debug(49, 5) ("snmp_meshPtblFn: peer %d requested!\n", Var->name[11]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    laddr = oid2addr(&Var->name[11]);

    for (p = Config.peers; p != NULL; p = p->next, cnt++)
	if (p->in_addr.sin_addr.s_addr == laddr->s_addr)
	    break;

#if SNMP_OLD_INDEX
    p = Config.peers;
    cnt = Var->name[11];
    debug(49, 5) ("snmp_meshPtblFn: we want .x.%d\n", Var->name[10]);
    while (--cnt)
	if (!(p = p->next));
#endif
    if (p == NULL) {
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	return (NULL);
    }
    switch (Var->name[10]) {
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
	*(Answer->val.integer) = (snint) p->icp_port;
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

    debug(49, 5) ("snmp_prfSysFn: Processing request with magic %d!\n", Var->name[9]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;
    Answer->val_len = sizeof(snint);
    Answer->val.integer = xmalloc(Answer->val_len);
    Answer->type = ASN_INTEGER;

    switch (Var->name[9]) {
    case PERF_SYS_PF:
	squid_getrusage(&rusage);
	*(Answer->val.integer) = rusage_pagefaults(&rusage);
	break;
    case PERF_SYS_NUMR:
	*(Answer->val.integer) = IOStats.Http.reads;
	break;
    case PERF_SYS_DEFR:
	*(Answer->val.integer) = IOStats.Http.reads_deferred;
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
	*(Answer->val.integer) = (snint) storeExpiredReferenceAge();
	break;
    case PERF_SYS_CURUNLREQ:
	*(Answer->val.integer) = (snint) Counter.unlink.requests;
	break;
    case PERF_SYS_CURUNUSED_FD:
	*(Answer->val.integer) = (snint) Squid_MaxFD - Number_FD;
	break;
    case PERF_SYS_CURRESERVED_FD:
	*(Answer->val.integer) = (snint) Number_FD;
	break;
    case PERF_SYS_NUMOBJCNT:
	*(Answer->val.integer) = (snint) memInUse(MEM_STOREENTRY);
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

    debug(49, 5) ("snmp_prfProtoFn: Processing request with magic %d!\n", Var->name[8]);

    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[9]) {
    case PERF_PROTOSTAT_AGGR:	/* cacheProtoAggregateStats */
	Answer->type = SMI_COUNTER32;
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);
	switch (Var->name[10]) {
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
	    break;
	case PERF_PROTOSTAT_AGGR_ERRORS:
	    *(Answer->val.integer) = (snint) Counter.server.all.errors;
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
	default:
	    *ErrP = SNMP_ERR_NOSUCHNAME;
	    snmp_var_free(Answer);
	    return (NULL);
	}
	return Answer;
    case PERF_PROTOSTAT_MEDIAN:

	minutes = Var->name[12];

	f = snmpStatGet(0);
	l = snmpStatGet(minutes);

	debug(49, 8) ("median: min= %d, %d l= %x , f = %x\n", minutes,
	    Var->name[11], l, f);
	Answer->type = SMI_INTEGER;
	Answer->val_len = sizeof(snint);
	Answer->val.integer = xmalloc(Answer->val_len);

	debug(49, 8) ("median: l= %x , f = %x\n", l, f);
	switch (Var->name[11]) {
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


variable_list *
snmp_dnsFn(variable_list * Var, snint * ErrP)
{
    debug(49, 5) ("snmp_dnsFn: Processing request with magic %d!\n", Var->name[9]);
    if (Var->name[9] == NET_DNS_IPCACHE)
	return snmp_ipcacheFn(Var, ErrP);
    if (Var->name[9] == NET_DNS_FQDNCACHE)
	return snmp_fqdncacheFn(Var, ErrP);

    return NULL;
}

void
addr2oid(struct in_addr addr, oid * Dest)
{
    u_char *cp;
    cp = (u_char *) & (addr.s_addr);
    Dest[0] = *cp++;
    Dest[1] = *cp++;
    Dest[2] = *cp++;
    Dest[3] = *cp++;
}

struct in_addr *
oid2addr(oid * id)
{
    static struct in_addr laddr;
    u_char *cp = (u_char *) & (laddr.s_addr);
    cp[0] = id[0];
    cp[1] = id[1];
    cp[2] = id[2];
    cp[3] = id[3];
    return &laddr;
}
