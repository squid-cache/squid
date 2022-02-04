/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#include "squid.h"
#include "cache_snmp.h"
#include "CachePeer.h"
#include "globals.h"
#include "mem_node.h"
#include "neighbors.h"
#include "snmp_agent.h"
#include "snmp_core.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "SquidTime.h"
#include "stat.h"
#include "StatCounters.h"
#include "StatHist.h"
#include "Store.h"
#include "tools.h"
// for tvSubDsec() which should be in SquidTime.h
#include "util.h"

/************************************************************************

 SQUID MIB Implementation

 ************************************************************************/

/*
 * cacheSystem group
 */

variable_list *
snmp_sysFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer = NULL;
    MemBuf tmp;
    debugs(49, 5, "snmp_sysFn: Processing request:" << snmpDebugOid(Var->name, Var->name_length, tmp));
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_SYS]) {

    case SYSVMSIZ:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      mem_node::StoreMemSize() >> 10,
                                      ASN_INTEGER);
        break;

    case SYSSTOR:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      Store::Root().currentSize() >> 10,
                                      ASN_INTEGER);
        break;

    case SYS_UPTIME:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (int)(tvSubDsec(squid_start, current_time) * 100),
                                      SMI_TIMETICKS);
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        break;
    }

    return Answer;
}

/*
 * cacheConfig group
 */
variable_list *
snmp_confFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer = NULL;
    const char *cp = NULL;
    debugs(49, 5, "snmp_confFn: Processing request with magic " << Var->name[8] << "!");
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_CONF]) {

    case CONF_ADMIN:
        Answer = snmp_var_new(Var->name, Var->name_length);
        Answer->type = ASN_OCTET_STR;
        Answer->val_len = strlen(Config.adminEmail);
        Answer->val.string = (u_char *) xstrdup(Config.adminEmail);
        break;

    case CONF_VERSION:
        Answer = snmp_var_new(Var->name, Var->name_length);
        Answer->type = ASN_OCTET_STR;
        Answer->val_len = strlen(APP_SHORTNAME);
        Answer->val.string = (u_char *) xstrdup(APP_SHORTNAME);
        break;

    case CONF_VERSION_ID:
        Answer = snmp_var_new(Var->name, Var->name_length);
        Answer->type = ASN_OCTET_STR;
        Answer->val_len = strlen(VERSION);
        Answer->val.string = (u_char *) xstrdup(VERSION);
        break;

    case CONF_STORAGE:

        switch (Var->name[LEN_SQ_CONF + 1]) {

        case CONF_ST_MMAXSZ:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) (Config.memMaxSize >> 20),
                                          ASN_INTEGER);
            break;

        case CONF_ST_SWMAXSZ:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) (Store::Root().maxSize() >> 20),
                                          ASN_INTEGER);
            break;

        case CONF_ST_SWHIWM:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) Config.Swap.highWaterMark,
                                          ASN_INTEGER);
            break;

        case CONF_ST_SWLOWM:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) Config.Swap.lowWaterMark,
                                          ASN_INTEGER);
            break;

        default:
            *ErrP = SNMP_ERR_NOSUCHNAME;
            break;
        }

        break;

    case CONF_LOG_FAC:
        Answer = snmp_var_new(Var->name, Var->name_length);

        if (!(cp = Debug::debugOptions))
            cp = "None";

        Answer->type = ASN_OCTET_STR;

        Answer->val_len = strlen(cp);

        Answer->val.string = (u_char *) xstrdup(cp);

        break;

    case CONF_UNIQNAME:
        Answer = snmp_var_new(Var->name, Var->name_length);

        cp = uniqueHostname();

        Answer->type = ASN_OCTET_STR;

        Answer->val_len = strlen(cp);

        Answer->val.string = (u_char *) xstrdup(cp);

        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;

        break;
    }

    return Answer;
}

/*
 * cacheMesh group
 *   - cachePeerTable
 */
variable_list *
snmp_meshPtblFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer = NULL;

    Ip::Address laddr;
    char *cp = NULL;
    CachePeer *p = NULL;
    int cnt = 0;
    debugs(49, 5, "snmp_meshPtblFn: peer " << Var->name[LEN_SQ_MESH + 3] << " requested!");
    *ErrP = SNMP_ERR_NOERROR;

    u_int index = Var->name[LEN_SQ_MESH + 3] ;
    for (p = Config.peers; p != NULL; p = p->next, ++cnt) {
        if (p->index == index) {
            laddr = p->in_addr ;
            break;
        }
    }

    if (p == NULL) {
        *ErrP = SNMP_ERR_NOSUCHNAME;
        return NULL;
    }

    switch (Var->name[LEN_SQ_MESH + 2]) {
    case MESH_PTBL_INDEX: { // XXX: Should be visible?
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint)p->index, SMI_INTEGER);
    }
    break;

    case MESH_PTBL_NAME:
        cp = p->host;
        Answer = snmp_var_new(Var->name, Var->name_length);
        Answer->type = ASN_OCTET_STR;
        Answer->val_len = strlen(cp);
        Answer->val.string = (u_char *) xstrdup(cp);

        break;

    case MESH_PTBL_ADDR_TYPE: {
        int ival;
        ival = laddr.isIPv4() ? INETADDRESSTYPE_IPV4 : INETADDRESSTYPE_IPV6 ;
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      ival, SMI_INTEGER);
    }
    break;
    case MESH_PTBL_ADDR: {
        Answer = snmp_var_new(Var->name, Var->name_length);
        // InetAddress doesn't have its own ASN.1 type,
        // like IpAddr does (SMI_IPADDRESS)
        // See: rfc4001.txt
        Answer->type = ASN_OCTET_STR;
        char host[MAX_IPSTRLEN];
        laddr.toStr(host,MAX_IPSTRLEN);
        Answer->val_len = strlen(host);
        Answer->val.string =  (u_char *) xstrdup(host);
    }
    break;

    case MESH_PTBL_HTTP:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) p->http_port,
                                      ASN_INTEGER);
        break;

    case MESH_PTBL_ICP:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) p->icp.port,
                                      ASN_INTEGER);
        break;

    case MESH_PTBL_TYPE:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) p->type,
                                      ASN_INTEGER);
        break;

    case MESH_PTBL_STATE:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) neighborUp(p),
                                      ASN_INTEGER);
        break;

    case MESH_PTBL_SENT:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      p->stats.pings_sent,
                                      SMI_COUNTER32);
        break;

    case MESH_PTBL_PACKED:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      p->stats.pings_acked,
                                      SMI_COUNTER32);
        break;

    case MESH_PTBL_FETCHES:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      p->stats.fetches,
                                      SMI_COUNTER32);
        break;

    case MESH_PTBL_RTT:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      p->stats.rtt,
                                      ASN_INTEGER);
        break;

    case MESH_PTBL_IGN:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      p->stats.ignored_replies,
                                      SMI_COUNTER32);
        break;

    case MESH_PTBL_KEEPAL_S:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      p->stats.n_keepalives_sent,
                                      SMI_COUNTER32);
        break;

    case MESH_PTBL_KEEPAL_R:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      p->stats.n_keepalives_recv,
                                      SMI_COUNTER32);
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        break;
    }

    return Answer;
}

variable_list *
snmp_prfSysFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer = NULL;

    static struct rusage rusage;
    debugs(49, 5, "snmp_prfSysFn: Processing request with magic " << Var->name[LEN_SQ_PRF + 1] << "!");
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_PRF + 1]) {

    case PERF_SYS_PF:
        squid_getrusage(&rusage);
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      rusage_pagefaults(&rusage),
                                      SMI_COUNTER32);
        break;

    case PERF_SYS_NUMR:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      IOStats.Http.reads,
                                      SMI_COUNTER32);
        break;

    case PERF_SYS_MEMUSAGE:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) statMemoryAccounted() >> 10,
                                      ASN_INTEGER);
        break;

    case PERF_SYS_CPUTIME:
        squid_getrusage(&rusage);
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) rusage_cputime(&rusage),
                                      ASN_INTEGER);
        break;

    case PERF_SYS_CPUUSAGE:
        squid_getrusage(&rusage);
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) Math::doublePercent(rusage_cputime(&rusage), tvSubDsec(squid_start, current_time)),
                                      ASN_INTEGER);
        break;

    case PERF_SYS_MAXRESSZ:
        squid_getrusage(&rusage);
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) rusage_maxrss(&rusage),
                                      ASN_INTEGER);
        break;

    case PERF_SYS_CURLRUEXP:
        /* No global LRU info anymore */
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      0,
                                      SMI_TIMETICKS);
        break;

    case PERF_SYS_CURUNLREQ:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) statCounter.unlink.requests,
                                      SMI_GAUGE32);
        break;

    case PERF_SYS_CURUNUSED_FD:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) Squid_MaxFD - Number_FD,
                                      SMI_GAUGE32);
        break;

    case PERF_SYS_CURRESERVED_FD:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) RESERVED_FD,
                                      SMI_GAUGE32);
        break;

    case PERF_SYS_CURUSED_FD:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) Number_FD,
                                      SMI_GAUGE32);
        break;

    case PERF_SYS_CURMAX_FD:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) Biggest_FD,
                                      SMI_GAUGE32);
        break;

    case PERF_SYS_NUMOBJCNT:
        Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                      (snint) StoreEntry::inUseCount(),
                                      SMI_GAUGE32);
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        break;
    }

    return Answer;
}

variable_list *
snmp_prfProtoFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer = NULL;
    static StatCounters *f = NULL;
    static StatCounters *l = NULL;
    double x;
    int minutes;
    debugs(49, 5, "snmp_prfProtoFn: Processing request with magic " << Var->name[LEN_SQ_PRF] << "!");
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_PRF + 1]) {

    case PERF_PROTOSTAT_AGGR:   /* cacheProtoAggregateStats */

        switch (Var->name[LEN_SQ_PRF + 2]) {

        case PERF_PROTOSTAT_AGGR_HTTP_REQ:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.client_http.requests,
                                          SMI_COUNTER32);
            break;

        case PERF_PROTOSTAT_AGGR_HTTP_HITS:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.client_http.hits,
                                          SMI_COUNTER32);
            break;

        case PERF_PROTOSTAT_AGGR_HTTP_ERRORS:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.client_http.errors,
                                          SMI_COUNTER32);
            break;

        case PERF_PROTOSTAT_AGGR_HTTP_KBYTES_IN:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.client_http.kbytes_in.kb,
                                          SMI_COUNTER32);
            break;

        case PERF_PROTOSTAT_AGGR_HTTP_KBYTES_OUT:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.client_http.kbytes_out.kb,
                                          SMI_COUNTER32);
            break;

        case PERF_PROTOSTAT_AGGR_ICP_S:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.icp.pkts_sent,
                                          SMI_COUNTER32);
            break;

        case PERF_PROTOSTAT_AGGR_ICP_R:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.icp.pkts_recv,
                                          SMI_COUNTER32);
            break;

        case PERF_PROTOSTAT_AGGR_ICP_SKB:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.icp.kbytes_sent.kb,
                                          SMI_COUNTER32);
            break;

        case PERF_PROTOSTAT_AGGR_ICP_RKB:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.icp.kbytes_recv.kb,
                                          SMI_COUNTER32);
            break;

        case PERF_PROTOSTAT_AGGR_REQ:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.server.all.requests,
                                          SMI_INTEGER);
            break;

        case PERF_PROTOSTAT_AGGR_ERRORS:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.server.all.errors,
                                          SMI_INTEGER);
            break;

        case PERF_PROTOSTAT_AGGR_KBYTES_IN:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.server.all.kbytes_in.kb,
                                          SMI_COUNTER32);
            break;

        case PERF_PROTOSTAT_AGGR_KBYTES_OUT:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.server.all.kbytes_out.kb,
                                          SMI_COUNTER32);
            break;

        case PERF_PROTOSTAT_AGGR_CURSWAP:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) Store::Root().currentSize() >> 10,
                                          SMI_GAUGE32);
            break;

        case PERF_PROTOSTAT_AGGR_CLIENTS:
            Answer = snmp_var_new_integer(Var->name, Var->name_length,
                                          (snint) statCounter.client_http.clients,
                                          SMI_GAUGE32);
            break;

        default:
            *ErrP = SNMP_ERR_NOSUCHNAME;
            break;
        }

        return Answer;

    case PERF_PROTOSTAT_MEDIAN:

        if (Var->name_length == LEN_SQ_PRF + 5)
            minutes = Var->name[LEN_SQ_PRF + 4];
        else
            break;

        if ((minutes < 1) || (minutes > 60))
            break;

        f = snmpStatGet(0);

        l = snmpStatGet(minutes);

        debugs(49, 8, "median: min= " << minutes << ", " << Var->name[LEN_SQ_PRF + 3] << " l= " << l << " , f = " << f);
        debugs(49, 8, "median: l= " << l << " , f = " << f);

        switch (Var->name[LEN_SQ_PRF + 3]) {

        case PERF_MEDIAN_TIME:
            x = minutes;
            break;

        case PERF_MEDIAN_HTTP_ALL:
            x = statHistDeltaMedian(l->client_http.allSvcTime,
                                    f->client_http.allSvcTime);
            break;

        case PERF_MEDIAN_HTTP_MISS:
            x = statHistDeltaMedian(l->client_http.missSvcTime,
                                    f->client_http.missSvcTime);
            break;

        case PERF_MEDIAN_HTTP_NM:
            x = statHistDeltaMedian(l->client_http.nearMissSvcTime,
                                    f->client_http.nearMissSvcTime);
            break;

        case PERF_MEDIAN_HTTP_HIT:
            x = statHistDeltaMedian(l->client_http.hitSvcTime,
                                    f->client_http.hitSvcTime);
            break;

        case PERF_MEDIAN_ICP_QUERY:
            x = statHistDeltaMedian(l->icp.querySvcTime, f->icp.querySvcTime);
            break;

        case PERF_MEDIAN_ICP_REPLY:
            x = statHistDeltaMedian(l->icp.replySvcTime, f->icp.replySvcTime);
            break;

        case PERF_MEDIAN_DNS:
            x = statHistDeltaMedian(l->dns.svcTime, f->dns.svcTime);
            break;

        case PERF_MEDIAN_RHR:
            x = statRequestHitRatio(minutes);
            break;

        case PERF_MEDIAN_BHR:
            x = statByteHitRatio(minutes);
            break;

        case PERF_MEDIAN_HTTP_NH:
            x = statHistDeltaMedian(l->client_http.nearHitSvcTime,
                                    f->client_http.nearHitSvcTime);
            break;

        default:
            *ErrP = SNMP_ERR_NOSUCHNAME;
            return NULL;
        }

        return snmp_var_new_integer(Var->name, Var->name_length,
                                    (snint) x,
                                    SMI_INTEGER);
    }

    *ErrP = SNMP_ERR_NOSUCHNAME;
    return NULL;
}

