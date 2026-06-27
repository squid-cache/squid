/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 49    SNMP Interface */

#include "squid.h"
#include "cache_snmp.h"
#include "CachePeer.h"
#include "CachePeers.h"
#include "globals.h"
#include "mem/Meter.h"
#include "mem/Stats.h"
#include "mem_node.h"
#include "neighbors.h"
#include "snmp_agent.h"
#include "snmp_core.h"
#include "SquidConfig.h"
#include "SquidMath.h"
#include "stat.h"
#include "StatCounters.h"
#include "StatHist.h"
#include "Store.h"
#include "store/Controller.h"
#include "StoreStats.h"
#include "tools.h"
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
    MemBuf tmp;
    debugs(49, 5, "snmp_sysFn: Processing request:" << snmpDebugOid(Var->name, Var->name_length, tmp));
    *ErrP = SNMP_ERR_NOERROR;

    int value = 0;
    auto type = ASN_INTEGER; // most of these are Integer
    switch (Var->name[LEN_SQ_SYS]) {

    case SYSVMSIZ:
        value = (mem_node::StoreMemSize() >> 10);
        break;

    case SYSSTOR:
        value = (Store::Root().currentSize() >> 10);
        break;

    case SYS_UPTIME:
        value = (tvSubDsec(squid_start, current_time) * 100);
        type = ASN_TIMETICKS;
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        break;
    }

    variable_list *Answer = nullptr;
    return snmp_varlist_add_variable(&Answer, Var->name, Var->name_length, type, &value, sizeof(value));
}

/*
 * cacheConfig group
 */
variable_list *
snmp_confFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer = nullptr;
    debugs(49, 5, "snmp_confFn: Processing request with magic " << Var->name[8] << "!");
    *ErrP = SNMP_ERR_NOERROR;

    char *value_str = nullptr;
    size_t value_int = 0;
    u_char type;
    switch (Var->name[LEN_SQ_CONF]) {

    case CONF_ADMIN:
        type = ASN_OCTET_STR;
        value_str = xstrdup(Config.adminEmail);
        break;

    case CONF_VERSION:
        type = ASN_OCTET_STR;
        value_str = xstrdup(APP_SHORTNAME);
        break;

    case CONF_VERSION_ID:
        type = ASN_OCTET_STR;
        value_str = xstrdup(VERSION);
        break;

    case CONF_STORAGE:

        type = ASN_INTEGER; // these are all Integer
        switch (Var->name[LEN_SQ_CONF + 1]) {

        case CONF_ST_MMAXSZ:
            value_int = (Config.memMaxSize >> 20);
            break;

        case CONF_ST_SWMAXSZ:
            value_int = (Store::Root().maxSize() >> 20);
            break;

        case CONF_ST_SWHIWM:
            value_int = Config.Swap.highWaterMark;
            break;

        case CONF_ST_SWLOWM:
            value_int = Config.Swap.lowWaterMark;
            break;

        default:
            *ErrP = SNMP_ERR_NOSUCHNAME;
            break;
        }

        break;

    case CONF_LOG_FAC:
        if (auto cp = Debug::debugOptions)
            value_str = xstrdup(cp);
        else
            value_str = xstrdup("None");
        type = ASN_OCTET_STR;
        break;

    case CONF_UNIQNAME:
        type = ASN_OCTET_STR;
        value_str = xstrdup(uniqueHostname());
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        return nullptr;
    }

    if (type == ASN_OCTET_STR)
        return snmp_varlist_add_variable(&Answer, Var->name, Var->name_length, type, &value_str, strlen(value_str));

    return snmp_varlist_add_variable(&Answer, Var->name, Var->name_length, type, &value_int, sizeof(value_int));
}

/*
 * cacheMesh group
 *   - cachePeerTable
 */
variable_list *
snmp_meshPtblFn(variable_list * Var, snint * ErrP)
{
    variable_list *Answer = nullptr;
    Ip::Address laddr;
    debugs(49, 5, "snmp_meshPtblFn: peer " << Var->name[LEN_SQ_MESH + 3] << " requested!");
    *ErrP = SNMP_ERR_NOERROR;

    u_int index = Var->name[LEN_SQ_MESH + 3] ;
    CachePeer *p = nullptr;
    for (const auto &peer: CurrentCachePeers()) {
        if (peer->index == index) {
            laddr = peer->in_addr ;
            p = peer.get();
            break;
        }
    }

    if (!p) {
        *ErrP = SNMP_ERR_NOSUCHNAME;
        return nullptr;
    }

    size_t value = 0;
    u_char type;
    switch (Var->name[LEN_SQ_MESH + 2]) {
    case MESH_PTBL_INDEX:
        value = p->index;
        type = ASN_INTEGER;
    break;

    case MESH_PTBL_NAME: {
        auto buf = xstrdup(p->host);
        return snmp_varlist_add_variable(&Answer, Var->name, Var->name_length, ASN_OCTET_STR, &buf, strlen(buf));
    }
    break;

    case MESH_PTBL_ADDR_TYPE: {
        value = laddr.isIPv4() ? INETADDRESSTYPE_IPV4 : INETADDRESSTYPE_IPV6;
        type = ASN_INTEGER;
    }
    break;
    case MESH_PTBL_ADDR: {
        // InetAddress doesn't have its own ASN.1 type,
        // like IpAddr does (SMI_IPADDRESS)
        // See: rfc4001.txt
        char host[MAX_IPSTRLEN];
        laddr.toStr(host,MAX_IPSTRLEN);
        auto buf = xstrdup(host);
        return snmp_varlist_add_variable(&Answer, Var->name, Var->name_length, ASN_OCTET_STR, &buf, strlen(buf));
    }
    break;

    case MESH_PTBL_HTTP:
        value = p->http_port;
        type = ASN_INTEGER;
        break;

    case MESH_PTBL_ICP:
        value = p->icp.port;
        type = ASN_INTEGER;
        break;

    case MESH_PTBL_TYPE:
        value = p->type;
        type = ASN_INTEGER;
        break;

    case MESH_PTBL_STATE:
        value = neighborUp(p);
        type = ASN_INTEGER;
        break;

    case MESH_PTBL_SENT:
        value = p->stats.pings_sent;
        type = ASN_COUNTER;
        break;

    case MESH_PTBL_PACKED:
        value = p->stats.pings_acked;
        type = ASN_COUNTER;
        break;

    case MESH_PTBL_FETCHES:
        value = p->stats.fetches;
        type = ASN_COUNTER;
        break;

    case MESH_PTBL_RTT:
        value = p->stats.rtt;
        type = ASN_INTEGER; // TODO: ASN_GUAGE ?
        break;

    case MESH_PTBL_IGN:
        value = p->stats.ignored_replies;
        type = ASN_COUNTER;
        break;

    case MESH_PTBL_KEEPAL_S:
        value = p->stats.n_keepalives_sent;
        type = ASN_COUNTER;
        break;

    case MESH_PTBL_KEEPAL_R:
        value = p->stats.n_keepalives_recv;
        type = ASN_COUNTER;
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        return nullptr;
    }

    return snmp_varlist_add_variable(&Answer, Var->name, Var->name_length, type, &value, sizeof(value));
}

variable_list *
snmp_prfSysFn(variable_list * Var, snint * ErrP)
{
    static struct rusage rusage;
    debugs(49, 5, "snmp_prfSysFn: Processing request with magic " << Var->name[LEN_SQ_PRF + 1] << "!");
    *ErrP = SNMP_ERR_NOERROR;

    size_t value = 0;
    u_char type = ASN_INTEGER; // default for deprecated is value=0
    switch (Var->name[LEN_SQ_PRF + 1]) {

    case PERF_SYS_PF:
        squid_getrusage(&rusage);
        value = rusage_pagefaults(&rusage);
        type = ASN_COUNTER;
        break;

    case PERF_SYS_NUMR:
        value = IOStats.Http.reads;
        type = ASN_COUNTER;
        break;

    case PERF_SYS_MEMUSAGE: {
        Mem::PoolStats stats;
        Mem::GlobalStats(stats);
        value = (stats.meter->alloc.currentLevel() >> 10);
        type = ASN_INTEGER;
    }
    break;

    case PERF_SYS_CPUTIME:
        squid_getrusage(&rusage);
        value = rusage_cputime(&rusage);
        type = ASN_INTEGER;
        break;

    case PERF_SYS_CPUUSAGE:
        squid_getrusage(&rusage);
        value = Math::doublePercent(rusage_cputime(&rusage), tvSubDsec(squid_start, current_time));
        type = ASN_INTEGER;
        break;

    case PERF_SYS_MAXRESSZ:
        squid_getrusage(&rusage);
        value = rusage_maxrss(&rusage);
        type = ASN_INTEGER;
        break;

    case PERF_SYS_CURUNLREQ:
        value = statCounter.unlink.requests;
        type = ASN_GAUGE;
        break;

    case PERF_SYS_CURUNUSED_FD:
        value = (Squid_MaxFD - Number_FD);
        type = ASN_GAUGE;
        break;

    case PERF_SYS_CURRESERVED_FD:
        value = RESERVED_FD;
        type = ASN_GAUGE;
        break;

    case PERF_SYS_CURUSED_FD:
        value = Number_FD;
        type = ASN_GAUGE;
        break;

    case PERF_SYS_CURMAX_FD:
        value = Biggest_FD;
        type = ASN_GAUGE;
        break;

    case PERF_SYS_NUMOBJCNT: {
        StoreInfoStats stats;
        Store::Root().getStats(stats);
        value = (stats.mem.count + stats.swap.count);
        type = ASN_GAUGE;
        break;
    }

    // deprecated OIDs, not an error, just value=0
    case PERF_SYS_CURLRUEXP:
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        break;
    }

    variable_list *Answer = nullptr;
    return snmp_varlist_add_variable(&Answer, Var->name, Var->name_length, type, &value, sizeof(value));
}

static variable_list *
CacheProtoAggregateStats(variable_list * Var, snint * ErrP)
{
    debugs(49, 5, "Processing request with magic " << Var->name[LEN_SQ_PRF + 2] << "!");
    *ErrP = SNMP_ERR_NOERROR;

    size_t value = 0;
    auto type = ASN_COUNTER; // most of these are Counter32
    switch (Var->name[LEN_SQ_PRF + 2]) {

    case PERF_PROTOSTAT_AGGR_HTTP_REQ:
        value = statCounter.client_http.requests;
        break;

    case PERF_PROTOSTAT_AGGR_HTTP_HITS:
        value = statCounter.client_http.hits;
        break;

    case PERF_PROTOSTAT_AGGR_HTTP_ERRORS:
        value = statCounter.client_http.errors;
        break;

    case PERF_PROTOSTAT_AGGR_HTTP_KBYTES_IN:
        value = statCounter.client_http.kbytes_in.kb;
        break;

    case PERF_PROTOSTAT_AGGR_HTTP_KBYTES_OUT:
        value = statCounter.client_http.kbytes_out.kb;
        break;

    case PERF_PROTOSTAT_AGGR_ICP_S:
        value = statCounter.icp.pkts_sent;
        break;

    case PERF_PROTOSTAT_AGGR_ICP_R:
        value = statCounter.icp.pkts_recv;
        break;

    case PERF_PROTOSTAT_AGGR_ICP_SKB:
        value = statCounter.icp.kbytes_sent.kb;
        break;

    case PERF_PROTOSTAT_AGGR_ICP_RKB:
        value = statCounter.icp.kbytes_recv.kb;
        break;

    case PERF_PROTOSTAT_AGGR_REQ:
        value = statCounter.server.all.requests;
        type = ASN_INTEGER; // TODO: can this be a Counter32 ?
        break;

    case PERF_PROTOSTAT_AGGR_ERRORS:
        value = statCounter.server.all.errors;
        type = ASN_INTEGER; // TODO: can this be a Counter32 ?
        break;

    case PERF_PROTOSTAT_AGGR_KBYTES_IN:
        value = statCounter.server.all.kbytes_in.kb;
        break;

    case PERF_PROTOSTAT_AGGR_KBYTES_OUT:
        value = statCounter.server.all.kbytes_out.kb;
        break;

    case PERF_PROTOSTAT_AGGR_CURSWAP:
        value = (Store::Root().currentSize() >> 10);
        type = ASN_GAUGE;
        break;

    case PERF_PROTOSTAT_AGGR_CLIENTS:
        value = statCounter.client_http.clients;
        type = ASN_GAUGE;
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        return nullptr;
    }

    variable_list *Answer = nullptr;
    return snmp_varlist_add_variable(&Answer, Var->name, Var->name_length, type, &value, sizeof(value));
}

static variable_list *
CacheProtoMedianStats(variable_list * Var, snint * ErrP)
{
    debugs(49, 5, "Processing request with magic " << Var->name[LEN_SQ_PRF + 3] << "!");
    *ErrP = SNMP_ERR_NOERROR;

    if (Var->name_length != LEN_SQ_PRF + 5) {
        *ErrP = SNMP_ERR_GENERR;
        return nullptr;
    }

    int minutes = Var->name[LEN_SQ_PRF + 4];
    if ((minutes < 1) || (minutes > 60)) {
        *ErrP = SNMP_ERR_BADVALUE;
        return nullptr;
    }

    static auto f = snmpStatGet(0);
    static auto l = snmpStatGet(minutes);

    debugs(49, 8, "median: min= " << minutes << ", " << Var->name[LEN_SQ_PRF + 3] << " l= " << l << " , f = " << f);
    debugs(49, 8, "median: l= " << l << " , f = " << f);

    double value = 0.0;
    auto type = ASN_INTEGER; // TODO: are these better as 64-bit Guage ?
    switch (Var->name[LEN_SQ_PRF + 3]) {

    case PERF_MEDIAN_TIME:
        value = minutes;
        break;

    case PERF_MEDIAN_HTTP_ALL:
        value = statHistDeltaMedian(l->client_http.allSvcTime, f->client_http.allSvcTime);
        break;

    case PERF_MEDIAN_HTTP_MISS:
        value = statHistDeltaMedian(l->client_http.missSvcTime, f->client_http.missSvcTime);
        break;

    case PERF_MEDIAN_HTTP_NM:
        value = statHistDeltaMedian(l->client_http.nearMissSvcTime, f->client_http.nearMissSvcTime);
        break;

    case PERF_MEDIAN_HTTP_HIT:
        value = statHistDeltaMedian(l->client_http.hitSvcTime, f->client_http.hitSvcTime);
        break;

    case PERF_MEDIAN_ICP_QUERY:
        value = statHistDeltaMedian(l->icp.querySvcTime, f->icp.querySvcTime);
        break;

    case PERF_MEDIAN_ICP_REPLY:
        value = statHistDeltaMedian(l->icp.replySvcTime, f->icp.replySvcTime);
        break;

    case PERF_MEDIAN_DNS:
        value = statHistDeltaMedian(l->dns.svcTime, f->dns.svcTime);
        break;

    case PERF_MEDIAN_RHR:
        value = statRequestHitRatio(minutes);
        break;

    case PERF_MEDIAN_BHR:
        value = statByteHitRatio(minutes);
        break;

    case PERF_MEDIAN_HTTP_NH:
        value = statHistDeltaMedian(l->client_http.nearHitSvcTime, f->client_http.nearHitSvcTime);
        break;

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        return nullptr;
    }

    variable_list *Answer = nullptr;
    return snmp_varlist_add_variable(&Answer, Var->name, Var->name_length, type, &value, sizeof(value));
}

variable_list *
snmp_prfProtoFn(variable_list * Var, snint * ErrP)
{
    debugs(49, 5, "snmp_prfProtoFn: Processing request with magic " << Var->name[LEN_SQ_PRF] << "!");
    *ErrP = SNMP_ERR_NOERROR;

    switch (Var->name[LEN_SQ_PRF + 1]) {

    case PERF_PROTOSTAT_AGGR:
        return CacheProtoAggregateStats(Var, ErrP);

    case PERF_PROTOSTAT_MEDIAN:
        return CacheProtoMedianStats(Var, ErrP);

    default:
        *ErrP = SNMP_ERR_NOSUCHNAME;
        return nullptr;
    }
}

