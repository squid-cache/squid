/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CACHE_SNMP_H
#define SQUID_CACHE_SNMP_H

#if SQUID_SNMP

typedef int64_t snint;

#ifndef MIN
#define MIN(a,b) (a<b?a:b)
#endif

#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"

/* MIB definitions
 * SQUID-MIB
 *      .iso.org.dod.internet.private.enterprises.nlanr.squid
 *        1   3   6     1        4         1      3495    1
 *
 * PROXY-MIB
 *      .iso.org.dod.internet.experimental.nsfnet.proxy
 *        1   3   6     1          3         25    17
 */

#define SQUIDMIB 1, 3, 6, 1, 4, 1, 3495, 1
#define LEN_SQUIDMIB 8
#define INSTANCE 0
#define TIME_INDEX 1, 5, 60
#define TIME_INDEX_LEN 3

/* basic groups under .squid */

#define SQ_SYS  SQUIDMIB, 1           /* cacheSystem group { squid 1 } */
#define LEN_SQ_SYS LEN_SQUIDMIB+1
#define SQ_CONF SQUIDMIB, 2           /* cacheConfig group { squid 2 } */
#define LEN_SQ_CONF LEN_SQUIDMIB+1
#define SQ_PRF  SQUIDMIB, 3           /* cachePerformance group { squid 3 } */
#define LEN_SQ_PRF LEN_SQUIDMIB+1
#define SQ_NET  SQUIDMIB, 4           /* cacheNetwork group { squid 4 }   */
#define LEN_SQ_NET LEN_SQUIDMIB+1
#define SQ_MESH  SQUIDMIB, 5          /* cacheMesh group { squid 5 }    */
#define LEN_SQ_MESH LEN_SQUIDMIB+1

/**
 * cacheSystem group { squid 1 }
 */
enum {
    SYS_START  = 0,
    SYSVMSIZ   = 1,  /**< cacheSysVMsize  */
    SYSSTOR    = 2,  /**< cacheSysStorage  */
    SYS_UPTIME = 3,  /**< cacheUptime  */
    SYS_END
};

#define LEN_SYS LEN_SQ_SYS + 1
#define LEN_SYS_INST LEN_SQ_SYS + 2

/**
 * cacheConfig group { squid 2 }
 */
enum {
    CONF_START      = 0,
    CONF_ADMIN      = 1,  /**< cacheAdmin */
    CONF_VERSION    = 2,  /**< cacheSoftware */
    CONF_VERSION_ID = 3,  /**< cacheVersionId */
    CONF_LOG_FAC    = 4,  /**< cacheLoggingFacility */
    CONF_STORAGE    = 5,  /**< cacheStorageConfig group */
    CONF_UNIQNAME   = 6,  /**< cacheUniqName */
    CONF_END
};

#define LEN_CONF LEN_SQ_CONF + 1
#define LEN_CONF_INST LEN_SQ_CONF + 2

/**
 * cacheStorageConfig group { cacheConfig 5 }
 */
enum {
    CONF_ST_START    = 0,
    CONF_ST_MMAXSZ   = 1,  /* cacheMemMaxSize */
    CONF_ST_SWMAXSZ  = 2,  /* cacheSwapMaxSize */
    CONF_ST_SWHIWM   = 3,  /* cacheSwapHighWM */
    CONF_ST_SWLOWM   = 4,  /* cacheSwapLowWM  */
    CONF_ST_END
};

#define LEN_CONF_ST LEN_CONF + 1
#define LEN_CONF_ST_INST LEN_CONF + 2

/*
 * Cache Performance Group  {squid 3}
 */

enum {
    PERF_START  = 0,
    PERF_SYS    = 1,  /* cacheSysPerf */
    PERF_PROTO  = 2,  /* cacheProtoStats */
    PERF_END
};

/* cacheSysPerf */
enum {
    PERF_SYS_START            = 0,
    PERF_SYS_PF               = 1,  /* cacheSysPageFaults */
    PERF_SYS_NUMR             = 2,  /* cacheSysNumReads */
    PERF_SYS_MEMUSAGE         = 3,  /* cacheMemUsage */
    PERF_SYS_CPUTIME          = 4,  /* cacheCpuTime */
    PERF_SYS_CPUUSAGE         = 5,  /* cacheCpuUsage */
    PERF_SYS_MAXRESSZ         = 6,  /* cacheMaxResSize */
    PERF_SYS_NUMOBJCNT        = 7,  /* cacheNumObjCount */
    PERF_SYS_CURLRUEXP        = 8,  /* cacheCurrentLRUExpiration */
    PERF_SYS_CURUNLREQ        = 9,  /* cacheCurrentUnlinkRequests */
    PERF_SYS_CURUNUSED_FD     = 10, /* cacheCurrentUnusedFDescrCnt */
    PERF_SYS_CURRESERVED_FD   = 11, /* cacheCurrentResFileDescrCnt */
    PERF_SYS_CURUSED_FD       = 12, /* cacheCurrentFileDescrCnt */
    PERF_SYS_CURMAX_FD        = 13, /* cacheCurrentFileDescrMax */
    PERF_SYS_END
};

/* cacheProtoStats */
enum {
    PERF_PROTOSTAT_START,
    PERF_PROTOSTAT_AGGR    = 1,  /* cacheProtoAggregateStats */
    PERF_PROTOSTAT_MEDIAN  = 2,  /* cacheMedianSvcTable */
    PERF_PROTOSTAT_END
};

/* cacheProtoAggregateStats */
enum {
    PERF_PROTOSTAT_AGGR_START           = 0,
    PERF_PROTOSTAT_AGGR_HTTP_REQ        = 1,  /* cacheProtoClientHttpRequests */
    PERF_PROTOSTAT_AGGR_HTTP_HITS       = 2,  /* cacheHttpHits */
    PERF_PROTOSTAT_AGGR_HTTP_ERRORS     = 3,  /* cacheHttpErrors */
    PERF_PROTOSTAT_AGGR_HTTP_KBYTES_IN  = 4,  /* cacheHttpInKb */
    PERF_PROTOSTAT_AGGR_HTTP_KBYTES_OUT = 5,  /* cacheHttpOutKb */
    PERF_PROTOSTAT_AGGR_ICP_S           = 6,  /* cacheIcpPktsSent */
    PERF_PROTOSTAT_AGGR_ICP_R           = 7,  /* cacheIcpPktsRecv */
    PERF_PROTOSTAT_AGGR_ICP_SKB         = 8,  /* cacheIcpKbSent */
    PERF_PROTOSTAT_AGGR_ICP_RKB         = 9,  /* cacheIcpKbRecv */
    PERF_PROTOSTAT_AGGR_REQ             = 10, /* cacheServerRequests */
    PERF_PROTOSTAT_AGGR_ERRORS          = 11, /* cacheServerErrors */
    PERF_PROTOSTAT_AGGR_KBYTES_IN       = 12, /* cacheServerInKb */
    PERF_PROTOSTAT_AGGR_KBYTES_OUT      = 13, /* cacheServerOutKb */
    PERF_PROTOSTAT_AGGR_CURSWAP         = 14, /* cacheCurrentSwapSize */
    PERF_PROTOSTAT_AGGR_CLIENTS         = 15, /* cacheClients */
    PERF_PROTOSTAT_AGGR_END
};

/* cacheMedianSvcEntry */
enum {
    PERF_MEDIAN_START     = 0,
    PERF_MEDIAN_TIME      = 1,  /* cacheMedianTime */
    PERF_MEDIAN_HTTP_ALL  = 2,  /* cacheHttpAllSvcTime */
    PERF_MEDIAN_HTTP_MISS = 3,  /* cacheHttpMissSvcTime */
    PERF_MEDIAN_HTTP_NM   = 4,  /* cacheHttpNmSvcTime */
    PERF_MEDIAN_HTTP_HIT  = 5,  /* cacheHttpHitSvcTime */
    PERF_MEDIAN_ICP_QUERY = 6,  /* cacheIcpQuerySvcTime */
    PERF_MEDIAN_ICP_REPLY = 7,  /* cacheIcpReplySvcTime */
    PERF_MEDIAN_DNS       = 8,  /* cacheDnsSvcTime */
    PERF_MEDIAN_RHR       = 9,  /* cacheRequestHitRatio */
    PERF_MEDIAN_BHR       = 10, /* cacheRequestByteRatio */
    PERF_MEDIAN_HTTP_NH   = 11, /* cacheHttpNhSvcTime */
    PERF_MEDIAN_END
};

/*
 * cacheNetwork group  { squid 4 }
 */
enum {
    NET_START       = 0,
    NET_IP_CACHE    = 1, /* cacheIpCache */
    NET_FQDN_CACHE  = 2, /* cacheFqdnCache */
    NET_DNS_CACHE   = 3,  /* cacheDns */
    NET_END
};

/* cacheIpCache */
enum {
    IP_START   = 0,
    IP_ENT     = 1,  /* cacheIpEntrie */
    IP_REQ     = 2,  /* cacheIpRequests */
    IP_HITS    = 3,  /* acheIpHits */
    IP_PENDHIT = 4,  /* cacheIpPendingHits */
    IP_NEGHIT  = 5,  /* cacheIpNegativeHit */
    IP_MISS    = 6,  /* cacheIpMisses */
    IP_GHBN    = 7,  /* cacheBlockingGetHostByName */
    IP_LOC     = 8,  /* cacheAttemptReleaseLckEntries */
    IP_END
};

/* cacheFqdnCache */
enum {
    FQDN_START   = 0,
    FQDN_ENT     = 1,  /* cacheFqdnEntries */
    FQDN_REQ     = 2,  /* cacheFqdnRequests */
    FQDN_HITS    = 3,  /* cacheFqdnHits */
    FQDN_PENDHIT = 4,  /* cacheFqdnPendingHits */
    FQDN_NEGHIT  = 5,  /* cacheFqdnNegativeHits */
    FQDN_MISS    = 6,  /* cacheFqdnMisses */
    FQDN_GHBN    = 7,  /* cacheBlockingGetHostByAddr */
    FQDN_END
};

/* cacheDNS */
enum {
    DNS_START   = 0,
    DNS_REQ     = 1,  /* cacheDnsRequests */
    DNS_REP     = 2,  /* cacheDnsReplies */
    DNS_SERVERS = 3,  /* cacheDnsNumberServers */
    DNS_END
};

/*
 * cacheMesh group { squid 5 }
 */

enum {
    MESH_START = 0,
    MESH_PTBL  = 1,  /* cachePeerTable  */
    MESH_CTBL  = 2,  /* cacheClientTable */
    MESH_END
};

/* CachePeerTableEntry (version 3) */
enum {
    MESH_PTBL_START     = 0,
    MESH_PTBL_INDEX     = 1,  /* cachePeerIndex  */
    MESH_PTBL_NAME      = 2,  /* cachePeerName  */
    MESH_PTBL_ADDR_TYPE = 3,  /* cachePeerAddressType */
    MESH_PTBL_ADDR      = 4,  /* cachePeerAddress */
    MESH_PTBL_HTTP      = 5,  /* cachePortHttp */
    MESH_PTBL_ICP       = 6,  /* cachePeerPortIcp */
    MESH_PTBL_TYPE      = 7,  /* cachePeerType  */
    MESH_PTBL_STATE     = 8,  /* cachePeerStat */
    MESH_PTBL_SENT      = 9,  /* cachePeerPingsSent */
    MESH_PTBL_PACKED    = 10, /* cachePeerPingsAcked */
    MESH_PTBL_FETCHES   = 11, /* cachePeerFetches */
    MESH_PTBL_RTT       = 12, /* cachePeerRtt */
    MESH_PTBL_IGN       = 13, /* cachePeerIgnored */
    MESH_PTBL_KEEPAL_S  = 14, /* cachePeerKeepAlSent */
    MESH_PTBL_KEEPAL_R  = 15, /* cachePeerKeepAlRecv */
    MESH_PTBL_END
};

/* cacheClientEntry */
enum {
    MESH_CTBL_START       = 0,
    MESH_CTBL_ADDR_TYPE   = 1,  /* cacheClientAddressType */
    MESH_CTBL_ADDR        = 2,  /* cacheClientAddress */
    MESH_CTBL_HTREQ       = 3,  /* cacheClientHttpRequests */
    MESH_CTBL_HTBYTES     = 4,  /* cacheClientHttpKb */
    MESH_CTBL_HTHITS      = 5,  /* cacheClientHttpHits */
    MESH_CTBL_HTHITBYTES  = 6,  /* cacheClientHTTPHitKb */
    MESH_CTBL_ICPREQ      = 7,  /* cacheClientIcpRequests */
    MESH_CTBL_ICPBYTES    = 8,  /* cacheClientIcpKb  */
    MESH_CTBL_ICPHITS     = 9,  /* cacheClientIcpHits */
    MESH_CTBL_ICPHITBYTES = 10, /* cacheClientIcpHitKb */
    MESH_CTBL_END
};

#endif /* SQUID_SNMP */

#endif /* SQUID_CACHE_SNMP_H */

