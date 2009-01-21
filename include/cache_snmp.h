/*
 * $Id$
 */
#ifndef SQUID_CACHE_SNMP_H
#define SQUID_CACHE_SNMP_H

#ifdef SQUID_SNMP

#if SIZEOF_LONG == 8
#define snint int
#else
#define snint long
#endif

#ifndef MIN
#define MIN(a,b) (a<b?a:b)
#endif

#include "snmp.h"
#include "snmp_impl.h"
#if 0
#include "asn1.h"
#endif
#include "snmp_api.h"

#include "snmp_vars.h"

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

/*
 * cacheSystem group { squid 1 }
 */

enum {
    SYS_START,
    SYSVMSIZ,  /* cacheSysVMsize  */
    SYSSTOR,   /* cacheSysStorage  */
    SYS_UPTIME,/* cacheUptime  */
    SYS_END
};

#define LEN_SYS LEN_SQ_SYS + 1
#define LEN_SYS_INST LEN_SQ_SYS + 2

/*
 * cacheConfig group { squid 2 }
 */

enum {
    CONF_START,
    CONF_ADMIN,      /* cacheAdmin */
    CONF_VERSION,    /* cacheSoftware */
    CONF_VERSION_ID, /* cacheVersionId */
    CONF_LOG_FAC,    /* cacheLoggingFacility */
    CONF_STORAGE,    /* cacheStorageConfig group */
    CONF_UNIQNAME,   /* cacheUniqName */
    CONF_END
};

#define LEN_CONF LEN_SQ_CONF + 1
#define LEN_CONF_INST LEN_SQ_CONF + 2


/*
 * cacheStorageConfig group { cacheConfig 5 }
 */
enum {
    CONF_ST_START,
    CONF_ST_MMAXSZ, /* cacheMemMaxSize */
    CONF_ST_SWMAXSZ, /* cacheSwapMaxSize */
    CONF_ST_SWHIWM,  /* cacheSwapHighWM */
    CONF_ST_SWLOWM,   /* cacheSwapLowWM  */
    CONF_ST_END
};

#define LEN_CONF_ST LEN_CONF + 1
#define LEN_CONF_ST_INST LEN_CONF + 2

/*
 * Cache Performance Group  {squid 3}
 */

enum {
    PERF_START,
    PERF_SYS,  /* cacheSysPerf */
    PERF_PROTO,   /* cacheProtoStats */
    PERF_END
};


/* cacheSysPerf */
enum {
    PERF_SYS_START,
    PERF_SYS_PF, /* cacheSysPageFaults */
    PERF_SYS_NUMR, /* cacheSysNumReads */
    PERF_SYS_MEMUSAGE,   /* cacheMemUsage */
    PERF_SYS_CPUTIME,  /* cacheCpuTime */
    PERF_SYS_CPUUSAGE,  /* cacheCpuUsage */
    PERF_SYS_MAXRESSZ,   /* cacheMaxResSize */
    PERF_SYS_NUMOBJCNT, /* cacheNumObjCount */
    PERF_SYS_CURLRUEXP,  /* cacheCurrentLRUExpiration */
    PERF_SYS_CURUNLREQ,  /* cacheCurrentUnlinkRequests */
    PERF_SYS_CURUNUSED_FD, /* cacheCurrentUnusedFDescrCnt */
    PERF_SYS_CURRESERVED_FD, /* cacheCurrentResFileDescrCnt */
    PERF_SYS_CURUSED_FD, /* cacheCurrentFileDescrCnt */
    PERF_SYS_CURMAX_FD, /* cacheCurrentFileDescrMax */
    PERF_SYS_END
};

/* cacheProtoStats */
enum {
    PERF_PROTOSTAT_START,
    PERF_PROTOSTAT_AGGR, /* cacheProtoAggregateStats */
    PERF_PROTOSTAT_MEDIAN,  /* cacheMedianSvcTable */
    PERF_PROTOSTAT_END
};

/* cacheProtoAggregateStats */
enum {
    PERF_PROTOSTAT_AGGR_START,
    PERF_PROTOSTAT_AGGR_HTTP_REQ, /* cacheProtoClientHttpRequests */
    PERF_PROTOSTAT_AGGR_HTTP_HITS, /* cacheHttpHits */
    PERF_PROTOSTAT_AGGR_HTTP_ERRORS, /* cacheHttpErrors */
    PERF_PROTOSTAT_AGGR_HTTP_KBYTES_IN, /* cacheHttpInKb */
    PERF_PROTOSTAT_AGGR_HTTP_KBYTES_OUT, /* cacheHttpOutKb */
    PERF_PROTOSTAT_AGGR_ICP_S,  /* cacheIcpPktsSent */
    PERF_PROTOSTAT_AGGR_ICP_R, /* cacheIcpPktsRecv */
    PERF_PROTOSTAT_AGGR_ICP_SKB, /* cacheIcpKbSent */
    PERF_PROTOSTAT_AGGR_ICP_RKB, /* cacheIcpKbRecv */
    PERF_PROTOSTAT_AGGR_REQ, /* cacheServerRequests */
    PERF_PROTOSTAT_AGGR_ERRORS, /* cacheServerErrors */
    PERF_PROTOSTAT_AGGR_KBYTES_IN, /* cacheServerInKb */
    PERF_PROTOSTAT_AGGR_KBYTES_OUT, /* cacheServerOutKb */
    PERF_PROTOSTAT_AGGR_CURSWAP, /* cacheCurrentSwapSize */
    PERF_PROTOSTAT_AGGR_CLIENTS, /* cacheClients */
    PERF_PROTOSTAT_AGGR_END
};


/* CacheMedianSvcEntry */
enum {
    PERF_MEDIAN_START,
    PERF_MEDIAN_TIME, /* cacheMedianTime */
    PERF_MEDIAN_HTTP_ALL, /* cacheHttpAllSvcTime */
    PERF_MEDIAN_HTTP_MISS, /* cacheHttpMissSvcTime */
    PERF_MEDIAN_HTTP_NM, /* cacheHttpNmSvcTime */
    PERF_MEDIAN_HTTP_HIT, /* cacheHttpHitSvcTime */
    PERF_MEDIAN_ICP_QUERY, /* cacheIcpQuerySvcTime */
    PERF_MEDIAN_ICP_REPLY, /* cacheIcpReplySvcTime */
    PERF_MEDIAN_DNS, /* cacheDnsSvcTime */
    PERF_MEDIAN_RHR, /* cacheRequestHitRatio */
    PERF_MEDIAN_BHR, /* cacheRequestByteRatio */
    PERF_MEDIAN_HTTP_NH, /* cacheHttpNhSvcTime */
    PERF_MEDIAN_END
};




/*
 * cacheNetwork group  { squid 4 }
 */

enum {
    NET_START,
    NET_IP_CACHE, /* cacheIpCache */
    NET_FQDN_CACHE, /* cacheFqdnCache */
    NET_DNS_CACHE,  /* cacheDns */
    NET_END
};

/* cacheIpCache */
enum {
    IP_START,
    IP_ENT, /* cacheIpEntrie */
    IP_REQ, /* cacheIpRequests */
    IP_HITS, /* acheIpHits */
    IP_PENDHIT, /* cacheIpPendingHits */
    IP_NEGHIT, /* cacheIpNegativeHit */
    IP_MISS,  /* cacheIpMisses */
    IP_GHBN, /* cacheBlockingGetHostByName */
    IP_LOC, /* cacheAttemptReleaseLckEntries */
    IP_END
};

/* cacheFqdnCache */
enum {
    FQDN_START,
    FQDN_ENT, /* cacheFqdnEntries */
    FQDN_REQ, /* cacheFqdnRequests */
    FQDN_HITS, /* cacheFqdnHits */
    FQDN_PENDHIT, /* cacheFqdnPendingHits */
    FQDN_NEGHIT, /* cacheFqdnNegativeHits */
    FQDN_MISS, /* cacheFqdnMisses */
    FQDN_GHBN, /* cacheBlockingGetHostByAddr */
    FQDN_END
};


/* cacheDNS */
enum {
    DNS_START,
    DNS_REQ, /* cacheDnsRequests */
    DNS_REP, /* cacheDnsReplies */
    DNS_SERVERS, /* cacheDnsNumberServers */
    DNS_END
};




/*
 * cacheMesh group { squid 5 }
 */

enum {
    MESH_START,
    MESH_PTBL,  /* cachePeerTable  */
    MESH_CTBL,  /* cacheClientTable */
    MESH_END
};

/* cachePeerEntry */
enum {
    MESH_PTBL_START,
    MESH_PTBL_INDEX, /* cachePeerIndex  */
    MESH_PTBL_NAME, /* cachePeerName  */
    MESH_PTBL_ADDR_TYPE, /* cachePeerAddressType */
    MESH_PTBL_ADDR,   /* cachePeerAddress */
    MESH_PTBL_HTTP, /* cachePortHttp */
    MESH_PTBL_ICP,  /* cachePeerPortIcp */
    MESH_PTBL_TYPE,  /* cachePeerType  */
    MESH_PTBL_STATE,  /* cachePeerStat */
    MESH_PTBL_SENT,   /* cachePeerPingsSent */
    MESH_PTBL_PACKED, /* cachePeerPingsAcked */
    MESH_PTBL_FETCHES,  /* cachePeerFetches */
    MESH_PTBL_RTT,   /* cachePeerRtt */
    MESH_PTBL_IGN,  /* cachePeerIgnored */
    MESH_PTBL_KEEPAL_S, /* cachePeerKeepAlSent */
    MESH_PTBL_KEEPAL_R, /* cachePeerKeepAlRecv */
    MESH_PTBL_END
};

/* cacheClientEntry */
enum {
    MESH_CTBL_START,
    MESH_CTBL_ADDR_TYPE, /* cacheClientAddressType */
    MESH_CTBL_ADDR,      /* cacheClientAddress */
    MESH_CTBL_HTREQ,     /* cacheClientHttpRequests */
    MESH_CTBL_HTBYTES,   /* cacheClientHttpKb */
    MESH_CTBL_HTHITS,    /* cacheClientHttpHits */
    MESH_CTBL_HTHITBYTES, /* cacheClientHTTPHitKb */
    MESH_CTBL_ICPREQ,     /* cacheClientIcpRequests */
    MESH_CTBL_ICPBYTES,   /* cacheClientIcpKb  */
    MESH_CTBL_ICPHITS,    /* cacheClientIcpHits */
    MESH_CTBL_ICPHITBYTES,/* cacheClientIcpHitKb */
    MESH_CTBL_END
};



#endif /* SQUID_SNMP */

#endif /* SQUID_CACHE_SNMP_H */
