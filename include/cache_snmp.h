#ifdef SQUID_SNMP
#ifndef CACHE_SNMP_H
#define CACHE_SNMP_H

#ifdef _SQUID_OSF_
#define snint int
#else
#define snint long
#endif

#include "snmp.h"
#include "snmp_impl.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "snmp_vars.h"
#include "snmp_oidlist.h"
#include "mib.h"

/* mib stuff here */

#ifndef CURRENT_MIB_VERSION
#define CURRENT_MIB_VERSION "v 1.12 1998/03/16 kostas@nlanr.net"
#endif

/* MIB definitions
 * We start from the SQUIDMIB as the root of the subtree
 *
 * we are under : iso.org.dod.internet.experimental.nsfnet.squid
 *                 1   3   6     1          3         25     17
 */

#define SQUIDMIB 1, 3, 6, 1, 3, 25, 17     /* length is 7 */
#define LEN_SQUIDMIB 7

#define SYSMIB 1, 3, 6, 1, 2, 1, 1	/* basic system vars */
#define LEN_SYSMIB 7

/* basic groups under .squid */

#define SQ_SYS  SQUIDMIB, 1		/* length is 8 */
#define LEN_SQ_SYS LEN_SQUIDMIB+1
#define SQ_CONF SQUIDMIB, 2
#define LEN_SQ_CONF LEN_SQUIDMIB+1
#define SQ_PRF  SQUIDMIB, 3
#define LEN_SQ_PRF LEN_SQUIDMIB+1
#define SQ_NET  SQUIDMIB, 4
#define LEN_SQ_NET LEN_SQUIDMIB+1
#define SQ_SEC  SQUIDMIB, 5
#define LEN_SQ_SEC LEN_SQUIDMIB+1
#define SQ_ACC  SQUIDMIB, 6
#define LEN_SQ_ACC LEN_SQUIDMIB+1

enum {	/* basic system mib info group */
SYSMIB_START,
VERSION_DESCR,
VERSION_ID,
UPTIME,
SYSCONTACT,
SYSYSNAME,
SYSLOCATION,
SYSSERVICES,
SYSORLASTCHANGE,
SYSMIB_END
};

/* cacheSystem group */

enum {
    SYS_START,
    SYSVMSIZ,
    SYSSTOR,
    SYSFDTBL,
    SYS_END
};

/* cacheConfig group */

enum {
    CONF_START,
    CONF_ADMIN,
    CONF_UPTIME,
    CONF_WAIS_RHOST,
    CONF_WAIS_RPORT,
    CONF_LOG_LVL,
    CONF_PTBL,
    CONF_STORAGE,
    CONF_TIO,
    CONF_END
};

enum {
    CONF_ST_START,
    CONF_ST_MMAXSZ,
    CONF_ST_MHIWM,
    CONF_ST_MLOWM,
    CONF_ST_SWMAXSZ,
    CONF_ST_SWHIWM,
    CONF_ST_SWLOWM,
    CONF_ST_END
};

enum {
    CONF_TIO_START,
    CONF_TIO_RD,
    CONF_TIO_CON,
    CONF_TIO_REQ,
    CONF_TIO_END
};

enum {
    CONF_PTBL_START,
    CONF_PTBL_ID,
    CONF_PTBL_NAME,
    CONF_PTBL_IP,
    CONF_PTBL_HTTP,
    CONF_PTBL_ICP,
    CONF_PTBL_TYPE,
    CONF_PTBL_STATE,
    CONF_PTBL_END
};

/* cacheNetwork group */

enum {
    NETDB_START,
    NETDB_ID,
    NETDB_NET,
    NETDB_PING_S,
    NETDB_PING_R,
    NETDB_HOPS,
    NETDB_RTT,
    NETDB_PINGTIME,
    NETDB_LASTUSE,
    NETDB_END
};

enum {
    NET_IPC_START,
    NET_IPC_ID,
    NET_IPC_NAME,
    NET_IPC_IP,
    NET_IPC_STATE,
    NET_IPC_END
};

enum {
    NET_DNS_START,
    NET_DNS_IPCACHE,
    NET_DNS_FQDNCACHE,
    NET_DNS_END
};


enum {
    NET_FQDN_START,
    NET_FQDN_ID,
    NET_FQDN_NAME,
    NET_FQDN_IP,
    NET_FQDN_LASTREF,
    NET_FQDN_EXPIRES,
    NET_FQDN_STATE,
    NET_FQDN_END
};

enum {
    NET_START,
    NET_NETDBTBL,
    NET_DNS,
    NET_NETSTAT,
    NET_END
};

enum {
    NETSTAT_START,
    NETSTAT_TCPCONNS,
    NETSTAT_UDPCONNS,
    NETSTAT_INTHRPUT,
    NETSTAT_OUTHRPUT
};

enum { 
    PERF_START,
    PERF_SYS,
    PERF_PROTO,
    PERF_PEER,
    PERF_END
};

enum {
    PERF_SYS_START,
    PERF_SYS_PF,
    PERF_SYS_NUMR,
    PERF_SYS_DEFR,
    PERF_SYS_MEMUSAGE,
    PERF_SYS_CPUUSAGE,
    PERF_SYS_MAXRESSZ,
    PERF_SYS_NUMOBJCNT,
    PERF_SYS_CURLRUEXP,
    PERF_SYS_CURUNLREQ,
    PERF_SYS_CURUNUSED_FD,
    PERF_SYS_CURRESERVED_FD,
    PERF_SYS_END
};

enum {
    PERF_PROTOSTAT_START,
    PERF_PROTOSTAT_AGGR,
    PERF_PROTOSTAT_MEDIAN,
    PERF_PROTOSTAT_END
};

enum {
    PERF_PROTOSTAT_AGGR_START,
    PERF_PROTOSTAT_AGGR_HTTP_REQ,
    PERF_PROTOSTAT_AGGR_HTTP_HITS,
    PERF_PROTOSTAT_AGGR_HTTP_ERRORS,
    PERF_PROTOSTAT_AGGR_HTTP_KBYTES_IN,
    PERF_PROTOSTAT_AGGR_HTTP_KBYTES_OUT,
    PERF_PROTOSTAT_AGGR_ICP_S,
    PERF_PROTOSTAT_AGGR_ICP_R,
    PERF_PROTOSTAT_AGGR_ICP_SKB,
    PERF_PROTOSTAT_AGGR_ICP_RKB,
    PERF_PROTOSTAT_AGGR_REQ,
    PERF_PROTOSTAT_AGGR_ERRORS,
    PERF_PROTOSTAT_AGGR_KBYTES_IN,
    PERF_PROTOSTAT_AGGR_KBYTES_OUT,
    PERF_PROTOSTAT_AGGR_CURSWAP,
    PERF_PROTOSTAT_AGGR_END
};

enum {
    PERF_MEDIAN_START,
    PERF_MEDIAN_TIME,
    PERF_MEDIAN_HTTP_ALL,
    PERF_MEDIAN_HTTP_MISS,
    PERF_MEDIAN_HTTP_NM,
    PERF_MEDIAN_HTTP_HIT,
    PERF_MEDIAN_ICP_QUERY,
    PERF_MEDIAN_ICP_REPLY,
    PERF_MEDIAN_DNS,
    PERF_MEDIAN_END
};

enum {
    SYS_FD_START,
    SYS_FD_NUMBER,
    SYS_FD_TYPE,
    SYS_FD_TOUT,
    SYS_FD_NREAD,
    SYS_FD_NWRITE,
    SYS_FD_ADDR,
    SYS_FD_NAME,
    SYS_FD_END
};

enum {
    PERF_PEERSTAT_START,
    PERF_PEERSTAT_ID,
    PERF_PEERSTAT_SENT,
    PERF_PEERSTAT_PACKED,
    PERF_PEERSTAT_FETCHES,
    PERF_PEERSTAT_RTT,
    PERF_PEERSTAT_IGN,
    PERF_PEERSTAT_KEEPAL_S,
    PERF_PEERSTAT_KEEPAL_R,
    PERF_PEERSTAT_END
};

/* First, we have a huge array of MIBs this agent knows about */
 
struct MIBListEntry {
  oid            Name[9]; /* Change as appropriate */
  snint           NameLen;
  oid_GetFn     *GetFn;
  oid_GetNextFn *GetNextFn;
};

variable_list *snmp_basicFn(variable_list *, snint *);
variable_list *snmp_confPtblFn(variable_list *, snint *);
variable_list *snmp_confFn(variable_list *, snint *);
variable_list *snmp_sysFn(variable_list *, snint *);
variable_list *snmp_prfSysFn(variable_list *, snint *);
variable_list *snmp_prfProtoFn(variable_list *, snint *);
variable_list *snmp_prfPeerFn(variable_list *, snint *);
variable_list *snmp_netdbFn(variable_list *, snint *);
variable_list *snmp_dnsFn(variable_list *, snint *);
variable_list *snmp_ipcacheFn(variable_list *, snint *);
variable_list *snmp_fqdncacheFn(variable_list *, snint *);

#endif
#endif
