#ifdef SQUID_SNMP
#ifndef CACHE_SNMP_H
#define CACHE_SNMP_H

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
#include "asn1.h"
#include "snmp_api.h"
#if 0
#include "snmp_client.h"
#include "mib.h"
#endif
#include "snmp_vars.h"
#include "snmp_oidlist.h"

/* mib stuff here */

#ifndef CURRENT_MIB_VERSION
#define CURRENT_MIB_VERSION "-- v 1.14 1998/04/03 kostas@nlanr.net"
#endif

/* MIB definitions
 * We start from the SQUIDMIB as the root of the subtree
 *
 * we are under : iso.org.dod.internet.experimental.nsfnet.squid
 *                 1   3   6     1          3         25     17
 */

#define SQUIDMIB 1, 3, 6, 1, 3, 25, 17	/* length is 7 */
#define LEN_SQUIDMIB 7

#define SYSMIB 1, 3, 6, 1, 2, 1, 1	/* basic system vars */
#define LEN_SYSMIB 7

/* basic groups under .squid */

#define SQ_SYS  SQUIDMIB, 1	/* length is 8 */
#define LEN_SQ_SYS LEN_SQUIDMIB+1
#define SQ_CONF SQUIDMIB, 2
#define LEN_SQ_CONF LEN_SQUIDMIB+1
#define SQ_PRF  SQUIDMIB, 3
#define LEN_SQ_PRF LEN_SQUIDMIB+1
#define SQ_NET  SQUIDMIB, 4
#define LEN_SQ_NET LEN_SQUIDMIB+1
#define SQ_MESH  SQUIDMIB, 5
#define LEN_SQ_MESH LEN_SQUIDMIB+1
#define SQ_ACC  SQUIDMIB, 6
#define LEN_SQ_ACC LEN_SQUIDMIB+1

enum {				/* basic system mib info group */
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
    SYSCONNTBL,
    SYSFDTBL,
    SYS_END
};

/* cacheConfig group */

enum {
    CONF_START,
    CONF_ADMIN,
    CONF_VERSION,
    CONF_VERSION_ID,
    CONF_UPTIME,
    CONF_LOG_FAC,
    CONF_STORAGE,
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

/* cacheMesh group */

enum {
    MESH_START,
    MESH_PTBL,
    MESH_CTBL,
    MESH_END
};

enum {				/* cachePeerTable */
    MESH_PTBL_START,
    MESH_PTBL_NAME,
    MESH_PTBL_IP,
    MESH_PTBL_HTTP,
    MESH_PTBL_ICP,
    MESH_PTBL_TYPE,
    MESH_PTBL_STATE,
    MESH_PTBL_SENT,
    MESH_PTBL_PACKED,
    MESH_PTBL_FETCHES,
    MESH_PTBL_RTT,
    MESH_PTBL_IGN,
    MESH_PTBL_KEEPAL_S,
    MESH_PTBL_KEEPAL_R,
    MESH_PTBL_END
};

enum {				/* cacheClientTable */
    MESH_CTBL_START,
    MESH_CTBL_ADDR,
    MESH_CTBL_HTREQ,
    MESH_CTBL_HTBYTES,
    MESH_CTBL_HTHITS,
    MESH_CTBL_HTHITBYTES,
    MESH_CTBL_ICPREQ,
    MESH_CTBL_ICPBYTES,
    MESH_CTBL_ICPHITS,
    MESH_CTBL_ICPHITBYTES,
    MESH_CTBL_END
};

/* cacheNetwork group */

enum {
    NETDB_START,
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
    SYS_FD_NREAD,
    SYS_FD_NWRITE,
    SYS_FD_NAME,
    SYS_FD_END
};

enum {
    SYS_CONN_START,
    SYS_CONN_FDNUM,
    SYS_CONN_READ,
    SYS_CONN_WRITE,
    SYS_CONN_ADDR,
    SYS_CONN_NAME,
    SYS_CONN_PORT,
    SYS_CONN_END
};

/* First, we have a huge array of MIBs this agent knows about */

struct MIBListEntry {
    oid Name[9];		/* Change as appropriate */
    snint NameLen;
    oid_GetFn *GetFn;
    oid_GetNextFn *GetNextFn;
};

variable_list *snmp_basicFn(variable_list *, snint *);
variable_list *snmp_meshPtblFn(variable_list *, snint *);
variable_list *snmp_meshCtblFn(variable_list *, snint *);
variable_list *snmp_confFn(variable_list *, snint *);
variable_list *snmp_sysFn(variable_list *, snint *);
variable_list *snmp_prfSysFn(variable_list *, snint *);
variable_list *snmp_prfProtoFn(variable_list *, snint *);
variable_list *snmp_prfPeerFn(variable_list *, snint *);
variable_list *snmp_netdbFn(variable_list *, snint *);
variable_list *snmp_dnsFn(variable_list *, snint *);
variable_list *snmp_ipcacheFn(variable_list *, snint *);
variable_list *snmp_fqdncacheFn(variable_list *, snint *);

extern int snmpInitAgentAuth();
extern void snmpAgentParse(void *);
extern int snmpDefaultAuth();
extern int get_median_svc(int, int);
extern void snmpAgentParseDone(int, void *);
extern int meshCtblGetRowFn(oid *, oid *);
extern int netdbGetRowFn(oid *, oid *);
extern int fqdn_getMax();
extern int ipcache_getMax();
extern struct snmp_pdu *snmpAgentResponse(struct snmp_pdu *PDU);
extern void snmpAclCheckStart(void *);
extern struct snmp_session *Session;
extern oid_ParseFn *genericGetNextFn(oid * Src, snint SrcLen, oid ** Dest, snint * DestLen,
    oid * MIBRoot, int MIBRootLen, oid_GetRowFn * getRowFn, int tblen, oid * MIBTail,
    oid_ParseFn * mygetFn, int MIBTailLen, int MIB_ACTION_INDEX);

extern int oidcmp(oid * A, snint ALen, oid * B, snint BLen);
extern int oidncmp(oid * A, snint ALen, oid * B, snint BLen, snint CompLen);
extern oid *oiddup(oid * A, snint ALen);


/* group handler definition */

extern oid_ParseFn *basicGetFn(oid *, snint);
extern oid_ParseFn *basicGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *sysGetFn(oid *, snint);
extern oid_ParseFn *sysGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *sysFdGetFn(oid *, snint);
extern oid_ParseFn *sysFdGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *sysConnGetFn(oid *, snint);
extern oid_ParseFn *sysConnGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *confGetFn(oid *, snint);
extern oid_ParseFn *confGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *confStGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *prfSysGetFn(oid *, snint);
extern oid_ParseFn *prfSysGetFn(oid *, snint);
extern oid_ParseFn *prfSysGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *prfProtoGetFn(oid *, snint);
extern oid_ParseFn *prfProtoGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *netdbGetFn(oid *, snint);
extern oid_ParseFn *netdbGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *dnsGetFn(oid *, snint);
extern oid_ParseFn *dnsGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *meshGetFn(oid *, snint);
extern oid_ParseFn *meshPtblGetNextFn(oid *, snint, oid **, snint *);
extern int meshPtblGetRowFn(oid *, oid *);
extern int sysConnGetRowFn(oid *, oid *);
extern int meshCtblGetRowFn(oid *, oid *);
extern int netdbGetRowFn(oid *, oid *);
oid_ParseFn *meshCtblGetNextFn(oid *, snint, oid **, snint *);

extern int fqdn_getMax();
extern int ipcache_getMax();
extern int fd_getMax();
extern struct in_addr *gen_getMax();

#endif
#endif
