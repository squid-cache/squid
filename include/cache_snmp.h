/*
 * $Id: cache_snmp.h,v 1.17 1998/09/23 21:31:29 glenn Exp $
 */

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
#define CURRENT_MIB_VERSION "-- v 1.16 1998/09/22 glenn@ircache.net"
#endif

/* MIB definitions
 * SQUID-MIB
 * 	.iso.org.dod.internet.private.enterprises.nlanr.squid
 *	  1   3   6     1        4         1      3495    1
 *
 * PROXY-MIB
 *	.iso.org.dod.internet.experimental.nsfnet.proxy
 *	  1   3   6     1          3         25    17
 */

#define SQUIDMIB 1, 3, 6, 1, 4, 1, 3495, 1
#define LEN_SQUIDMIB 8

/* basic groups under .squid */

#define SQ_SYS  SQUIDMIB, 1
#define LEN_SQ_SYS LEN_SQUIDMIB+1
#define SQ_CONF SQUIDMIB, 2
#define LEN_SQ_CONF LEN_SQUIDMIB+1
#define SQ_PRF  SQUIDMIB, 3
#define LEN_SQ_PRF LEN_SQUIDMIB+1
#define SQ_NET  SQUIDMIB, 4
#define LEN_SQ_NET LEN_SQUIDMIB+1
#define SQ_MESH  SQUIDMIB, 5
#define LEN_SQ_MESH LEN_SQUIDMIB+1

/* 
	cacheSystem group 
*/

enum {
    SYS_START,
    SYSVMSIZ,
    SYSSTOR,
    SYS_UPTIME,
    SYS_END
};

/* 
	cacheConfig group 
*/

enum {
    CONF_START,
    CONF_ADMIN,
    CONF_VERSION,
    CONF_VERSION_ID,
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

/* 
	cacheMesh group 
*/

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

/* 
	cacheNetwork group 
*/

enum {
    IP_START,
    IP_ENT,
    IP_REQ,
    IP_HITS,
    IP_PENDHIT,
    IP_NEGHIT,
    IP_MISS,
    IP_GHBN,
    IP_LOC,
    IP_LENG,
    IP_END
};

enum {
    FQDN_START,
    FQDN_ENT,
    FQDN_REQ,
    FQDN_HITS,
    FQDN_PENDHIT,
    FQDN_NEGHIT,
    FQDN_MISS,
    FQDN_GHBN,
    FQDN_LENG,
    FQDN_END
};

enum {
    DNS_START,
    DNS_REQ,
    DNS_REP,
    DNS_SERVERS,
    DNS_END
};

/* 
	Cache Performance Group 
*/

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

/* First, we have a huge array of MIBs this agent knows about */

struct MIBListEntry {
    oid Name[10];		/* This needs to be fixed, a static is ugly */
    snint NameLen;
    oid_GetFn *GetFn;
    oid_GetNextFn *GetNextFn;
};

variable_list *snmp_basicFn(variable_list *, snint *);
variable_list *snmp_confFn(variable_list *, snint *);
variable_list *snmp_sysFn(variable_list *, snint *);
variable_list *snmp_prfSysFn(variable_list *, snint *);
variable_list *snmp_prfProtoFn(variable_list *, snint *);
variable_list *snmp_prfPeerFn(variable_list *, snint *);
variable_list *snmp_netIpFn(variable_list *, snint *);
variable_list *snmp_netFqdnFn(variable_list *, snint *);
variable_list *snmp_netDnsFn(variable_list *, snint *);
variable_list *snmp_meshPtblFn(variable_list *, snint *);
variable_list *snmp_meshCtblFn(variable_list *, snint *);


extern int snmpInitAgentAuth();
extern void snmpAgentParse(void *);
extern int snmpDefaultAuth();
extern int get_median_svc(int, int);
extern void snmpAgentParseDone(int, void *);
extern int meshCtblGetRowFn(oid *, oid *);
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

extern oid_ParseFn *sysGetFn(oid *, snint);
extern oid_ParseFn *sysGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *confGetFn(oid *, snint);
extern oid_ParseFn *confGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *confStGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *prfSysGetFn(oid *, snint);
extern oid_ParseFn *prfSysGetFn(oid *, snint);
extern oid_ParseFn *prfSysGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *prfProtoGetFn(oid *, snint);
extern oid_ParseFn *prfProtoGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *netIpGetFn(oid *, snint);
extern oid_ParseFn *netDnsGetFn(oid *, snint);
extern oid_ParseFn *netFqdnGetFn(oid *, snint);
extern oid_ParseFn *netFqdnGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *netIpGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *netDnsGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *meshGetFn(oid *, snint);
extern oid_ParseFn *meshPtblGetNextFn(oid *, snint, oid **, snint *);
extern oid_ParseFn *meshCtblGetNextFn(oid *, snint, oid **, snint *);
extern int meshPtblGetRowFn(oid *, oid *);
extern int sysConnGetRowFn(oid *, oid *);
extern int meshCtblGetRowFn(oid *, oid *);

extern struct in_addr *gen_getMax();

#endif
#endif
