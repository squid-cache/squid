#ifdef SQUID_SNMP
#ifndef CACHE_SNMP_H
#define CACHE_SNMP_H

/* mib stuff here */

struct subtree {
    oid name[16];		/* objid prefix of subtree */
    u_char namelen;		/* number of subid's in name above */
    struct variable *variables;	/* pointer to variables array */
    int variables_len;		/* number of entries in above array */
    int variables_width;	/* sizeof each variable entry */
    struct subtree *next;
};

#if 1
#define variable2 variable
#define variable4 variable
#define variable5 variable
#define variable7 variable
#define variable13 variable
#else
/**
 * This is a new variable structure that doesn't have as much memory
 * tied up in the object identifier.  It's elements have also been re-arranged
 * so that the name field can be variable length.  Any number of these
 * structures can be created with lengths tailor made to a particular
 * application.  The first 5 elements of the structure must remain constant.
 */
struct variable2 {
    u_char magic;		/* passed to function as a hint */
    char type;			/* type of variable */
    u_short acl;		/* access control list for variable */
    u_char *(*findVar) ();	/* function that finds variable */
    u_char namelen;		/* length of name below */
    oid name[2];		/* object identifier of variable */
};

struct variable4 {
    u_char magic;		/* passed to function as a hint */
    char type;			/* type of variable */
    u_short acl;		/* access control list for variable */
    u_char *(*findVar) ();	/* function that finds variable */
    u_char namelen;		/* length of name below */
    oid name[4];		/* object identifier of variable */
};

struct variable7 {
    u_char magic;		/* passed to function as a hint */
    char type;			/* type of variable */
    u_short acl;		/* access control list for variable */
    u_char *(*findVar) ();	/* function that finds variable */
    u_char namelen;		/* length of name below */
    oid name[7];		/* object identifier of variable */
};
struct variable13 {
    u_char magic;		/* passed to function as a hint */
    char type;			/* type of variable */
    u_short acl;		/* access control list for variable */
    u_char *(*findVar) ();	/* function that finds variable */
    u_char namelen;		/* length of name below */
    oid name[13];		/* object identifier of variable */
};

#endif


/* MIB definitions
 * We start from the SQUIDMIB as the root of the subtree
 *
 * we are under : iso.org.dod.internet.experimental.nsfnet.squid
 *
 */


#define SQUIDMIB 1, 3, 6, 1, 3, 25, 17


/* basic groups under .squid */

#define SQ_SYS SQUIDMIB, 1
#define SQ_CONF SQUIDMIB, 2
#define SQ_PRF SQUIDMIB, 3
#define SQ_ACC SQUIDMIB, 6
#define SQ_SEC SQUIDMIB, 5
#define SQ_NET SQUIDMIB, 4

/* cacheSystem group */

enum {
    SYSVMSIZ,
    SYSSTOR
};

/* cacheConfig group */

enum {
    CONF_ADMIN,
    CONF_UPTIME,
    CONF_ST_MMAXSZ,
    CONF_ST_MHIWM,
    CONF_ST_MLOWM,
    CONF_ST_SWMAXSZ,
    CONF_ST_SWHIWM,
    CONF_ST_SWLOWM,
    CONF_WAIS_RHOST,
    CONF_WAIS_RPORT,
    CONF_TIO_RD,
    CONF_TIO_CON,
    CONF_TIO_REQ,
    CONF_LOG_LVL,
    CONF_PTBL_ID,
    CONF_PTBL_NAME,
    CONF_PTBL_IP,
    CONF_PTBL_HTTP,
    CONF_PTBL_ICP,
    CONF_PTBL_TYPE,
    CONF_PTBL_STATE
};

/* cacheNetwork group */

enum {
    NETDB_ID,
    NETDB_NET,
    NETDB_PING_S,
    NETDB_PING_R,
    NETDB_HOPS,
    NETDB_RTT,
    NETDB_PINGTIME,
    NETDB_LASTUSE,
    NETDB_LINKCOUNT,
    NET_IPC_ID,
    NET_IPC_NAME,
    NET_IPC_IP,
    NET_IPC_STATE,
    NET_FQDN_ID,
    NET_FQDN_NAME,
    NET_FQDN_IP,
    NET_FQDN_LASTREF,
    NET_FQDN_EXPIRES,
    NET_FQDN_STATE,
    NET_TCPCONNS,
    NET_UDPCONNS,
    NET_INTHRPUT,
    NET_OUTHRPUT
};

enum {
    PERF_SYS_PF,
    PERF_SYS_NUMR,
    PERF_SYS_DEFR,
    PERF_SYS_MEMUSAGE,
    PERF_SYS_CPUUSAGE,
    PERF_SYS_MAXRESSZ,
    PERF_SYS_CURMEMSZ,
    PERF_SYS_CURLRUEXP,
    PERF_SYS_CURUNLREQ,
    PERF_SYS_CURUNUSED_FD,
    PERF_SYS_CURRESERVED_FD,
    PERF_SYS_NUMOBJCNT,
    PERF_PROTOSTAT_ID,
    PERF_PROTOSTAT_KBMAX,
    PERF_PROTOSTAT_KBMIN,
    PERF_PROTOSTAT_KBAVG,
    PERF_PROTOSTAT_KBNOW,
    PERF_PROTOSTAT_HIT,
    PERF_PROTOSTAT_MISS,
    PERF_PROTOSTAT_REFCOUNT,
    PERF_PROTOSTAT_TRNFRB,
    PERF_PROTOSTAT_AGGR_CLHTTP,
    PERF_PROTOSTAT_AGGR_ICP_S,
    PERF_PROTOSTAT_AGGR_ICP_R,
    PERF_PROTOSTAT_AGGR_CURSWAP,
    PERF_SYS_FD_NUMBER,
    PERF_SYS_FD_TYPE,
    PERF_SYS_FD_TOUT,
    PERF_SYS_FD_NREAD,
    PERF_SYS_FD_NWRITE,
    PERF_SYS_FD_ADDR,
    PERF_SYS_FD_NAME,
    PERF_PEERSTAT_ID,
    PERF_PEERSTAT_SENT,
    PERF_PEERSTAT_PACKED,
    PERF_PEERSTAT_FETCHES,
    PERF_PEERSTAT_RTT,
    PERF_PEERSTAT_IGN,
    PERF_PEERSTAT_KEEPAL_S,
    PERF_PEERSTAT_KEEPAL_R
};

#endif
#endif
