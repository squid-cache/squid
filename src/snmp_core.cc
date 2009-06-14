/*
 * DEBUG: section 49    SNMP support
 * AUTHOR: Glenn Chisholm
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
#include "comm.h"
#include "cache_snmp.h"
#include "acl/FilledChecklist.h"
#include "ip/IpAddress.h"

#define SNMP_REQUEST_SIZE 4096
#define MAX_PROTOSTAT 5

IpAddress theOutSNMPAddr;

typedef struct _mib_tree_entry mib_tree_entry;
typedef oid *(instance_Fn) (oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn);

struct _mib_tree_entry {
    oid *name;
    int len;
    oid_ParseFn *parsefunction;
    instance_Fn *instancefunction;
    int children;

    struct _mib_tree_entry **leaves;

    struct _mib_tree_entry *parent;
};

mib_tree_entry *mib_tree_head;
mib_tree_entry *mib_tree_last;

static mib_tree_entry *snmpAddNode(oid * name, int len, oid_ParseFn * parsefunction, instance_Fn * instancefunction, int children,...);
static oid *snmpCreateOid(int length,...);
SQUIDCEXTERN void (*snmplib_debug_hook) (int, char *);
static oid *static_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn);
static oid *time_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn);
static oid *peer_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn);
static oid *client_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn);
static void snmpDecodePacket(snmp_request_t * rq);
static void snmpConstructReponse(snmp_request_t * rq);

static struct snmp_pdu *snmpAgentResponse(struct snmp_pdu *PDU);
static oid_ParseFn *snmpTreeNext(oid * Current, snint CurrentLen, oid ** Next, snint * NextLen);
static oid_ParseFn *snmpTreeGet(oid * Current, snint CurrentLen);
static mib_tree_entry *snmpTreeEntry(oid entry, snint len, mib_tree_entry * current);
static mib_tree_entry *snmpTreeSiblingEntry(oid entry, snint len, mib_tree_entry * current);
static void snmpSnmplibDebug(int lvl, char *buf);

/*
 * The functions used during startup:
 * snmpInit
 * snmpConnectionOpen
 * snmpConnectionShutdown
 * snmpConnectionClose
 */

/*
 * Turns the MIB into a Tree structure. Called during the startup process.
 */
void
snmpInit(void)
{
    debugs(49, 5, "snmpInit: Building SNMP mib tree structure");

    snmplib_debug_hook = snmpSnmplibDebug;

    mib_tree_head = snmpAddNode(snmpCreateOid(1, 1),
                                1, NULL, NULL, 1,
                                snmpAddNode(snmpCreateOid(2, 1, 3),
                                            2, NULL, NULL, 1,
                                            snmpAddNode(snmpCreateOid(3, 1, 3, 6),
                                                        3, NULL, NULL, 1,
                                                        snmpAddNode(snmpCreateOid(4, 1, 3, 6, 1),
                                                                    4, NULL, NULL, 1,
                                                                    snmpAddNode(snmpCreateOid(5, 1, 3, 6, 1, 4),
                                                                                5, NULL, NULL, 1,
                                                                                snmpAddNode(snmpCreateOid(6, 1, 3, 6, 1, 4, 1),
                                                                                            6, NULL, NULL, 1,
                                                                                            snmpAddNode(snmpCreateOid(7, 1, 3, 6, 1, 4, 1, 3495),
                                                                                                        7, NULL, NULL, 1,
                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQUIDMIB, SQUIDMIB),
                                                                                                                    8, NULL, NULL, 5,
                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_SYS, SQ_SYS),
                                                                                                                                LEN_SQ_SYS, NULL, NULL, 3,
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SYS, SQ_SYS, SYSVMSIZ),
                                                                                                                                            LEN_SYS, snmp_sysFn, static_Inst, 0),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SYS, SQ_SYS, SYSSTOR),
                                                                                                                                            LEN_SYS, snmp_sysFn, static_Inst, 0),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SYS, SQ_SYS, SYS_UPTIME),
                                                                                                                                            LEN_SYS, snmp_sysFn, static_Inst, 0)),
                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_CONF, SQ_CONF),
                                                                                                                                LEN_SQ_CONF, NULL, NULL, 6,
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SYS, SQ_CONF, CONF_ADMIN),
                                                                                                                                            LEN_SYS, snmp_confFn, static_Inst, 0),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SYS, SQ_CONF, CONF_VERSION),
                                                                                                                                            LEN_SYS, snmp_confFn, static_Inst, 0),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SYS, SQ_CONF, CONF_VERSION_ID),
                                                                                                                                            LEN_SYS, snmp_confFn, static_Inst, 0),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SYS, SQ_CONF, CONF_LOG_FAC),
                                                                                                                                            LEN_SYS, snmp_confFn, static_Inst, 0),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SYS, SQ_CONF, CONF_STORAGE),
                                                                                                                                            LEN_SYS, NULL, NULL, 4,
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_CONF_ST, SQ_CONF, CONF_STORAGE, CONF_ST_MMAXSZ),
                                                                                                                                                        LEN_CONF_ST, snmp_confFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_CONF_ST, SQ_CONF, CONF_STORAGE, CONF_ST_SWMAXSZ),
                                                                                                                                                        LEN_CONF_ST, snmp_confFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_CONF_ST, SQ_CONF, CONF_STORAGE, CONF_ST_SWHIWM),
                                                                                                                                                        LEN_CONF_ST, snmp_confFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_CONF_ST, SQ_CONF, CONF_STORAGE, CONF_ST_SWLOWM),
                                                                                                                                                        LEN_CONF_ST, snmp_confFn, static_Inst, 0)),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SYS, SQ_CONF, CONF_UNIQNAME),
                                                                                                                                            LEN_SYS, snmp_confFn, static_Inst, 0)),
                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF, SQ_PRF),
                                                                                                                                LEN_SQ_PRF, NULL, NULL, 2,
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 1, SQ_PRF, PERF_SYS),
                                                                                                                                            LEN_SQ_PRF + 1, NULL, NULL, 13,
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_PF),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_NUMR),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_MEMUSAGE),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_CPUTIME),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_CPUUSAGE),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_MAXRESSZ),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_NUMOBJCNT),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_CURLRUEXP),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_CURUNLREQ),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_CURUNUSED_FD),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_CURRESERVED_FD),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_CURUSED_FD),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, PERF_SYS_CURMAX_FD),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0)),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 1, SQ_PRF, PERF_PROTO),
                                                                                                                                            LEN_SQ_PRF + 1, NULL, NULL, 2,
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR),
                                                                                                                                                        LEN_SQ_PRF + 2, NULL, NULL, 15,
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_HTTP_REQ),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_HTTP_HITS),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_HTTP_ERRORS),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_HTTP_KBYTES_IN),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_HTTP_KBYTES_OUT),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_ICP_S),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_ICP_R),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_ICP_SKB),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_ICP_RKB),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_REQ),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_ERRORS),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_KBYTES_IN),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_KBYTES_OUT),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_CURSWAP),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_AGGR, PERF_PROTOSTAT_AGGR_CLIENTS),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0)),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_PROTO, 2),
                                                                                                                                                        LEN_SQ_PRF + 2, NULL, NULL, 1,
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_MEDIAN, 1),
                                                                                                                                                                    LEN_SQ_PRF + 3, NULL, NULL, 11,
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_MEDIAN, 1, PERF_MEDIAN_TIME),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_MEDIAN, 1, PERF_MEDIAN_HTTP_ALL),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_MEDIAN, 1, PERF_MEDIAN_HTTP_MISS),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_MEDIAN, 1, PERF_MEDIAN_HTTP_NM),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_MEDIAN, 1, PERF_MEDIAN_HTTP_HIT),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_MEDIAN, 1, PERF_MEDIAN_ICP_QUERY),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_MEDIAN, 1, PERF_MEDIAN_ICP_REPLY),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_MEDIAN, 1, PERF_MEDIAN_DNS),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_MEDIAN, 1, PERF_MEDIAN_RHR),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_MEDIAN, 1, PERF_MEDIAN_BHR),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, PERF_PROTOSTAT_MEDIAN, 1, PERF_MEDIAN_HTTP_NH),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0))))),
                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_NET, SQ_NET),
                                                                                                                                LEN_SQ_NET, NULL, NULL, 3,
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SQ_NET + 1, SQ_NET, NET_IP_CACHE),
                                                                                                                                            LEN_SQ_NET + 1, NULL, NULL, 8,
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_IP_CACHE, IP_ENT),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netIpFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_IP_CACHE, IP_REQ),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netIpFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_IP_CACHE, IP_HITS),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netIpFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_IP_CACHE, IP_PENDHIT),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netIpFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_IP_CACHE, IP_NEGHIT),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netIpFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_IP_CACHE, IP_MISS),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netIpFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_IP_CACHE, IP_GHBN),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netIpFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_IP_CACHE, IP_LOC),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netIpFn, static_Inst, 0)),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SQ_NET + 1, SQ_NET, NET_FQDN_CACHE),
                                                                                                                                            LEN_SQ_NET + 1, NULL, NULL, 7,
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_FQDN_CACHE, FQDN_ENT),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netFqdnFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_FQDN_CACHE, FQDN_REQ),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netFqdnFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_FQDN_CACHE, FQDN_HITS),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netFqdnFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_FQDN_CACHE, FQDN_PENDHIT),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netFqdnFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_FQDN_CACHE, FQDN_NEGHIT),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netFqdnFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_FQDN_CACHE, FQDN_MISS),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netFqdnFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_FQDN_CACHE, FQDN_GHBN),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netFqdnFn, static_Inst, 0)),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SQ_NET + 1, SQ_NET, NET_DNS_CACHE),
                                                                                                                                            LEN_SQ_NET + 1, NULL, NULL, 3,
#if USE_DNSSERVERS
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_DNS_CACHE, DNS_REQ),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netDnsFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_DNS_CACHE, DNS_REP),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netDnsFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_DNS_CACHE, DNS_SERVERS),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netDnsFn, static_Inst, 0))),
#else
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_DNS_CACHE, DNS_REQ),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netIdnsFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_DNS_CACHE, DNS_REP),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netIdnsFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, NET_DNS_CACHE, DNS_SERVERS),
                                                                                                                                                        LEN_SQ_NET + 2, snmp_netIdnsFn, static_Inst, 0))),
#endif
                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_MESH, SQ_MESH),
                                                                                                                                LEN_SQ_MESH, NULL, NULL, 2,
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 1, SQ_MESH, MESH_PTBL),
                                                                                                                                            LEN_SQ_MESH + 1, NULL, NULL, 1,
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 2, SQ_MESH, 1, 1),
                                                                                                                                                        LEN_SQ_MESH + 2, NULL, NULL, 15,
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_INDEX),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_NAME),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_ADDR_TYPE),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_ADDR),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_HTTP),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_ICP),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_TYPE),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_STATE),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_SENT),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_PACKED),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_FETCHES),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_RTT),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_IGN),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_KEEPAL_S),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_PTBL, 1, MESH_PTBL_KEEPAL_R),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0))),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 1, SQ_MESH, MESH_CTBL),
                                                                                                                                            LEN_SQ_MESH + 1, NULL, NULL, 1,
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 2, SQ_MESH, MESH_CTBL, 1),
                                                                                                                                                        LEN_SQ_MESH + 2, NULL, NULL, 10,
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_CTBL, 1, MESH_CTBL_ADDR_TYPE),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_CTBL, 1, MESH_CTBL_ADDR),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_CTBL, 1, MESH_CTBL_HTREQ),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_CTBL, 1, MESH_CTBL_HTBYTES),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_CTBL, 1, MESH_CTBL_HTHITS),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_CTBL, 1, MESH_CTBL_HTHITBYTES),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_CTBL, 1, MESH_CTBL_ICPREQ),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_CTBL, 1, MESH_CTBL_ICPBYTES),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_CTBL, 1, MESH_CTBL_ICPHITS),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        (mib_tree_last = snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, MESH_CTBL, 1, MESH_CTBL_ICPHITBYTES),
                                                                                                                                                                                     LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0)))))
                                                                                                                   )
                                                                                                       )
                                                                                           )
                                                                               )
                                                                   )
                                                       )
                                           )
                               );

    debugs(49, 9, "snmpInit: Completed SNMP mib tree structure");
}

void
snmpConnectionOpen(void)
{
    struct addrinfo *xaddr = NULL;
    int x;

    debugs(49, 5, "snmpConnectionOpen: Called");

    if (Config.Port.snmp > 0) {
        Config.Addrs.snmp_incoming.SetPort(Config.Port.snmp);
        enter_suid();
        theInSnmpConnection = comm_open_listener(SOCK_DGRAM,
                              IPPROTO_UDP,
                              Config.Addrs.snmp_incoming,
                              COMM_NONBLOCKING,
                              "SNMP Port");
        leave_suid();

        if (theInSnmpConnection < 0)
            fatal("Cannot open SNMP Port");

        commSetSelect(theInSnmpConnection, COMM_SELECT_READ, snmpHandleUdp, NULL, 0);

        debugs(1, 1, "Accepting SNMP messages on " << Config.Addrs.snmp_incoming << ", FD " << theInSnmpConnection << ".");

        if (!Config.Addrs.snmp_outgoing.IsNoAddr()) {
            Config.Addrs.snmp_outgoing.SetPort(Config.Port.snmp);
            enter_suid();
            theOutSnmpConnection = comm_open_listener(SOCK_DGRAM,
                                   IPPROTO_UDP,
                                   Config.Addrs.snmp_outgoing,
                                   COMM_NONBLOCKING,
                                   "SNMP Port");
            leave_suid();

            if (theOutSnmpConnection < 0)
                fatal("Cannot open Outgoing SNMP Port");

            commSetSelect(theOutSnmpConnection,
                          COMM_SELECT_READ,
                          snmpHandleUdp,
                          NULL, 0);

            debugs(1, 1, "Outgoing SNMP messages on " << Config.Addrs.snmp_outgoing << ", FD " << theOutSnmpConnection << ".");

            fd_note(theOutSnmpConnection, "Outgoing SNMP socket");

            fd_note(theInSnmpConnection, "Incoming SNMP socket");
        } else {
            theOutSnmpConnection = theInSnmpConnection;
        }

        theOutSNMPAddr.SetEmpty();

        theOutSNMPAddr.InitAddrInfo(xaddr);

        x = getsockname(theOutSnmpConnection, xaddr->ai_addr, &xaddr->ai_addrlen);

        if (x < 0)
            debugs(51, 1, "theOutSnmpConnection FD " << theOutSnmpConnection << ": getsockname: " << xstrerror());
        else
            theOutSNMPAddr = *xaddr;

        theOutSNMPAddr.FreeAddrInfo(xaddr);
    }
}

void
snmpConnectionShutdown(void)
{
    if (theInSnmpConnection < 0)
        return;

    if (theInSnmpConnection != theOutSnmpConnection) {
        debugs(49, 1, "FD " << theInSnmpConnection << " Closing SNMP socket");
        comm_close(theInSnmpConnection);
    }

    /*
     * Here we set 'theInSnmpConnection' to -1 even though the SNMP 'in'
     * and 'out' sockets might be just one FD.  This prevents this
     * function from executing repeatedly.  When we are really ready to
     * exit or restart, main will comm_close the 'out' descriptor.
     */
    theInSnmpConnection = -1;

    /*
     * Normally we only write to the outgoing SNMP socket, but we
     * also have a read handler there to catch messages sent to that
     * specific interface.  During shutdown, we must disable reading
     * on the outgoing socket.
     */
    assert(theOutSnmpConnection > -1);

    commSetSelect(theOutSnmpConnection, COMM_SELECT_READ, NULL, NULL, 0);
}

void
snmpConnectionClose(void)
{
    snmpConnectionShutdown();

    if (theOutSnmpConnection > -1) {
        debugs(49, 1, "FD " << theOutSnmpConnection << " Closing SNMP socket");
        comm_close(theOutSnmpConnection);
        /* make sure the SNMP out connection is unset */
        theOutSnmpConnection = -1;
    }
}

/*
 * Functions for handling the requests.
 */

/*
 * Accept the UDP packet
 */
void
snmpHandleUdp(int sock, void *not_used)
{
    LOCAL_ARRAY(char, buf, SNMP_REQUEST_SIZE);
    IpAddress from;
    snmp_request_t *snmp_rq;
    int len;

    debugs(49, 5, "snmpHandleUdp: Called.");

    commSetSelect(sock, COMM_SELECT_READ, snmpHandleUdp, NULL, 0);

    memset(buf, '\0', SNMP_REQUEST_SIZE);

    len = comm_udp_recvfrom(sock,
                            buf,
                            SNMP_REQUEST_SIZE,
                            0,
                            from);

    if (len > 0) {
        buf[len] = '\0';
        debugs(49, 3, "snmpHandleUdp: FD " << sock << ": received " << len << " bytes from " << from << ".");

        snmp_rq = (snmp_request_t *)xcalloc(1, sizeof(snmp_request_t));
        snmp_rq->buf = (u_char *) buf;
        snmp_rq->len = len;
        snmp_rq->sock = sock;
        snmp_rq->outbuf = (unsigned char *)xmalloc(snmp_rq->outlen = SNMP_REQUEST_SIZE);
        snmp_rq->from = from;
        snmpDecodePacket(snmp_rq);
        xfree(snmp_rq->outbuf);
        xfree(snmp_rq);
    } else {
        debugs(49, 1, "snmpHandleUdp: FD " << sock << " recvfrom: " << xstrerror());
    }
}

/*
 * Turn SNMP packet into a PDU, check available ACL's
 */
static void
snmpDecodePacket(snmp_request_t * rq)
{
    struct snmp_pdu *PDU;
    u_char *Community;
    u_char *buf = rq->buf;
    int len = rq->len;
    int allow = 0;

    debugs(49, 5, HERE << "Called.");
    PDU = snmp_pdu_create(0);
    /* Allways answer on SNMPv1 */
    rq->session.Version = SNMP_VERSION_1;
    Community = snmp_parse(&rq->session, PDU, buf, len);

    /* Check if we have explicit permission to access SNMP data.
     * default (set above) is to deny all */
    if (Community && Config.accessList.snmp) {
        ACLFilledChecklist checklist(Config.accessList.snmp, NULL, NULL);
        checklist.src_addr = rq->from;
        checklist.snmp_community = (char *) Community;
        allow = checklist.fastCheck();
    }

    if ((snmp_coexist_V2toV1(PDU)) && (Community) && (allow)) {
        rq->community = Community;
        rq->PDU = PDU;
        debugs(49, 5, "snmpAgentParse: reqid=[" << PDU->reqid << "]");
        snmpConstructReponse(rq);
    } else {
        debugs(49, 1, HERE << "Failed SNMP agent query from : " << rq->from);
        snmp_free_pdu(PDU);
    }

    if (Community)
        xfree(Community);
}

/*
 * Packet OK, ACL Check OK, Create reponse.
 */
static void
snmpConstructReponse(snmp_request_t * rq)
{

    struct snmp_pdu *RespPDU;

    debugs(49, 5, "snmpConstructReponse: Called.");
    RespPDU = snmpAgentResponse(rq->PDU);
    snmp_free_pdu(rq->PDU);

    if (RespPDU != NULL) {
        snmp_build(&rq->session, RespPDU, rq->outbuf, &rq->outlen);
        comm_udp_sendto(rq->sock, rq->from, rq->outbuf, rq->outlen);
        snmp_free_pdu(RespPDU);
    }
}

/*
 * Decide how to respond to the request, construct a response and
 * return the response to the requester.
 */

static struct snmp_pdu *

            snmpAgentResponse(struct snmp_pdu *PDU) {

    struct snmp_pdu *Answer = NULL;

    debugs(49, 5, "snmpAgentResponse: Called.");

    if ((Answer = snmp_pdu_create(SNMP_PDU_RESPONSE))) {
        Answer->reqid = PDU->reqid;
        Answer->errindex = 0;

        if (PDU->command == SNMP_PDU_GET || PDU->command == SNMP_PDU_GETNEXT) {
            /* Indirect way */
            int get_next = (PDU->command == SNMP_PDU_GETNEXT);
            variable_list *VarPtr_;
            variable_list **RespVars = &(Answer->variables);
            oid_ParseFn *ParseFn;
            int index = 0;
            /* Loop through all variables */

            for (VarPtr_ = PDU->variables; VarPtr_; VarPtr_ = VarPtr_->next_variable) {
                variable_list *VarPtr = VarPtr_;
                variable_list *VarNew = NULL;
                oid *NextOidName = NULL;
                snint NextOidNameLen = 0;

                index++;

                if (get_next)
                    ParseFn = snmpTreeNext(VarPtr->name, VarPtr->name_length, &NextOidName, &NextOidNameLen);
                else
                    ParseFn = snmpTreeGet(VarPtr->name, VarPtr->name_length);

                if (ParseFn == NULL) {
                    Answer->errstat = SNMP_ERR_NOSUCHNAME;
                    debugs(49, 5, "snmpAgentResponse: No such oid. ");
                } else {
                    if (get_next) {
                        VarPtr = snmp_var_new(NextOidName, NextOidNameLen);
                        xfree(NextOidName);
                    }

                    int * errstatTmp =  &(Answer->errstat);

                    VarNew = (*ParseFn) (VarPtr, (snint *) errstatTmp);

                    if (get_next)
                        snmp_var_free(VarPtr);
                }

                if ((Answer->errstat != SNMP_ERR_NOERROR) || (VarNew == NULL)) {
                    Answer->errindex = index;
                    debugs(49, 5, "snmpAgentResponse: error.");

                    if (VarNew)
                        snmp_var_free(VarNew);

                    while ((VarPtr = Answer->variables) != NULL) {
                        Answer->variables = VarPtr->next_variable;
                        snmp_var_free(VarPtr);
                    }

                    /* Steal the original PDU list of variables for the error response */
                    Answer->variables = PDU->variables;

                    PDU->variables = NULL;

                    return (Answer);
                }

                /* No error.  Insert this var at the end, and move on to the next.
                 */
                *RespVars = VarNew;

                RespVars = &(VarNew->next_variable);
            }
        }
    }

    return (Answer);
}

static oid_ParseFn *
snmpTreeGet(oid * Current, snint CurrentLen)
{
    oid_ParseFn *Fn = NULL;
    mib_tree_entry *mibTreeEntry = NULL;
    int count = 0;

    debugs(49, 5, "snmpTreeGet: Called");

    debugs(49, 6, "snmpTreeGet: Current : ");
    snmpDebugOid(6, Current, CurrentLen);

    mibTreeEntry = mib_tree_head;

    if (Current[count] == mibTreeEntry->name[count]) {
        count++;

        while ((mibTreeEntry) && (count < CurrentLen) && (!mibTreeEntry->parsefunction)) {
            mibTreeEntry = snmpTreeEntry(Current[count], count, mibTreeEntry);
            count++;
        }
    }

    if (mibTreeEntry && mibTreeEntry->parsefunction)
        Fn = mibTreeEntry->parsefunction;

    debugs(49, 5, "snmpTreeGet: return");

    return (Fn);
}

static oid_ParseFn *
snmpTreeNext(oid * Current, snint CurrentLen, oid ** Next, snint * NextLen)
{
    oid_ParseFn *Fn = NULL;
    mib_tree_entry *mibTreeEntry = NULL, *nextoid = NULL;
    int count = 0;

    debugs(49, 5, "snmpTreeNext: Called");

    debugs(49, 6, "snmpTreeNext: Current : ");
    snmpDebugOid(6, Current, CurrentLen);

    mibTreeEntry = mib_tree_head;

    if (Current[count] == mibTreeEntry->name[count]) {
        count++;

        while ((mibTreeEntry) && (count < CurrentLen) && (!mibTreeEntry->parsefunction)) {
            mib_tree_entry *nextmibTreeEntry = snmpTreeEntry(Current[count], count, mibTreeEntry);

            if (!nextmibTreeEntry)
                break;
            else
                mibTreeEntry = nextmibTreeEntry;

            count++;
        }
        debugs(49, 5, "snmpTreeNext: Recursed down to requested object");
    } else {
        return NULL;
    }

    if (mibTreeEntry == mib_tree_last)
        return (Fn);


    if ((mibTreeEntry) && (mibTreeEntry->parsefunction)) {
        *NextLen = CurrentLen;
        *Next = (*mibTreeEntry->instancefunction) (Current, NextLen, mibTreeEntry, &Fn);
        if (*Next) {
            debugs(49, 6, "snmpTreeNext: Next : ");
            snmpDebugOid(6, *Next, *NextLen);
            return (Fn);
        }
    }

    if ((mibTreeEntry) && (mibTreeEntry->parsefunction)) {
        count--;
        nextoid = snmpTreeSiblingEntry(Current[count], count, mibTreeEntry->parent);
        if (nextoid) {
            debugs(49, 5, "snmpTreeNext: Next OID found for sibling" << nextoid );
            mibTreeEntry = nextoid;
            count++;
        } else {
            debugs(49, 5, "snmpTreeNext: Attempting to recurse up for next object");

            while (!nextoid) {
                count--;

                if (mibTreeEntry->parent->parent) {
                    nextoid = mibTreeEntry->parent;
                    mibTreeEntry = snmpTreeEntry(Current[count] + 1, count, nextoid->parent);

                    if (!mibTreeEntry) {
                        mibTreeEntry = nextoid;
                        nextoid = NULL;
                    }
                } else {
                    nextoid = mibTreeEntry;
                    mibTreeEntry = NULL;
                }
            }
        }
    }
    while ((mibTreeEntry) && (!mibTreeEntry->parsefunction)) {
        mibTreeEntry = mibTreeEntry->leaves[0];
    }

    if (mibTreeEntry) {
        *NextLen = mibTreeEntry->len;
        *Next = (*mibTreeEntry->instancefunction) (mibTreeEntry->name, NextLen, mibTreeEntry, &Fn);
    }

    if (*Next) {
        debugs(49, 6, "snmpTreeNext: Next : ");
        snmpDebugOid(6, *Next, *NextLen);
        return (Fn);
    } else
        return NULL;
}

static oid *
static_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn)
{
    oid *instance = NULL;
    if (*len <= current->len) {
        instance = (oid *)xmalloc(sizeof(name) * (*len + 1));
        xmemcpy(instance, name, (sizeof(name) * *len));
        instance[*len] = 0;
        *len += 1;
    }
    *Fn = current->parsefunction;
    return (instance);
}

static oid *
time_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn)
{
    oid *instance = NULL;
    int identifier = 0, loop = 0;
    int index[TIME_INDEX_LEN] = {TIME_INDEX};

    if (*len <= current->len) {
        instance = (oid *)xmalloc(sizeof(name) * (*len + 1));
        xmemcpy(instance, name, (sizeof(name) * *len));
        instance[*len] = *index;
        *len += 1;
    } else {
        identifier = name[*len - 1];

        while ((loop < TIME_INDEX_LEN) && (identifier != index[loop]))
            loop++;

        if (loop < (TIME_INDEX_LEN - 1)) {
            instance = (oid *)xmalloc(sizeof(name) * (*len));
            xmemcpy(instance, name, (sizeof(name) * *len));
            instance[*len - 1] = index[++loop];
        }
    }

    *Fn = current->parsefunction;
    return (instance);
}


static oid *
peer_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn)
{
    oid *instance = NULL;
    peer *peers = Config.peers;

    if (peers == NULL) {
        current = current->parent->parent->parent->leaves[1];
        while ((current) && (!current->parsefunction))
            current = current->leaves[0];

        instance = client_Inst(current->name, len, current, Fn);
    } else if (*len <= current->len) {
        instance = (oid *)xmalloc(sizeof(name) * ( *len + 1));
        xmemcpy(instance, name, (sizeof(name) * *len));
        instance[*len] = 1 ;
        *len += 1;
    } else {
        int no = name[current->len] ;
        int i ; // Note: This works because the Confifg.peers
        // keep its index acording to its position.
        for ( i=0 ; peers && (i < no) ; peers = peers->next , i++ ) ;

        if (peers) {
            instance = (oid *)xmalloc(sizeof(name) * (current->len + 1 ));
            xmemcpy(instance, name, (sizeof(name) * current->len ));
            instance[current->len] = no + 1 ; // i.e. the next index on cache_peeer table.
        } else {
            return (instance);
        }
    }
    *Fn = current->parsefunction;
    return (instance);
}

static oid *
client_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn)
{
    oid *instance = NULL;
    IpAddress laddr;
    IpAddress *aux;
    int size = 0;
    int newshift = 0;

    if (*len <= current->len) {
        aux  = client_entry(NULL);
        if (aux)
            laddr = *aux;
        else
            laddr.SetAnyAddr();

        if (laddr.IsIPv4())
            size = sizeof(in_addr);
#if USE_IPV6
        else
            size = sizeof(in6_addr);
#endif

        instance = (oid *)xmalloc(sizeof(name) * (*len + size ));
        xmemcpy(instance, name, (sizeof(name) * (*len)));

        if ( !laddr.IsAnyAddr() ) {
            addr2oid(laddr, &instance[ *len]);  // the addr
            *len += size ;
        }
    } else {
        int shift = *len - current->len ; // i.e 4 or 16
        oid2addr(&name[*len - shift], laddr,shift);
        aux = client_entry(&laddr);
        if (aux)
            laddr = *aux;
        else
            laddr.SetAnyAddr();

        if (!laddr.IsAnyAddr()) {
            if (laddr.IsIPv4())
                newshift = sizeof(in_addr);
#if USE_IPV6
            else
                newshift = sizeof(in6_addr);
#endif
            instance = (oid *)xmalloc(sizeof(name) * (current->len +  newshift));
            xmemcpy(instance, name, (sizeof(name) * (current->len)));
            addr2oid(laddr, &instance[current->len]);  // the addr.
            *len = current->len + newshift ;
        }
    }

    *Fn = current->parsefunction;
    return (instance);
}


/*
 * Utility functions
 */

/*
 * Tree utility functions.
 */

/*
 * Returns a sibling object for the requested child object or NULL
 * if it does not exit
 */
static mib_tree_entry *
snmpTreeSiblingEntry(oid entry, snint len, mib_tree_entry * current)
{
    mib_tree_entry *next = NULL;
    int count = 0;

    while ((!next) && (count < current->children)) {
        if (current->leaves[count]->name[len] == entry) {
            next = current->leaves[count];
        }

        count++;
    }

    /* Exactly the sibling on rigth */
    if (count < current->children) {
        next = current->leaves[count];
    } else {
        next = NULL;
    }

    return (next);
}

/*
 * Returns the requested child object or NULL if it does not exist
 */
static mib_tree_entry *
snmpTreeEntry(oid entry, snint len, mib_tree_entry * current)
{
    mib_tree_entry *next = NULL;
    int count = 0;

    while ((!next) && (count < current->children)) {
        if (current->leaves[count]->name[len] == entry) {
            next = current->leaves[count];
        }

        count++;
    }

    return (next);
}

/*
 * Adds a node to the MIB tree structure and adds the appropriate children
 */
static mib_tree_entry *
snmpAddNode(oid * name, int len, oid_ParseFn * parsefunction, instance_Fn * instancefunction, int children,...)
{
    va_list args;
    int loop;
    mib_tree_entry *entry = NULL;
    va_start(args, children);

    debugs(49, 6, "snmpAddNode: Children : " << children << ", Oid : ");
    snmpDebugOid(6, name, len);

    va_start(args, children);
    entry = (mib_tree_entry *)xmalloc(sizeof(mib_tree_entry));
    entry->name = name;
    entry->len = len;
    entry->parsefunction = parsefunction;
    entry->instancefunction = instancefunction;
    entry->children = children;

    if (children > 0) {
        entry->leaves = (mib_tree_entry **)xmalloc(sizeof(mib_tree_entry *) * children);

        for (loop = 0; loop < children; loop++) {
            entry->leaves[loop] = va_arg(args, mib_tree_entry *);
            entry->leaves[loop]->parent = entry;
        }
    }

    return (entry);
}
/* End of tree utility functions */

/*
 * Returns the list of parameters in an oid
 */
static oid *
snmpCreateOid(int length,...)
{
    va_list args;
    oid *new_oid;
    int loop;
    va_start(args, length);

    new_oid = (oid *)xmalloc(sizeof(oid) * length);

    if (length > 0) {
        for (loop = 0; loop < length; loop++) {
            new_oid[loop] = va_arg(args, int);
        }
    }

    return (new_oid);
}

/*
 * Debug calls, prints out the OID for debugging purposes.
 */
void
snmpDebugOid(int lvl, oid * Name, snint Len)
{
    char mbuf[16], objid[1024];
    int x;
    objid[0] = '\0';

    for (x = 0; x < Len; x++) {
        snprintf(mbuf, sizeof(mbuf), ".%u", (unsigned int) Name[x]);
        strncat(objid, mbuf, sizeof(objid) - strlen(objid) - 1);
    }

    debugs(49, lvl, "   oid = " << objid);
}

static void
snmpSnmplibDebug(int lvl, char *buf)
{
    debug(49, lvl) ("%s", buf);
}



/*
   IPv4 address: 10.10.0.9  ==>
   oid == 10.10.0.9
   IPv6 adress : 20:01:32:ef:a2:21:fb:32:00:00:00:00:00:00:00:00:OO:01 ==>
   oid == 32.1.50.239.162.33.251.20.50.0.0.0.0.0.0.0.0.0.1
*/
void
addr2oid(IpAddress &addr, oid * Dest)
{
    u_int i ;
    u_char *cp = NULL;
    struct in_addr iaddr;
#if USE_IPV6
    struct in6_addr i6addr;
    oid code = addr.IsIPv4()? INETADDRESSTYPE_IPV4  : INETADDRESSTYPE_IPV6 ;
    u_int size = (code == INETADDRESSTYPE_IPV4) ? sizeof(struct in_addr):sizeof(struct in6_addr);
#else
    oid code = INETADDRESSTYPE_IPV4 ;
    u_int size = sizeof(struct in_addr) ;
#endif /* USE_IPV6 */
    //  Dest[0] = code ;
    if ( code == INETADDRESSTYPE_IPV4 ) {
        addr.GetInAddr(iaddr);
        cp = (u_char *) &(iaddr.s_addr);
    }
#if USE_IPV6
    else {
        addr.GetInAddr(i6addr);
        cp = (u_char *) &i6addr;
    }
#endif
    for ( i=0 ; i < size ; i++) {
        // OID's are in network order
        Dest[i] = *cp++;
    }
    debugs(49, 7, "addr2oid: Dest : ");
    snmpDebugOid(7, Dest, size );

}

/*
   oid == 10.10.0.9 ==>
   IPv4 address: 10.10.0.9
   oid == 32.1.50.239.162.33.251.20.50.0.0.0.0.0.0.0.0.0.1 ==>
   IPv6 adress : 20:01:32:ef:a2:21:fb:32:00:00:00:00:00:00:00:00:OO:01
*/
void
oid2addr(oid * id, IpAddress &addr, u_int size)
{
    struct in_addr iaddr;
    u_int i;
    u_char *cp;
#if USE_IPV6
    struct in6_addr i6addr;
    if ( size == sizeof(struct in_addr) )
#endif /* USE_IPV6 */
        cp = (u_char *) &(iaddr.s_addr);
#if USE_IPV6
    else
        cp = (u_char *) &(i6addr);
#endif /* USE_IPV6 */
    debugs(49, 7, "oid2addr: id : ");
    snmpDebugOid(7, id, size  );
    for (i=0 ; i<size; i++) {
        cp[i] = id[i];
    }
#if USE_IPV6
    if ( size == sizeof(struct in_addr) )
#endif
        addr = iaddr;
#if USE_IPV6
    else
        addr = i6addr;
#endif

}

/* SNMP checklists */
#include "acl/Strategy.h"
#include "acl/Strategised.h"
#include "acl/StringData.h"

class ACLSNMPCommunityStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
    static ACLSNMPCommunityStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLSNMPCommunityStrategy(ACLSNMPCommunityStrategy const &);

private:
    static ACLSNMPCommunityStrategy Instance_;
    ACLSNMPCommunityStrategy() {}

    ACLSNMPCommunityStrategy&operator=(ACLSNMPCommunityStrategy const &);
};

class ACLSNMPCommunity
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<char const *> RegistryEntry_;
};

ACL::Prototype ACLSNMPCommunity::RegistryProtoype(&ACLSNMPCommunity::RegistryEntry_, "snmp_community");
ACLStrategised<char const *> ACLSNMPCommunity::RegistryEntry_(new ACLStringData, ACLSNMPCommunityStrategy::Instance(), "snmp_community");

int
ACLSNMPCommunityStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    return data->match (checklist->snmp_community);
}

ACLSNMPCommunityStrategy *
ACLSNMPCommunityStrategy::Instance()
{
    return &Instance_;
}

ACLSNMPCommunityStrategy ACLSNMPCommunityStrategy::Instance_;
