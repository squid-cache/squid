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
#include "acl/FilledChecklist.h"
#include "base/CbcPointer.h"
#include "CachePeer.h"
#include "client_db.h"
#include "comm.h"
#include "comm/Connection.h"
#include "comm/Loops.h"
#include "comm/UdpOpenDialer.h"
#include "ip/Address.h"
#include "ip/tools.h"
#include "snmp_agent.h"
#include "snmp_core.h"
#include "snmp/Forwarder.h"
#include "SnmpRequest.h"
#include "SquidConfig.h"
#include "tools.h"

static void snmpPortOpened(const Comm::ConnectionPointer &conn, int errNo);

mib_tree_entry *mib_tree_head;
mib_tree_entry *mib_tree_last;

Comm::ConnectionPointer snmpIncomingConn;
Comm::ConnectionPointer snmpOutgoingConn;

static mib_tree_entry * snmpAddNodeStr(const char *base_str, int o, oid_ParseFn * parsefunction, instance_Fn * instancefunction, AggrType aggrType = atNone);
static mib_tree_entry *snmpAddNode(oid * name, int len, oid_ParseFn * parsefunction, instance_Fn * instancefunction, AggrType aggrType, int children,...);
static oid *snmpCreateOid(int length,...);
mib_tree_entry * snmpLookupNodeStr(mib_tree_entry *entry, const char *str);
bool snmpCreateOidFromStr(const char *str, oid **name, int *nl);
SQUIDCEXTERN void (*snmplib_debug_hook) (int, char *);
static oid *static_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn);
static oid *time_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn);
static oid *peer_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn);
static oid *client_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn);
static void snmpDecodePacket(SnmpRequest * rq);
static void snmpConstructReponse(SnmpRequest * rq);

static oid_ParseFn *snmpTreeNext(oid * Current, snint CurrentLen, oid ** Next, snint * NextLen);
static oid_ParseFn *snmpTreeGet(oid * Current, snint CurrentLen);
static mib_tree_entry *snmpTreeEntry(oid entry, snint len, mib_tree_entry * current);
static mib_tree_entry *snmpTreeSiblingEntry(oid entry, snint len, mib_tree_entry * current);
extern "C" void snmpSnmplibDebug(int lvl, char *buf);

/*
 * The functions used during startup:
 * snmpInit
 * snmpConnectionOpen
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

    /*
     * This following bit of evil is to get the final node in the "squid" mib
     * without having a "search" function. A search function should be written
     * to make this and the other code much less evil.
     */
    mib_tree_head = snmpAddNode(snmpCreateOid(1, 1), 1, NULL, NULL, atNone, 0);

    assert(mib_tree_head);
    debugs(49, 5, "snmpInit: root is " << mib_tree_head);
    snmpAddNodeStr("1", 3, NULL, NULL);

    snmpAddNodeStr("1.3", 6, NULL, NULL);

    snmpAddNodeStr("1.3.6", 1, NULL, NULL);
    snmpAddNodeStr("1.3.6.1", 4, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4", 1, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1", 3495, NULL, NULL);
    mib_tree_entry *m2 = snmpAddNodeStr("1.3.6.1.4.1.3495", 1, NULL, NULL);

    mib_tree_entry *n = snmpLookupNodeStr(NULL, "1.3.6.1.4.1.3495.1");
    assert(m2 == n);

    /* SQ_SYS - 1.3.6.1.4.1.3495.1.1 */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1", 1, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.1", SYSVMSIZ, snmp_sysFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.1", SYSSTOR, snmp_sysFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.1", SYS_UPTIME, snmp_sysFn, static_Inst, atMax);

    /* SQ_CONF - 1.3.6.1.4.1.3495.1.2 */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1", 2, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.2", CONF_ADMIN, snmp_confFn, static_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.2", CONF_VERSION, snmp_confFn, static_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.2", CONF_VERSION_ID, snmp_confFn, static_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.2", CONF_LOG_FAC, snmp_confFn, static_Inst);

    /* SQ_CONF + CONF_STORAGE - 1.3.6.1.4.1.3495.1.5 */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.2", CONF_STORAGE, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.2.5", CONF_ST_MMAXSZ, snmp_confFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.2.5", CONF_ST_SWMAXSZ, snmp_confFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.2.5", CONF_ST_SWHIWM, snmp_confFn, static_Inst, atMin);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.2.5", CONF_ST_SWLOWM, snmp_confFn, static_Inst, atMin);

    snmpAddNodeStr("1.3.6.1.4.1.3495.1.2", CONF_UNIQNAME, snmp_confFn, static_Inst);

    /* SQ_PRF - 1.3.6.1.4.1.3495.1.3 */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1", 3, NULL, NULL);                    /* SQ_PRF */

    /* PERF_SYS - 1.3.6.1.4.1.3495.1.3.1 */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3", PERF_SYS, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_PF, snmp_prfSysFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_NUMR, snmp_prfSysFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_MEMUSAGE, snmp_prfSysFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_CPUTIME, snmp_prfSysFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_CPUUSAGE, snmp_prfSysFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_MAXRESSZ, snmp_prfSysFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_NUMOBJCNT, snmp_prfSysFn, static_Inst, atSum);
    /*
      Amos comments:
      The meaning of LRU is "oldest timestamped object in cache,  if LRU algorithm is
      used"...
      What this SMP support needs to do is aggregate via a special filter equivalent to
      min() to retain the semantic oldest-object meaning. A special one is needed that
      works as unsigned and ignores '0' values.
     */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_CURLRUEXP, snmp_prfSysFn, static_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_CURUNLREQ, snmp_prfSysFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_CURUNUSED_FD, snmp_prfSysFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_CURRESERVED_FD, snmp_prfSysFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_CURUSED_FD, snmp_prfSysFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.1", PERF_SYS_CURMAX_FD, snmp_prfSysFn, static_Inst, atMax);

    /* PERF_PROTO - 1.3.6.1.4.1.3495.1.3.2 */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3", PERF_PROTO, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2", PERF_PROTOSTAT_AGGR, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_HTTP_REQ, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_HTTP_HITS, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_HTTP_ERRORS, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_HTTP_KBYTES_IN, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_HTTP_KBYTES_OUT, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_ICP_S, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_ICP_R, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_ICP_SKB, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_ICP_RKB, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_REQ, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_ERRORS, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_KBYTES_IN, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_KBYTES_OUT, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_CURSWAP, snmp_prfProtoFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.1", PERF_PROTOSTAT_AGGR_CLIENTS, snmp_prfProtoFn, static_Inst, atSum);

    /* Note this is time-series rather than 'static' */
    /* cacheMedianSvcTable */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2", PERF_PROTOSTAT_MEDIAN, NULL, NULL);

    /* cacheMedianSvcEntry */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.2", 1, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.2.1", PERF_MEDIAN_TIME, snmp_prfProtoFn, time_Inst, atAverage);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.2.1", PERF_MEDIAN_HTTP_ALL, snmp_prfProtoFn, time_Inst, atAverage);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.2.1", PERF_MEDIAN_HTTP_MISS, snmp_prfProtoFn, time_Inst, atAverage);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.2.1", PERF_MEDIAN_HTTP_NM, snmp_prfProtoFn, time_Inst, atAverage);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.2.1", PERF_MEDIAN_HTTP_HIT, snmp_prfProtoFn, time_Inst, atAverage);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.2.1", PERF_MEDIAN_ICP_QUERY, snmp_prfProtoFn, time_Inst, atAverage);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.2.1", PERF_MEDIAN_ICP_REPLY, snmp_prfProtoFn, time_Inst, atAverage);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.2.1", PERF_MEDIAN_DNS, snmp_prfProtoFn, time_Inst, atAverage);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.2.1", PERF_MEDIAN_RHR, snmp_prfProtoFn, time_Inst, atAverage);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.2.1", PERF_MEDIAN_BHR, snmp_prfProtoFn, time_Inst, atAverage);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.3.2.2.1", PERF_MEDIAN_HTTP_NH, snmp_prfProtoFn, time_Inst, atAverage);

    /* SQ_NET - 1.3.6.1.4.1.3495.1.4 */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1", 4, NULL, NULL);

    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4", NET_IP_CACHE, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.1", IP_ENT, snmp_netIpFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.1", IP_REQ, snmp_netIpFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.1", IP_HITS, snmp_netIpFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.1", IP_PENDHIT, snmp_netIpFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.1", IP_NEGHIT, snmp_netIpFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.1", IP_MISS, snmp_netIpFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.1", IP_GHBN, snmp_netIpFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.1", IP_LOC, snmp_netIpFn, static_Inst, atSum);

    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4", NET_FQDN_CACHE, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.2", FQDN_ENT, snmp_netFqdnFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.2", FQDN_REQ, snmp_netFqdnFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.2", FQDN_HITS, snmp_netFqdnFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.2", FQDN_PENDHIT, snmp_netFqdnFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.2", FQDN_NEGHIT, snmp_netFqdnFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.2", FQDN_MISS, snmp_netFqdnFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.2", FQDN_GHBN, snmp_netFqdnFn, static_Inst, atSum);

    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4", NET_DNS_CACHE, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.3", DNS_REQ, snmp_netDnsFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.3", DNS_REP, snmp_netDnsFn, static_Inst, atSum);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.4.3", DNS_SERVERS, snmp_netDnsFn, static_Inst, atSum);

    /* SQ_MESH - 1.3.6.1.4.1.3495.1.5 */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1", 5, NULL, NULL);

    /* cachePeerTable - 1.3.6.1.4.1.3495.1.5.1 */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5", MESH_PTBL, NULL, NULL);

    /* CachePeerTableEntry (version 3) - 1.3.6.1.4.1.3495.1.5.1.3 */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1", 3, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_INDEX, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_NAME, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_ADDR_TYPE, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_ADDR, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_HTTP, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_ICP, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_TYPE, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_STATE, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_SENT, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_PACKED, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_FETCHES, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_RTT, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_IGN, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_KEEPAL_S, snmp_meshPtblFn, peer_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.1.3", MESH_PTBL_KEEPAL_R, snmp_meshPtblFn, peer_Inst);

    /* cacheClientTable - 1.3.6.1.4.1.3495.1.5.2 */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5", MESH_CTBL, NULL, NULL);

    /* BUG 2811: we NEED to create a reliable index for the client DB and make version 3 of the table. */
    /* for now we have version 2 table with OID capable of mixed IPv4 / IPv6 clients and upgraded address text format. */

    /* cacheClientEntry - 1.3.6.1.4.1.3495.1.5.2.2 */
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.2", 2, NULL, NULL);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.2.2", MESH_CTBL_ADDR_TYPE, snmp_meshCtblFn, client_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.2.2", MESH_CTBL_ADDR, snmp_meshCtblFn, client_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.2.2", MESH_CTBL_HTREQ, snmp_meshCtblFn, client_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.2.2", MESH_CTBL_HTBYTES, snmp_meshCtblFn, client_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.2.2", MESH_CTBL_HTHITS, snmp_meshCtblFn, client_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.2.2", MESH_CTBL_HTHITBYTES, snmp_meshCtblFn, client_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.2.2", MESH_CTBL_ICPREQ, snmp_meshCtblFn, client_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.2.2", MESH_CTBL_ICPBYTES, snmp_meshCtblFn, client_Inst);
    snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.2.2", MESH_CTBL_ICPHITS, snmp_meshCtblFn, client_Inst);
    mib_tree_last = snmpAddNodeStr("1.3.6.1.4.1.3495.1.5.2.2", MESH_CTBL_ICPHITBYTES, snmp_meshCtblFn, client_Inst);

    debugs(49, 9, "snmpInit: Completed SNMP mib tree structure");
}

void
snmpOpenPorts(void)
{
    debugs(49, 5, "snmpConnectionOpen: Called");

    if (Config.Port.snmp <= 0)
        return;

    snmpIncomingConn = new Comm::Connection;
    snmpIncomingConn->local = Config.Addrs.snmp_incoming;
    snmpIncomingConn->local.port(Config.Port.snmp);

    if (!Ip::EnableIpv6 && !snmpIncomingConn->local.setIPv4()) {
        debugs(49, DBG_CRITICAL, "ERROR: IPv6 is disabled. " << snmpIncomingConn->local << " is not an IPv4 address.");
        fatal("SNMP port cannot be opened.");
    }
    /* split-stack for now requires IPv4-only SNMP */
    if (Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK && snmpIncomingConn->local.isAnyAddr()) {
        snmpIncomingConn->local.setIPv4();
    }

    AsyncCall::Pointer call = asyncCall(49, 2, "snmpIncomingConnectionOpened",
                                        Comm::UdpOpenDialer(&snmpPortOpened));
    Ipc::StartListening(SOCK_DGRAM, IPPROTO_UDP, snmpIncomingConn, Ipc::fdnInSnmpSocket, call);

    if (!Config.Addrs.snmp_outgoing.isNoAddr()) {
        snmpOutgoingConn = new Comm::Connection;
        snmpOutgoingConn->local = Config.Addrs.snmp_outgoing;
        snmpOutgoingConn->local.port(Config.Port.snmp);

        if (!Ip::EnableIpv6 && !snmpOutgoingConn->local.setIPv4()) {
            debugs(49, DBG_CRITICAL, "ERROR: IPv6 is disabled. " << snmpOutgoingConn->local << " is not an IPv4 address.");
            fatal("SNMP port cannot be opened.");
        }
        /* split-stack for now requires IPv4-only SNMP */
        if (Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK && snmpOutgoingConn->local.isAnyAddr()) {
            snmpOutgoingConn->local.setIPv4();
        }
        AsyncCall::Pointer c = asyncCall(49, 2, "snmpOutgoingConnectionOpened",
                                         Comm::UdpOpenDialer(&snmpPortOpened));
        Ipc::StartListening(SOCK_DGRAM, IPPROTO_UDP, snmpOutgoingConn, Ipc::fdnOutSnmpSocket, c);
    } else {
        snmpOutgoingConn = snmpIncomingConn;
        debugs(1, DBG_IMPORTANT, "Sending SNMP messages from " << snmpOutgoingConn->local);
    }
}

static void
snmpPortOpened(const Comm::ConnectionPointer &conn, int errNo)
{
    if (!Comm::IsConnOpen(conn))
        fatalf("Cannot open SNMP %s Port",(conn->fd == snmpIncomingConn->fd?"receiving":"sending"));

    Comm::SetSelect(conn->fd, COMM_SELECT_READ, snmpHandleUdp, NULL, 0);

    if (conn->fd == snmpIncomingConn->fd)
        debugs(1, DBG_IMPORTANT, "Accepting SNMP messages on " << snmpIncomingConn->local);
    else if (conn->fd == snmpOutgoingConn->fd)
        debugs(1, DBG_IMPORTANT, "Sending SNMP messages from " << snmpOutgoingConn->local);
    else
        fatalf("Lost SNMP port (%d) on FD %d", (int)conn->local.port(), conn->fd);
}

void
snmpClosePorts(void)
{
    if (Comm::IsConnOpen(snmpIncomingConn)) {
        debugs(49, DBG_IMPORTANT, "Closing SNMP receiving port " << snmpIncomingConn->local);
        snmpIncomingConn->close();
    }
    snmpIncomingConn = NULL;

    if (Comm::IsConnOpen(snmpOutgoingConn) && snmpIncomingConn != snmpOutgoingConn) {
        // Perform OUT port closure so as not to step on IN port when sharing a conn.
        debugs(49, DBG_IMPORTANT, "Closing SNMP sending port " << snmpOutgoingConn->local);
        snmpOutgoingConn->close();
    }
    snmpOutgoingConn = NULL;
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
    static char buf[SNMP_REQUEST_SIZE];
    Ip::Address from;
    SnmpRequest *snmp_rq;
    int len;

    debugs(49, 5, "snmpHandleUdp: Called.");

    Comm::SetSelect(sock, COMM_SELECT_READ, snmpHandleUdp, NULL, 0);

    memset(buf, '\0', sizeof(buf));

    len = comm_udp_recvfrom(sock, buf, sizeof(buf)-1, 0, from);

    if (len > 0) {
        debugs(49, 3, "snmpHandleUdp: FD " << sock << ": received " << len << " bytes from " << from << ".");

        snmp_rq = (SnmpRequest *)xcalloc(1, sizeof(SnmpRequest));
        snmp_rq->buf = (u_char *) buf;
        snmp_rq->len = len;
        snmp_rq->sock = sock;
        snmp_rq->outbuf = (unsigned char *)xmalloc(snmp_rq->outlen = SNMP_REQUEST_SIZE);
        snmp_rq->from = from;
        snmpDecodePacket(snmp_rq);
        xfree(snmp_rq->outbuf);
        xfree(snmp_rq);
    } else {
        debugs(49, DBG_IMPORTANT, "snmpHandleUdp: FD " << sock << " recvfrom: " << xstrerror());
    }
}

/*
 * Turn SNMP packet into a PDU, check available ACL's
 */
static void
snmpDecodePacket(SnmpRequest * rq)
{
    struct snmp_pdu *PDU;
    u_char *Community;
    u_char *buf = rq->buf;
    int len = rq->len;
    allow_t allow = ACCESS_DENIED;

    if (!Config.accessList.snmp) {
        debugs(49, DBG_IMPORTANT, "WARNING: snmp_access not configured. agent query DENIED from : " << rq->from);
        return;
    }

    debugs(49, 5, HERE << "Called.");
    PDU = snmp_pdu_create(0);
    /* Allways answer on SNMPv1 */
    rq->session.Version = SNMP_VERSION_1;
    Community = snmp_parse(&rq->session, PDU, buf, len);

    /* Check if we have explicit permission to access SNMP data.
     * default (set above) is to deny all */
    if (Community) {
        ACLFilledChecklist checklist(Config.accessList.snmp, NULL, NULL);
        checklist.src_addr = rq->from;
        checklist.snmp_community = (char *) Community;
        allow = checklist.fastCheck();

        if (allow == ACCESS_ALLOWED && (snmp_coexist_V2toV1(PDU))) {
            rq->community = Community;
            rq->PDU = PDU;
            debugs(49, 5, "snmpAgentParse: reqid=[" << PDU->reqid << "]");
            snmpConstructReponse(rq);
        } else {
            debugs(49, DBG_IMPORTANT, "WARNING: SNMP agent query DENIED from : " << rq->from);
        }
        xfree(Community);

    } else {
        debugs(49, DBG_IMPORTANT, "WARNING: Failed SNMP agent query from : " << rq->from);
        snmp_free_pdu(PDU);
    }
}

/*
 * Packet OK, ACL Check OK, Create reponse.
 */
static void
snmpConstructReponse(SnmpRequest * rq)
{

    struct snmp_pdu *RespPDU;

    debugs(49, 5, "snmpConstructReponse: Called.");

    if (UsingSmp() && IamWorkerProcess()) {
        AsyncJob::Start(new Snmp::Forwarder(static_cast<Snmp::Pdu&>(*rq->PDU),
                                            static_cast<Snmp::Session&>(rq->session), rq->sock, rq->from));
        snmp_free_pdu(rq->PDU);
        return;
    }

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

struct snmp_pdu *
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

                ++index;

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

    MemBuf tmp;
    debugs(49, 6, "snmpTreeGet: Current : " << snmpDebugOid(Current, CurrentLen, tmp) );

    mibTreeEntry = mib_tree_head;

    if (Current[count] == mibTreeEntry->name[count]) {
        ++count;

        while ((mibTreeEntry) && (count < CurrentLen) && (!mibTreeEntry->parsefunction)) {
            mibTreeEntry = snmpTreeEntry(Current[count], count, mibTreeEntry);
            ++count;
        }
    }

    if (mibTreeEntry && mibTreeEntry->parsefunction)
        Fn = mibTreeEntry->parsefunction;

    debugs(49, 5, "snmpTreeGet: return");

    return (Fn);
}

AggrType
snmpAggrType(oid* Current, snint CurrentLen)
{
    debugs(49, 5, HERE);

    mib_tree_entry* mibTreeEntry = mib_tree_head;
    AggrType type = atNone;
    int count = 0;

    if (Current[count] == mibTreeEntry->name[count]) {
        ++count;

        while (mibTreeEntry != NULL && count < CurrentLen) {
            mibTreeEntry = snmpTreeEntry(Current[count], count, mibTreeEntry);
            if (mibTreeEntry != NULL)
                type = mibTreeEntry->aggrType;
            ++count;
        }
    }

    return type;
}

static oid_ParseFn *
snmpTreeNext(oid * Current, snint CurrentLen, oid ** Next, snint * NextLen)
{
    oid_ParseFn *Fn = NULL;
    int count = 0;

    debugs(49, 5, "snmpTreeNext: Called");

    MemBuf tmp;
    debugs(49, 6, "snmpTreeNext: Current : " << snmpDebugOid(Current, CurrentLen, tmp));

    mib_tree_entry *mibTreeEntry = mib_tree_head;

    if (mibTreeEntry && Current[count] == mibTreeEntry->name[count]) {
        ++count;

        while ((mibTreeEntry) && (count < CurrentLen) && (!mibTreeEntry->parsefunction)) {
            mib_tree_entry *nextmibTreeEntry = snmpTreeEntry(Current[count], count, mibTreeEntry);

            if (!nextmibTreeEntry)
                break;
            else
                mibTreeEntry = nextmibTreeEntry;

            ++count;
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
            debugs(49, 6, "snmpTreeNext: Next : " << snmpDebugOid(*Next, *NextLen, tmp));
            return (Fn);
        }
    }

    if ((mibTreeEntry) && (mibTreeEntry->parsefunction)) {
        --count;
        mib_tree_entry *nextoid = snmpTreeSiblingEntry(Current[count], count, mibTreeEntry->parent);
        if (nextoid) {
            debugs(49, 5, "snmpTreeNext: Next OID found for sibling" << nextoid );
            mibTreeEntry = nextoid;
            ++count;
        } else {
            debugs(49, 5, "snmpTreeNext: Attempting to recurse up for next object");

            while (!nextoid) {
                --count;

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
        debugs(49, 6, "snmpTreeNext: Next : " << snmpDebugOid(*Next, *NextLen, tmp));
        return (Fn);
    } else
        return NULL;
}

static oid *
static_Inst(oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn)
{
    oid *instance = NULL;
    if (*len <= current->len) {
        instance = (oid *)xmalloc(sizeof(*name) * (*len + 1));
        memcpy(instance, name, sizeof(*name) * (*len));
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
        instance = (oid *)xmalloc(sizeof(*name) * (*len + 1));
        memcpy(instance, name, sizeof(*name) * (*len));
        instance[*len] = *index;
        *len += 1;
    } else {
        identifier = name[*len - 1];

        while ((loop < TIME_INDEX_LEN) && (identifier != index[loop]))
            ++loop;

        if (loop < (TIME_INDEX_LEN - 1)) {
            instance = (oid *)xmalloc(sizeof(*name) * (*len));
            memcpy(instance, name, sizeof(*name) * (*len));
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
    CachePeer *peers = Config.peers;

    if (peers == NULL) {
        debugs(49, 6, "snmp peer_Inst: No Peers.");
        current = current->parent->parent->parent->leaves[1];
        while ((current) && (!current->parsefunction))
            current = current->leaves[0];

        if (!current)
            return (instance);

        instance = client_Inst(current->name, len, current, Fn);
    } else if (*len <= current->len) {
        debugs(49, 6, "snmp peer_Inst: *len <= current->len ???");
        instance = (oid *)xmalloc(sizeof(*name) * ( *len + 1));
        memcpy(instance, name, sizeof(*name) * (*len));
        instance[*len] = 1 ;
        *len += 1;
    } else {
        int no = name[current->len] ;
        int i;
        // Note: This works because the Config.peers keeps its index according to its position.
        for ( i=0 ; peers && (i < no) ; peers = peers->next , ++i ) ;

        if (peers) {
            debugs(49, 6, "snmp peer_Inst: Encode peer #" << i);
            instance = (oid *)xmalloc(sizeof(*name) * (current->len + 1 ));
            memcpy(instance, name, (sizeof(*name) * current->len ));
            instance[current->len] = no + 1 ; // i.e. the next index on cache_peeer table.
        } else {
            debugs(49, 6, "snmp peer_Inst: We have " << i << " peers. Can't find #" << no);
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
    Ip::Address laddr;
    Ip::Address *aux;
    int size = 0;
    int newshift = 0;

    if (*len <= current->len) {
        aux  = client_entry(NULL);
        if (aux)
            laddr = *aux;
        else
            laddr.setAnyAddr();

        if (laddr.isIPv4())
            size = sizeof(in_addr);
        else
            size = sizeof(in6_addr);

        debugs(49, 6, HERE << "len" << *len << ", current-len" << current->len << ", addr=" << laddr << ", size=" << size);

        instance = (oid *)xmalloc(sizeof(*name) * (*len + size ));
        memcpy(instance, name, (sizeof(*name) * (*len)));

        if ( !laddr.isAnyAddr() ) {
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
            laddr.setAnyAddr();

        if (!laddr.isAnyAddr()) {
            if (laddr.isIPv4())
                newshift = sizeof(in_addr);
            else
                newshift = sizeof(in6_addr);

            debugs(49, 6, HERE << "len" << *len << ", current-len" << current->len << ", addr=" << laddr << ", newshift=" << newshift);

            instance = (oid *)xmalloc(sizeof(*name) * (current->len +  newshift));
            memcpy(instance, name, (sizeof(*name) * (current->len)));
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

        ++count;
    }

    /* Exactly the sibling on right */
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

    while ((!next) && current && (count < current->children)) {
        if (current->leaves[count]->name[len] == entry) {
            next = current->leaves[count];
        }

        ++count;
    }

    return (next);
}

void
snmpAddNodeChild(mib_tree_entry *entry, mib_tree_entry *child)
{
    debugs(49, 5, "snmpAddNodeChild: assigning " << child << " to parent " << entry);
    entry->leaves = (mib_tree_entry **)xrealloc(entry->leaves, sizeof(mib_tree_entry *) * (entry->children + 1));
    entry->leaves[entry->children] = child;
    entry->leaves[entry->children]->parent = entry;
    ++ entry->children;
}

mib_tree_entry *
snmpLookupNodeStr(mib_tree_entry *root, const char *str)
{
    oid *name;
    int namelen;
    mib_tree_entry *e;

    if (root)
        e = root;
    else
        e = mib_tree_head;

    if (! snmpCreateOidFromStr(str, &name, &namelen))
        return NULL;

    /* I wish there were some kind of sensible existing tree traversal
     * routine to use. I'll worry about that later */
    if (namelen <= 1) {
        xfree(name);
        return e;       /* XXX it should only be this? */
    }

    int i, r = 1;
    while (r < namelen) {

        /* Find the child node which matches this */
        for (i = 0; i < e->children && e->leaves[i]->name[r] != name[r]; ++i) ; // seek-loop

        /* Are we pointing to that node? */
        if (i >= e->children)
            break;
        assert(e->leaves[i]->name[r] == name[r]);

        /* Skip to that node! */
        e = e->leaves[i];
        ++r;
    }

    xfree(name);
    return e;
}

bool
snmpCreateOidFromStr(const char *str, oid **name, int *nl)
{
    char const *delim = ".";

    *name = NULL;
    *nl = 0;
    const char *s = str;

    /* Parse the OID string into oid bits */
    while (size_t len = strcspn(s, delim)) {
        *name = (oid*)xrealloc(*name, sizeof(oid) * ((*nl) + 1));
        (*name)[*nl] = atoi(s); // stops at the '.' delimiter
        ++(*nl);
        // exit with true when the last octet has been parsed
        if (s[len] == '\0')
            return true;
        s += len+1;
    }

    // if we aborted before the lst octet was found, return false.
    safe_free(name);
    return false;
}

/*
 * Create an entry. Return a pointer to the newly created node, or NULL
 * on failure.
 */
static mib_tree_entry *
snmpAddNodeStr(const char *base_str, int o, oid_ParseFn * parsefunction, instance_Fn * instancefunction, AggrType aggrType)
{
    mib_tree_entry *m, *b;
    oid *n;
    int nl;
    char s[1024];

    /* Find base node */
    b = snmpLookupNodeStr(mib_tree_head, base_str);
    if (! b)
        return NULL;
    debugs(49, 5, "snmpAddNodeStr: " << base_str << ": -> " << b);

    /* Create OID string for new entry */
    snprintf(s, 1024, "%s.%d", base_str, o);
    if (! snmpCreateOidFromStr(s, &n, &nl))
        return NULL;

    /* Create a node */
    m = snmpAddNode(n, nl, parsefunction, instancefunction, aggrType, 0);

    /* Link it into the existing tree */
    snmpAddNodeChild(b, m);

    /* Return the node */
    return m;
}

/*
 * Adds a node to the MIB tree structure and adds the appropriate children
 */
static mib_tree_entry *
snmpAddNode(oid * name, int len, oid_ParseFn * parsefunction, instance_Fn * instancefunction, AggrType aggrType, int children,...)
{
    va_list args;
    int loop;
    mib_tree_entry *entry = NULL;
    va_start(args, children);

    MemBuf tmp;
    debugs(49, 6, "snmpAddNode: Children : " << children << ", Oid : " << snmpDebugOid(name, len, tmp));

    va_start(args, children);
    entry = (mib_tree_entry *)xmalloc(sizeof(mib_tree_entry));
    entry->name = name;
    entry->len = len;
    entry->parsefunction = parsefunction;
    entry->instancefunction = instancefunction;
    entry->children = children;
    entry->leaves = NULL;
    entry->aggrType = aggrType;

    if (children > 0) {
        entry->leaves = (mib_tree_entry **)xmalloc(sizeof(mib_tree_entry *) * children);

        for (loop = 0; loop < children; ++loop) {
            entry->leaves[loop] = va_arg(args, mib_tree_entry *);
            entry->leaves[loop]->parent = entry;
        }
    }

    va_end(args);
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
        for (loop = 0; loop < length; ++loop) {
            new_oid[loop] = va_arg(args, int);
        }
    }

    va_end(args);
    return (new_oid);
}

/*
 * Debug calls, prints out the OID for debugging purposes.
 */
const char *
snmpDebugOid(oid * Name, snint Len, MemBuf &outbuf)
{
    char mbuf[16];
    int x;
    if (outbuf.isNull())
        outbuf.init(16, MAX_IPSTRLEN);

    for (x = 0; x < Len; ++x) {
        size_t bytes = snprintf(mbuf, sizeof(mbuf), ".%u", (unsigned int) Name[x]);
        outbuf.append(mbuf, bytes);
    }
    return outbuf.content();
}

void
snmpSnmplibDebug(int lvl, char *buf)
{
    debugs(49, lvl, buf);
}

/*
   IPv4 address: 10.10.0.9  ==>
   oid == 10.10.0.9
   IPv6 adress : 20:01:32:ef:a2:21:fb:32:00:00:00:00:00:00:00:00:OO:01 ==>
   oid == 32.1.50.239.162.33.251.20.50.0.0.0.0.0.0.0.0.0.1
*/
void
addr2oid(Ip::Address &addr, oid * Dest)
{
    u_int i ;
    u_char *cp = NULL;
    struct in_addr i4addr;
    struct in6_addr i6addr;
    oid code = addr.isIPv6()? INETADDRESSTYPE_IPV6  : INETADDRESSTYPE_IPV4 ;
    u_int size = (code == INETADDRESSTYPE_IPV4) ? sizeof(struct in_addr):sizeof(struct in6_addr);
    //  Dest[0] = code ;
    if ( code == INETADDRESSTYPE_IPV4 ) {
        addr.getInAddr(i4addr);
        cp = (u_char *) &(i4addr.s_addr);
    } else {
        addr.getInAddr(i6addr);
        cp = (u_char *) &i6addr;
    }
    for ( i=0 ; i < size ; ++i) {
        // OID's are in network order
        Dest[i] = *cp;
        ++cp;
    }
    MemBuf tmp;
    debugs(49, 7, "addr2oid: Dest : " << snmpDebugOid(Dest, size, tmp));
}

/*
   oid == 10.10.0.9 ==>
   IPv4 address: 10.10.0.9
   oid == 32.1.50.239.162.33.251.20.50.0.0.0.0.0.0.0.0.0.1 ==>
   IPv6 adress : 20:01:32:ef:a2:21:fb:32:00:00:00:00:00:00:00:00:OO:01
*/
void
oid2addr(oid * id, Ip::Address &addr, u_int size)
{
    struct in_addr i4addr;
    struct in6_addr i6addr;
    u_int i;
    u_char *cp;
    if ( size == sizeof(struct in_addr) )
        cp = (u_char *) &(i4addr.s_addr);
    else
        cp = (u_char *) &(i6addr);
    MemBuf tmp;
    debugs(49, 7, "oid2addr: id : " << snmpDebugOid(id, size, tmp) );
    for (i=0 ; i<size; ++i) {
        cp[i] = id[i];
    }
    if ( size == sizeof(struct in_addr) )
        addr = i4addr;
    else
        addr = i6addr;
}

/* SNMP checklists */
#include "acl/Strategy.h"
#include "acl/Strategised.h"
#include "acl/StringData.h"

class ACLSNMPCommunityStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    static ACLSNMPCommunityStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g++ warnings about
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
ACLSNMPCommunityStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    return data->match (checklist->snmp_community);
}

ACLSNMPCommunityStrategy *
ACLSNMPCommunityStrategy::Instance()
{
    return &Instance_;
}

ACLSNMPCommunityStrategy ACLSNMPCommunityStrategy::Instance_;
