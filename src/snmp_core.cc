
/*
 * $Id: snmp_core.cc,v 1.75 2006/09/22 02:48:51 hno Exp $
 *
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
#include "ACLChecklist.h"

#define SNMP_REQUEST_SIZE 4096
#define MAX_PROTOSTAT 5

typedef struct _mib_tree_entry mib_tree_entry;
typedef oid *(instance_Fn) (oid * name, snint * len, mib_tree_entry * current, oid_ParseFn ** Fn);

struct _mib_tree_entry
{
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

#if STDC_HEADERS
static mib_tree_entry *snmpAddNode(oid * name, int len, oid_ParseFn * parsefunction, instance_Fn * instancefunction, int children,...);
static oid *snmpCreateOid(int length,...);
#else
static mib_tree_entry *snmpAddNode();
static oid *snmpCreateOid();
#endif
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
    debug(49, 5) ("snmpInit: Called.\n");

    debug(49, 5) ("snmpInit: Building SNMP mib tree structure\n");

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
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 1),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 2),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 3),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 4),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 5),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 6),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 7),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 8),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 9),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 10),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 11),
                                                                                                                                                        LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
																	    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 12),
																			LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0),
																	    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_SYS, 13),
																			LEN_SQ_PRF + 2, snmp_prfSysFn, static_Inst, 0)),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 1, SQ_PRF, PERF_PROTO),
                                                                                                                                            LEN_SQ_PRF + 1, NULL, NULL, 2,
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_PROTO, 1),
                                                                                                                                                        LEN_SQ_PRF + 2, NULL, NULL, 15,
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 1),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 2),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 3),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 4),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 5),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 6),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 7),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 8),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 9),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 10),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 11),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 12),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 13),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 14),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 1, 15),
                                                                                                                                                                    LEN_SQ_PRF + 3, snmp_prfProtoFn, static_Inst, 0)),
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, PERF_PROTO, 2),
                                                                                                                                                        LEN_SQ_PRF + 2, NULL, NULL, 1,
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, PERF_PROTO, 2, 1),
                                                                                                                                                                    LEN_SQ_PRF + 3, NULL, NULL, 11,
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, 2, 1, 1),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, 2, 1, 2),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, 2, 1, 3),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, 2, 1, 4),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, 2, 1, 5),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, 2, 1, 6),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, 2, 1, 7),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, 2, 1, 8),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, 2, 1, 9),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, 2, 1, 10),
                                                                                                                                                                                LEN_SQ_PRF + 4, snmp_prfProtoFn, time_Inst, 0),
                                                                                                                                                                    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, PERF_PROTO, 2, 1, 11),
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
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 1, SQ_MESH, 1),
                                                                                                                                            LEN_SQ_MESH + 1, NULL, NULL, 1,
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 2, SQ_MESH, 1, 1),
                                                                                                                                                        LEN_SQ_MESH + 2, NULL, NULL, 13,
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 1),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 2),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 3),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 4),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 5),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 6),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 7),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 8),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 9),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 10),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 11),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 12),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 13),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshPtblFn, peer_Inst, 0))),
                                                                                                                                snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 1, SQ_MESH, 2),
                                                                                                                                            LEN_SQ_MESH + 1, NULL, NULL, 1,
                                                                                                                                            snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 2, SQ_MESH, 2, 1),
                                                                                                                                                        LEN_SQ_MESH + 2, NULL, NULL, 9,
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 1),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 2),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 3),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 4),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 5),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 6),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 7),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 8),
                                                                                                                                                                    LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0),
                                                                                                                                                        (mib_tree_last = snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 9),
                                                                                                                                                                                     LEN_SQ_MESH + 3, snmp_meshCtblFn, client_Inst, 0)))))
                                                                                                                   )
                                                                                                       )
                                                                                           )
                                                                               )
                                                                   )
                                                       )
                                           )
                               );

    debug(49, 9) ("snmpInit: Completed SNMP mib tree structure\n");
}

void
snmpConnectionOpen(void)
{
    u_short port;

    struct sockaddr_in xaddr;
    socklen_t len;
    int x;

    debug(49, 5) ("snmpConnectionOpen: Called\n");

    if ((port = Config.Port.snmp) > (u_short) 0) {
        enter_suid();
        theInSnmpConnection = comm_open(SOCK_DGRAM,
                                        IPPROTO_UDP,
                                        Config.Addrs.snmp_incoming,
                                        port,
                                        COMM_NONBLOCKING,
                                        "SNMP Port");
        leave_suid();

        if (theInSnmpConnection < 0)
            fatal("Cannot open snmp Port");

        commSetSelect(theInSnmpConnection, COMM_SELECT_READ, snmpHandleUdp, NULL, 0);

        debug(1, 1) ("Accepting SNMP messages on port %d, FD %d.\n",
                     (int) port, theInSnmpConnection);

        if (Config.Addrs.snmp_outgoing.s_addr != no_addr.s_addr) {
            enter_suid();
            theOutSnmpConnection = comm_open(SOCK_DGRAM,
                                             IPPROTO_UDP,
                                             Config.Addrs.snmp_outgoing,
                                             port,
                                             COMM_NONBLOCKING,
                                             "SNMP Port");
            leave_suid();

            if (theOutSnmpConnection < 0)
                fatal("Cannot open Outgoing SNMP Port");

            commSetSelect(theOutSnmpConnection,
                          COMM_SELECT_READ,
                          snmpHandleUdp,
                          NULL, 0);

            debug(1, 1) ("Outgoing SNMP messages on port %d, FD %d.\n",
                         (int) port, theOutSnmpConnection);

            fd_note(theOutSnmpConnection, "Outgoing SNMP socket");

            fd_note(theInSnmpConnection, "Incoming SNMP socket");
        } else {
            theOutSnmpConnection = theInSnmpConnection;
        }

        memset(&theOutSNMPAddr, '\0', sizeof(struct IN_ADDR));

        len = sizeof(struct sockaddr_in);
        memset(&xaddr, '\0', len);
        x = getsockname(theOutSnmpConnection,

                        (struct sockaddr *) &xaddr, &len);

        if (x < 0)
            debug(51, 1) ("theOutSnmpConnection FD %d: getsockname: %s\n",
                          theOutSnmpConnection, xstrerror());
        else
            theOutSNMPAddr = xaddr.sin_addr;
    }
}

void
snmpConnectionShutdown(void)
{
    if (theInSnmpConnection < 0)
        return;

    if (theInSnmpConnection != theOutSnmpConnection) {
        debug(49, 1) ("FD %d Closing SNMP socket\n", theInSnmpConnection);
        comm_close(theInSnmpConnection);
    }

    /*
     * Here we set 'theInSnmpConnection' to -1 even though the SNMP 'in'
     * and 'out' sockets might be just one FD.  This prevents this
     * function from executing repeatedly.  When we are really ready to
     * exit or restart, main will comm_close the 'out' descriptor.
     */ theInSnmpConnection = -1;

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
        debug(49, 1) ("FD %d Closing SNMP socket\n", theOutSnmpConnection);
        comm_close(theOutSnmpConnection);
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

    struct sockaddr_in from;
    socklen_t from_len;
    snmp_request_t *snmp_rq;
    int len;

    debug(49, 5) ("snmpHandleUdp: Called.\n");

    commSetSelect(sock, COMM_SELECT_READ, snmpHandleUdp, NULL, 0);

    from_len = sizeof(struct sockaddr_in);
    memset(&from, '\0', from_len);
    memset(buf, '\0', SNMP_REQUEST_SIZE);

    len = comm_udp_recvfrom(sock,
                            buf,
                            SNMP_REQUEST_SIZE,
                            0,

                            (struct sockaddr *) &from,
                            &from_len);

    if (len > 0) {
        buf[len] = '\0';
        debug(49, 3) ("snmpHandleUdp: FD %d: received %d bytes from %s.\n",
                      sock,
                      len,
                      inet_ntoa(from.sin_addr));

        snmp_rq = (snmp_request_t *)xcalloc(1, sizeof(snmp_request_t));
        snmp_rq->buf = (u_char *) buf;
        snmp_rq->len = len;
        snmp_rq->sock = sock;
        snmp_rq->outbuf = (unsigned char *)xmalloc(snmp_rq->outlen = SNMP_REQUEST_SIZE);

        xmemcpy(&snmp_rq->from, &from, sizeof(struct sockaddr_in));
        snmpDecodePacket(snmp_rq);
        xfree(snmp_rq->outbuf);
        xfree(snmp_rq);
    } else {
        debug(49, 1) ("snmpHandleUdp: FD %d recvfrom: %s\n", sock, xstrerror());
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

    debug(49, 5) ("snmpDecodePacket: Called.\n");
    /* Now that we have the data, turn it into a PDU */
    PDU = snmp_pdu_create(0);
    rq->session.Version = SNMP_VERSION_1;
    Community = snmp_parse(&rq->session, PDU, buf, len);

    if (Community) {
        ACLChecklist checklist;
        checklist.accessList = cbdataReference(Config.accessList.snmp);
        checklist.src_addr = rq->from.sin_addr;
        checklist.snmp_community = (char *) Community;
        /* cbdataReferenceDone() happens in either fastCheck() or ~ACLCheckList */
        allow = checklist.fastCheck();
    }

    if ((snmp_coexist_V2toV1(PDU)) && (Community) && (allow)) {
        rq->community = Community;
        rq->PDU = PDU;
        debug(49, 5) ("snmpAgentParse: reqid=[%d]\n", PDU->reqid);
        snmpConstructReponse(rq);
    } else {
        debug(49, 1) ("Failed SNMP agent query from : %s.\n",
                      inet_ntoa(rq->from.sin_addr));
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

    debug(49, 5) ("snmpConstructReponse: Called.\n");
    RespPDU = snmpAgentResponse(rq->PDU);
    snmp_free_pdu(rq->PDU);

    if (RespPDU != NULL) {
        snmp_build(&rq->session, RespPDU, rq->outbuf, &rq->outlen);
        comm_udp_sendto(rq->sock, &rq->from, sizeof(rq->from), rq->outbuf, rq->outlen);
        snmp_free_pdu(RespPDU);
    }
}

/*
 * Decide how to respond to the request, construct a response and
 * return the response to the requester.
 */

static struct snmp_pdu *

            snmpAgentResponse(struct snmp_pdu *PDU)
{

    struct snmp_pdu *Answer = NULL;

    debug(49, 5) ("snmpAgentResponse: Called.\n");

    if ((Answer = snmp_pdu_create(SNMP_PDU_RESPONSE)))
    {
        Answer->reqid = PDU->reqid;
        Answer->errindex = 0;

        if (PDU->command == SNMP_PDU_GET || PDU->command == SNMP_PDU_GETNEXT) {
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

                /* Find the parsing function for this variable */

                if (get_next)
                    ParseFn = snmpTreeNext(VarPtr->name, VarPtr->name_length, &NextOidName, &NextOidNameLen);
                else
                    ParseFn = snmpTreeGet(VarPtr->name, VarPtr->name_length);

                if (ParseFn == NULL) {
                    Answer->errstat = SNMP_ERR_NOSUCHNAME;
                    debug(49, 5) ("snmpAgentResponse: No such oid. ");
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

                /* Was there an error? */
                if ((Answer->errstat != SNMP_ERR_NOERROR) || (VarNew == NULL)) {
                    Answer->errindex = index;
                    debug(49, 5) ("snmpAgentResponse: error.\n");

                    if (VarNew)
                        snmp_var_free(VarNew);

                    /* Free the already processed results, if any */
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

    debug(49, 5) ("snmpTreeGet: Called\n");

    debug(49, 6) ("snmpTreeGet: Current : \n");
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

    debug(49, 5) ("snmpTreeGet: return\n");

    return (Fn);
}

static oid_ParseFn *
snmpTreeNext(oid * Current, snint CurrentLen, oid ** Next, snint * NextLen)
{
    oid_ParseFn *Fn = NULL;
    mib_tree_entry *mibTreeEntry = NULL, *nextoid = NULL;
    int count = 0;

    debug(49, 5) ("snmpTreeNext: Called\n");

    debug(49, 6) ("snmpTreeNext: Current : \n");
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

        debug(49, 5) ("snmpTreeNext: Recursed down to requested object\n");
    } else {
        return NULL;
    }

    if (mibTreeEntry == mib_tree_last)
        return (Fn);

    if ((mibTreeEntry) && (mibTreeEntry->parsefunction)) {
        *NextLen = CurrentLen;
        *Next = (*mibTreeEntry->instancefunction) (Current, NextLen, mibTreeEntry, &Fn);

        if (*Next)
            return (Fn);
    }

    if ((mibTreeEntry) && (mibTreeEntry->parsefunction)) {
        count--;
        nextoid = snmpTreeSiblingEntry(Current[count], count, mibTreeEntry->parent);

        if (nextoid) {
            debug(49, 5) ("snmpTreeNext: Next OID found for sibling\n");
            mibTreeEntry = nextoid;
            count++;
        } else {
            debug(49, 5) ("snmpTreeNext: Attempting to recurse up for next object\n");

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

    if (*Next)
        return (Fn);
    else
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
    int index[TIME_INDEX_LEN] =
        {TIME_INDEX};

    if (*len <= current->len) {
        instance = (oid *)xmalloc(sizeof(name) * (*len + 1));
        xmemcpy(instance, name, (sizeof(name) * *len));
        instance[*len] = *index;
        *len += 1;
    } else {
        identifier = name[*len - 1];

        while ((identifier != index[loop]) && (loop < TIME_INDEX_LEN))
            loop++;

        if (loop < TIME_INDEX_LEN - 1) {
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
    u_char *cp = NULL;
    peer *peers = Config.peers;

    struct IN_ADDR *laddr = NULL;
    char *host_addr = NULL, *current_addr = NULL, *last_addr = NULL;

    if (peers == NULL) {
        current = current->parent->parent->parent->leaves[1];

        while ((current) && (!current->parsefunction))
            current = current->leaves[0];

        instance = client_Inst(current->name, len, current, Fn);
    } else if (*len <= current->len) {
        instance = (oid *)xmalloc(sizeof(name) * (*len + 4));
        xmemcpy(instance, name, (sizeof(name) * *len));
        cp = (u_char *) & (peers->in_addr.sin_addr.s_addr);
        instance[*len] = *cp++;
        instance[*len + 1] = *cp++;
        instance[*len + 2] = *cp++;
        instance[*len + 3] = *cp++;
        *len += 4;
    } else {
        laddr = oid2addr(&name[*len - 4]);
        host_addr = inet_ntoa(*laddr);
        last_addr = (char *)xmalloc(strlen(host_addr));
        strncpy(last_addr, host_addr, strlen(host_addr));
        current_addr = inet_ntoa(peers->in_addr.sin_addr);

        while ((peers) && (strncmp(last_addr, current_addr, strlen(current_addr)))) {
            if (peers->next) {
                peers = peers->next;
                current_addr = inet_ntoa(peers->in_addr.sin_addr);
            } else {
                peers = NULL;
            }
        }

        xfree(last_addr);

        if (peers) {
            if (peers->next) {
                peers = peers->next;
                instance = (oid *)xmalloc(sizeof(name) * (*len));
                xmemcpy(instance, name, (sizeof(name) * *len));
                cp = (u_char *) & (peers->in_addr.sin_addr.s_addr);
                instance[*len - 4] = *cp++;
                instance[*len - 3] = *cp++;
                instance[*len - 2] = *cp++;
                instance[*len - 1] = *cp++;
            } else {
                return (instance);
            }
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
    u_char *cp = NULL;

    struct IN_ADDR *laddr = NULL;

    if (*len <= current->len) {
        instance = (oid *)xmalloc(sizeof(name) * (*len + 4));
        xmemcpy(instance, name, (sizeof(name) * *len));
        laddr = client_entry(NULL);

        if (laddr) {
            cp = (u_char *) & (laddr->s_addr);
            instance[*len] = *cp++;
            instance[*len + 1] = *cp++;
            instance[*len + 2] = *cp++;
            instance[*len + 3] = *cp++;
            *len += 4;
        }
    } else {
        laddr = oid2addr(&name[*len - 4]);
        laddr = client_entry(laddr);

        if (laddr) {
            instance = (oid *)xmalloc(sizeof(name) * (*len));
            xmemcpy(instance, name, (sizeof(name) * *len));
            cp = (u_char *) & (laddr->s_addr);
            instance[*len - 4] = *cp++;
            instance[*len - 3] = *cp++;
            instance[*len - 2] = *cp++;
            instance[*len - 1] = *cp++;
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
 * Returns a the sibling object in the tree
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
#if STDC_HEADERS
snmpAddNode(oid * name, int len, oid_ParseFn * parsefunction, instance_Fn * instancefunction, int children,...)
#else
snmpAddNode(va_alist)
va_dcl
#endif
{
#if STDC_HEADERS
    va_list args;
    int loop;
    mib_tree_entry *entry = NULL;
    va_start(args, children);
#else

    va_list args;
    oid *name = NULL;
    int len = 0, children = 0, loop;
    oid_ParseFn *parsefunction = NULL;
    instance_Fn *instancefunction = NULL;
    mib_tree_entry *entry = NULL;
    va_start(args);
    name = va_arg(args, oid *);
    len = va_arg(args, int);
    parsefunction = va_arg(args, oid_ParseFn *);
    instancefunction = va_arg(args, instance_Fn *);
    children = va_arg(args, int);
#endif

    debug(49, 6) ("snmpAddNode: Children : %d, Oid : \n", children);
    snmpDebugOid(6, name, len);

    va_start(args, children);
    entry = (mib_tree_entry *)xmalloc(sizeof(mib_tree_entry));
    entry->name = name;
    entry->len = len;
    entry->parsefunction = parsefunction;
    entry->instancefunction = instancefunction;
    entry->children = children;

    if (children > 0)
    {
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
#if STDC_HEADERS
snmpCreateOid(int length,...)
#else
snmpCreateOid(va_alist)
va_dcl
#endif
{
#if STDC_HEADERS
    va_list args;
    oid *new_oid;
    int loop;
    va_start(args, length);
#else

    va_list args;
    int length = 0, loop;
    oid *new_oid;
    va_start(args);
    length va_arg(args, int);
#endif

    new_oid = (oid *)xmalloc(sizeof(oid) * length);

    if (length > 0)
    {
        for (loop = 0; loop < length; loop++) {
            new_oid[loop] = va_arg(args, int);
        }
    }

    return (new_oid);
}

#if UNUSED_CODE
/*
 * Allocate space for, and copy, an OID.  Returns new oid.
 */
static oid *
snmpOidDup(oid * A, snint ALen)
{
    oid *Ans = xmalloc(sizeof(oid) * ALen);
    xmemcpy(Ans, A, (sizeof(oid) * ALen));
    return Ans;
}

#endif

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
        strncat(objid, mbuf, sizeof(objid));
    }

    debug(49, lvl) ("   oid = %s\n", objid);
}

static void
snmpSnmplibDebug(int lvl, char *buf)
{
    debug(49, lvl) ("%s", buf);
}

void

addr2oid(struct IN_ADDR addr, oid * Dest)
{
    u_char *cp;
    cp = (u_char *) & (addr.s_addr);
    Dest[0] = *cp++;
    Dest[1] = *cp++;
    Dest[2] = *cp++;
    Dest[3] = *cp++;
}

struct IN_ADDR
            *
            oid2addr(oid * id)
{

    static struct IN_ADDR laddr;
    u_char *cp = (u_char *) & (laddr.s_addr);
    cp[0] = id[0];
    cp[1] = id[1];
    cp[2] = id[2];
    cp[3] = id[3];
    return &laddr;
}

/* SNMP checklists */
#include "ACLStrategy.h"
#include "ACLStrategised.h"
#include "ACLStringData.h"

class ACLSNMPCommunityStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLChecklist *);
    static ACLSNMPCommunityStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLSNMPCommunityStrategy(ACLSNMPCommunityStrategy const &);

private:
    static ACLSNMPCommunityStrategy Instance_;
    ACLSNMPCommunityStrategy(){}

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
ACLSNMPCommunityStrategy::match (ACLData<MatchType> * &data, ACLChecklist *checklist)
{
    return data->match (checklist->snmp_community);
}

ACLSNMPCommunityStrategy *
ACLSNMPCommunityStrategy::Instance()
{
    return &Instance_;
}

ACLSNMPCommunityStrategy ACLSNMPCommunityStrategy::Instance_;
