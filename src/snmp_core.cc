/*
 * $Id: snmp_core.cc,v 1.29 1999/01/19 02:24:30 wessels Exp $
 *
 * DEBUG: section 49    SNMP support
 * AUTHOR: Glenn Chisholm
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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
#include "cache_snmp.h"

#define SNMP_REQUEST_SIZE 4096
#define MAX_PROTOSTAT 5

struct _mib_tree_entry {
    oid *name;
    int len;
    oid_ParseFn *parsefunction;
    int children;
    struct _mib_tree_entry **leaves;
    struct _mib_tree_entry *parent;
};

typedef struct _mib_tree_entry mib_tree_entry;

mib_tree_entry *mib_tree_head;

#if STDC_HEADERS
static mib_tree_entry *snmpAddNode(oid * name, int len, oid_ParseFn * parsefunction, int children,...);
static oid *snmpCreateOid(int length,...);
#else
static mib_tree_entry *snmpAddNode();
static oid *snmpCreateOid();
#endif
extern void (*snmplib_debug_hook) (int, char *);
static void snmpDecodePacket(snmp_request_t * rq);
static void snmpConstructReponse(snmp_request_t * rq);
static struct snmp_pdu *snmpAgentResponse(struct snmp_pdu *PDU);
static oid_ParseFn *snmpTreeNext(oid * Current, snint CurrentLen, oid ** Next, snint * NextLen);
static oid_ParseFn *snmpTreeGet(oid * Current, snint CurrentLen);
static mib_tree_entry *snmpTreeEntry(oid entry, snint len, mib_tree_entry * current);
static mib_tree_entry *snmpTreeSiblingEntry(oid entry, snint len, mib_tree_entry * current);
static oid *snmpOidDup(oid * A, snint ALen);
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
	1, NULL, 1,
	snmpAddNode(snmpCreateOid(2, 1, 3),
	    2, NULL, 1,
	    snmpAddNode(snmpCreateOid(3, 1, 3, 6),
		3, NULL, 1,
		snmpAddNode(snmpCreateOid(4, 1, 3, 6, 1),
		    4, NULL, 1,
		    snmpAddNode(snmpCreateOid(5, 1, 3, 6, 1, 4),
			5, NULL, 1,
			snmpAddNode(snmpCreateOid(6, 1, 3, 6, 1, 4, 1),
			    6, NULL, 1,
			    snmpAddNode(snmpCreateOid(7, 1, 3, 6, 1, 4, 1, 3495),
				7, NULL, 1,
				snmpAddNode(snmpCreateOid(LEN_SQUIDMIB, SQUIDMIB),
				    8, NULL, 5,
				    snmpAddNode(snmpCreateOid(LEN_SQ_SYS, SQ_SYS),
					LEN_SQ_SYS, NULL, 3,
					snmpAddNode(snmpCreateOid(LEN_SQ_SYS + 1, SQ_SYS, 1),
					    LEN_SQ_SYS + 1, snmp_sysFn, 1,
					    snmpAddNode(snmpCreateOid(LEN_SQ_SYS + 2, SQ_SYS, 1, 0),
						LEN_SQ_SYS + 2, snmp_sysFn, 0)),
					snmpAddNode(snmpCreateOid(LEN_SQ_SYS + 1, SQ_SYS, 2),
					    LEN_SQ_SYS + 1, snmp_sysFn, 1,
					    snmpAddNode(snmpCreateOid(LEN_SQ_SYS + 2, SQ_SYS, 2, 0),
						LEN_SQ_SYS + 2, snmp_sysFn, 0)),
					snmpAddNode(snmpCreateOid(LEN_SQ_SYS + 1, SQ_SYS, 3),
					    LEN_SQ_SYS + 1, snmp_sysFn, 1,
					    snmpAddNode(snmpCreateOid(LEN_SQ_SYS + 2, SQ_SYS, 3, 0),
						LEN_SQ_SYS + 2, snmp_sysFn, 0))),
				    snmpAddNode(snmpCreateOid(LEN_SQ_CONF, SQ_CONF),
					LEN_SQ_CONF, NULL, 5,
					snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 1, SQ_CONF, 1),
					    LEN_SQ_CONF + 1, snmp_confFn, 1,
					    snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 2, SQ_CONF, 1, 0),
						LEN_SQ_CONF + 2, snmp_confFn, 0)),
					snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 1, SQ_CONF, 2),
					    LEN_SQ_CONF + 1, snmp_confFn, 1,
					    snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 2, SQ_CONF, 2, 0),
						LEN_SQ_CONF + 2, snmp_confFn, 0)),
					snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 1, SQ_CONF, 3),
					    LEN_SQ_CONF + 1, snmp_confFn, 1,
					    snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 2, SQ_CONF, 3, 0),
						LEN_SQ_CONF + 2, snmp_confFn, 0)),
					snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 1, SQ_CONF, 4),
					    LEN_SQ_CONF + 1, snmp_confFn, 1,
					    snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 2, SQ_CONF, 4, 0),
						LEN_SQ_CONF + 2, snmp_confFn, 0)),
					snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 1, SQ_CONF, 5),
					    LEN_SQ_CONF + 1, NULL, 6,
					    snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 2, SQ_CONF, 5, 1),
						LEN_SQ_CONF + 2, snmp_confFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 3, SQ_CONF, 5, 1, 0),
						    LEN_SQ_CONF + 3, snmp_confFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 2, SQ_CONF, 5, 2),
						LEN_SQ_CONF + 2, snmp_confFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 3, SQ_CONF, 5, 2, 0),
						    LEN_SQ_CONF + 3, snmp_confFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 2, SQ_CONF, 5, 3),
						LEN_SQ_CONF + 2, snmp_confFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 3, SQ_CONF, 5, 3, 0),
						    LEN_SQ_CONF + 3, snmp_confFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 2, SQ_CONF, 5, 4),
						LEN_SQ_CONF + 2, snmp_confFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 3, SQ_CONF, 5, 4, 0),
						    LEN_SQ_CONF + 3, snmp_confFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 2, SQ_CONF, 5, 5),
						LEN_SQ_CONF + 2, snmp_confFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 3, SQ_CONF, 5, 5, 0),
						    LEN_SQ_CONF + 3, snmp_confFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 2, SQ_CONF, 5, 6),
						LEN_SQ_CONF + 2, snmp_confFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_CONF + 3, SQ_CONF, 5, 6, 0),
						    LEN_SQ_CONF + 3, snmp_confFn, 0)))),
				    snmpAddNode(snmpCreateOid(LEN_SQ_PRF, SQ_PRF),
					LEN_SQ_PRF, NULL, 2,
					snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 1, SQ_PRF, 1),
					    LEN_SQ_PRF + 1, NULL, 11,
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 1, 1),
						LEN_SQ_PRF + 2, snmp_prfSysFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 1, 1, 0),
						    LEN_SQ_PRF + 3, snmp_prfSysFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 1, 2),
						LEN_SQ_PRF + 2, snmp_prfSysFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 1, 2, 0),
						    LEN_SQ_PRF + 3, snmp_prfSysFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 1, 3),
						LEN_SQ_PRF + 2, snmp_prfSysFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 1, 3, 0),
						    LEN_SQ_PRF + 3, snmp_prfSysFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 1, 4),
						LEN_SQ_PRF + 2, snmp_prfSysFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 1, 4, 0),
						    LEN_SQ_PRF + 3, snmp_prfSysFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 1, 5),
						LEN_SQ_PRF + 2, snmp_prfSysFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 1, 5, 0),
						    LEN_SQ_PRF + 3, snmp_prfSysFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 1, 6),
						LEN_SQ_PRF + 2, snmp_prfSysFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 1, 6, 0),
						    LEN_SQ_PRF + 3, snmp_prfSysFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 1, 7),
						LEN_SQ_PRF + 2, snmp_prfSysFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 1, 7, 0),
						    LEN_SQ_PRF + 3, snmp_prfSysFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 1, 8),
						LEN_SQ_PRF + 2, snmp_prfSysFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 1, 8, 0),
						    LEN_SQ_PRF + 3, snmp_prfSysFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 1, 9),
						LEN_SQ_PRF + 2, snmp_prfSysFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 1, 9, 0),
						    LEN_SQ_PRF + 3, snmp_prfSysFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 1, 10),
						LEN_SQ_PRF + 2, snmp_prfSysFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 1, 10, 0),
						    LEN_SQ_PRF + 3, snmp_prfSysFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 1, 11),
						LEN_SQ_PRF + 2, snmp_prfSysFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 1, 11, 0),
						    LEN_SQ_PRF + 3, snmp_prfSysFn, 0))),
					snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 1, SQ_PRF, 2),
					    LEN_SQ_PRF + 1, NULL, 2,
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 2, 1),
						LEN_SQ_PRF + 2, NULL, 15,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 1),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 1, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 2),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 2, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 3),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 3, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 4),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 4, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 5),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 5, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 6),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 6, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 7),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 7, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 8),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 8, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 9),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 9, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 10),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 10, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 11),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 11, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 12),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 12, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 13),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 13, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 14),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 14, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0)),
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 1, 15),
						    LEN_SQ_PRF + 3, snmp_prfProtoFn, 1,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 1, 15, 0),
							LEN_SQ_PRF + 4, snmp_prfProtoFn, 0))),
					    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 2, SQ_PRF, 2, 2),
						LEN_SQ_PRF + 2, NULL, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 3, SQ_PRF, 2, 2, 1),
						    LEN_SQ_PRF + 3, NULL, 10,
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 2, 1, 1),
							LEN_SQ_PRF + 4, NULL, 3,
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 1, 1),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 1, 5),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 1, 60),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0)),
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 2, 1, 2),
							LEN_SQ_PRF + 4, NULL, 3,
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 2, 1),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 2, 5),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 2, 60),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0)),
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 2, 1, 3),
							LEN_SQ_PRF + 4, NULL, 3,
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 3, 1),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 3, 5),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 3, 60),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0)),
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 2, 1, 4),
							LEN_SQ_PRF + 4, NULL, 3,
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 4, 1),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 4, 5),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 4, 60),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0)),
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 2, 1, 5),
							LEN_SQ_PRF + 4, NULL, 3,
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 5, 1),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 5, 5),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 5, 60),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0)),
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 2, 1, 6),
							LEN_SQ_PRF + 4, NULL, 3,
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 6, 1),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 6, 5),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 6, 60),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0)),
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 2, 1, 7),
							LEN_SQ_PRF + 4, NULL, 3,
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 7, 1),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 7, 5),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 7, 60),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0)),
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 2, 1, 8),
							LEN_SQ_PRF + 4, NULL, 3,
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 8, 1),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 8, 5),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 8, 60),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0)),
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 2, 1, 9),
							LEN_SQ_PRF + 4, NULL, 3,
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 9, 1),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 9, 5),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 9, 60),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0)),
						    snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 4, SQ_PRF, 2, 2, 1, 10),
							LEN_SQ_PRF + 4, NULL, 3,
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 10, 1),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 10, 5),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0),
							snmpAddNode(snmpCreateOid(LEN_SQ_PRF + 5, SQ_PRF, 2, 2, 1, 10, 60),
							    LEN_SQ_PRF + 5, snmp_prfProtoFn, 0)))))),
				    snmpAddNode(snmpCreateOid(LEN_SQ_NET, SQ_NET),
					LEN_SQ_NET, NULL, 3,
					snmpAddNode(snmpCreateOid(LEN_SQ_NET + 1, SQ_NET, 1),
					    LEN_SQ_NET + 1, NULL, 8,
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 1, 1),
						LEN_SQ_NET + 2, snmp_netIpFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 1, 1, 0),
						    LEN_SQ_NET + 3, snmp_netIpFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 1, 2),
						LEN_SQ_NET + 2, snmp_netIpFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 1, 2, 0),
						    LEN_SQ_NET + 3, snmp_netIpFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 1, 3),
						LEN_SQ_NET + 2, snmp_netIpFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 1, 3, 0),
						    LEN_SQ_NET + 3, snmp_netIpFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 1, 4),
						LEN_SQ_NET + 2, snmp_netIpFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 1, 4, 0),
						    LEN_SQ_NET + 3, snmp_netIpFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 1, 5),
						LEN_SQ_NET + 2, snmp_netIpFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 1, 5, 0),
						    LEN_SQ_NET + 3, snmp_netIpFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 1, 6),
						LEN_SQ_NET + 2, snmp_netIpFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 1, 6, 0),
						    LEN_SQ_NET + 3, snmp_netIpFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 1, 7),
						LEN_SQ_NET + 2, snmp_netIpFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 1, 7, 0),
						    LEN_SQ_NET + 3, snmp_netIpFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 1, 8),
						LEN_SQ_NET + 2, snmp_netIpFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 1, 8, 0),
						    LEN_SQ_NET + 3, snmp_netIpFn, 0))),
					snmpAddNode(snmpCreateOid(LEN_SQ_NET + 1, SQ_NET, 2),
					    LEN_SQ_NET + 1, NULL, 7,
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 2, 1),
						LEN_SQ_NET + 2, snmp_netFqdnFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 2, 1, 0),
						    LEN_SQ_NET + 3, snmp_netFqdnFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 2, 2),
						LEN_SQ_NET + 2, snmp_netFqdnFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 2, 2, 0),
						    LEN_SQ_NET + 3, snmp_netFqdnFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 2, 3),
						LEN_SQ_NET + 2, snmp_netFqdnFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 2, 3, 0),
						    LEN_SQ_NET + 3, snmp_netFqdnFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 2, 4),
						LEN_SQ_NET + 2, snmp_netFqdnFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 2, 4, 0),
						    LEN_SQ_NET + 3, snmp_netFqdnFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 2, 5),
						LEN_SQ_NET + 2, snmp_netFqdnFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 2, 5, 0),
						    LEN_SQ_NET + 3, snmp_netFqdnFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 2, 6),
						LEN_SQ_NET + 2, snmp_netFqdnFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 2, 6, 0),
						    LEN_SQ_NET + 3, snmp_netFqdnFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 2, 7),
						LEN_SQ_NET + 2, snmp_netFqdnFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 2, 7, 0),
						    LEN_SQ_NET + 3, snmp_netFqdnFn, 0))),
					snmpAddNode(snmpCreateOid(LEN_SQ_NET + 1, SQ_NET, 3),
					    LEN_SQ_NET + 1, NULL, 3,
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 3, 1),
						LEN_SQ_NET + 2, snmp_netDnsFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 3, 1, 0),
						    LEN_SQ_NET + 3, snmp_netDnsFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 3, 2),
						LEN_SQ_NET + 2, snmp_netDnsFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 3, 2, 0),
						    LEN_SQ_NET + 3, snmp_netDnsFn, 0)),
					    snmpAddNode(snmpCreateOid(LEN_SQ_NET + 2, SQ_NET, 3, 3),
						LEN_SQ_NET + 2, snmp_netDnsFn, 1,
						snmpAddNode(snmpCreateOid(LEN_SQ_NET + 3, SQ_NET, 3, 3, 0),
						    LEN_SQ_NET + 3, snmp_netDnsFn, 0)))),
				    snmpAddNode(snmpCreateOid(LEN_SQ_MESH, SQ_MESH),
					LEN_SQ_MESH, NULL, 2,
					snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 1, SQ_MESH, 1),
					    LEN_SQ_MESH + 1, NULL, 1,
					    snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 2, SQ_MESH, 1, 1),
						LEN_SQ_MESH + 2, NULL, 13,
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 1),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 2),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 3),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 4),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 5),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 6),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 7),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 8),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 9),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 10),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 11),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 12),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 1, 1, 13),
						    LEN_SQ_MESH + 3, snmp_meshPtblFn, 0))),
					snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 1, SQ_MESH, 2),
					    LEN_SQ_MESH + 1, NULL, 1,
					    snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 2, SQ_MESH, 2, 1),
						LEN_SQ_MESH + 2, NULL, 9,
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 1),
						    LEN_SQ_MESH + 3, snmp_meshCtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 2),
						    LEN_SQ_MESH + 3, snmp_meshCtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 3),
						    LEN_SQ_MESH + 3, snmp_meshCtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 4),
						    LEN_SQ_MESH + 3, snmp_meshCtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 5),
						    LEN_SQ_MESH + 3, snmp_meshCtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 6),
						    LEN_SQ_MESH + 3, snmp_meshCtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 7),
						    LEN_SQ_MESH + 3, snmp_meshCtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 8),
						    LEN_SQ_MESH + 3, snmp_meshCtblFn, 0),
						snmpAddNode(snmpCreateOid(LEN_SQ_MESH + 3, SQ_MESH, 2, 1, 9),
						    LEN_SQ_MESH + 3, snmp_meshCtblFn, 0))))
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
	    0,
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
		0,
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
	memset(&theOutSNMPAddr, '\0', sizeof(struct in_addr));
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

    Counter.syscalls.sock.recvfroms++;

    len = recvfrom(sock,
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

	snmp_rq = xcalloc(1, sizeof(snmp_request_t));
	snmp_rq->buf = (u_char *) buf;
	snmp_rq->len = len;
	snmp_rq->sock = sock;
	snmp_rq->outbuf = xmalloc(snmp_rq->outlen = SNMP_REQUEST_SIZE);
	xmemcpy(&snmp_rq->from, &from, sizeof(struct sockaddr_in));
	snmpDecodePacket(snmp_rq);
	xfree(snmp_rq);
    } else {
	debug(49, 1) ("snmpHandleUdp: FD %d recvfrom: %s\n", sock, xstrerror());
    }
}

/*
 * Turn SNMP packet into a PDU, check available ACL's
 */
void
snmpDecodePacket(snmp_request_t * rq)
{
    struct snmp_pdu *PDU;
    struct snmp_session Session;
    aclCheck_t checklist;
    u_char *Community;
    u_char *buf = rq->buf;
    int len = rq->len;
    int allow = 0;

    debug(49, 5) ("snmpDecodePacket: Called.\n");
    /* Now that we have the data, turn it into a PDU */
    PDU = snmp_pdu_create(0);
    Session.Version = SNMP_VERSION_1;
    Community = snmp_parse(&Session, PDU, buf, len);

    checklist.src_addr = rq->from.sin_addr;
    checklist.snmp_community = (char *) Community;

    allow = aclCheckFast(Config.accessList.snmp, &checklist);
    if ((snmp_coexist_V2toV1(PDU)) && (Community) && (allow)) {
	rq->community = Community;
	rq->PDU = PDU;
	debug(49, 5) ("snmpAgentParse: reqid=[%d]\n", PDU->reqid);
	snmpConstructReponse(rq);
    } else {
	snmp_free_pdu(PDU);
    }
}

/*
 * Packet OK, ACL Check OK, Create reponse.
 */
void
snmpConstructReponse(snmp_request_t * rq)
{
    struct snmp_session Session;
    struct snmp_pdu *RespPDU;
    int ret;

    debug(49, 5) ("snmpConstructReponse: Called.\n");
    RespPDU = snmpAgentResponse(rq->PDU);
    snmp_free_pdu(rq->PDU);
    if (RespPDU != NULL) {
	Session.Version = SNMP_VERSION_1;
	Session.community = rq->community;
	Session.community_len = strlen((char *) rq->community);
	ret = snmp_build(&Session, RespPDU, rq->outbuf, &rq->outlen);
	sendto(rq->sock, rq->outbuf, rq->outlen, 0, (struct sockaddr *) &rq->from, sizeof(rq->from));
	snmp_free_pdu(RespPDU);
	xfree(rq->outbuf);
    }
}

/*
 * Decide how to respond to the request, construct a response and
 * return the response to the requester.
 * 
 * If configured forward any reponses which are not for this agent.
 */
struct snmp_pdu *
snmpAgentResponse(struct snmp_pdu *PDU)
{
    struct snmp_pdu *Answer = NULL;
    oid_ParseFn *ParseFn = NULL;

    variable_list *VarPtr, *VarNew = NULL, **VarPtrP;
    int index = 0;

    debug(49, 5) ("snmpAgentResponse: Called.\n");

    if ((Answer = snmp_pdu_create(SNMP_PDU_RESPONSE))) {
	Answer->reqid = PDU->reqid;
	Answer->errindex = 0;
	if (PDU->command == SNMP_PDU_GET) {
	    variable_list **RespVars;

	    RespVars = &(Answer->variables);
	    /* Loop through all variables */
	    for (VarPtrP = &(PDU->variables);
		*VarPtrP;
		VarPtrP = &((*VarPtrP)->next_variable)) {
		VarPtr = *VarPtrP;

		index++;

		/* Find the parsing function for this variable */
		ParseFn = snmpTreeGet(VarPtr->name, VarPtr->name_length);

		if (ParseFn == NULL) {
		    Answer->errstat = SNMP_ERR_NOSUCHNAME;
		    debug(49, 5) ("snmpAgentResponse: No such oid. ");
		} else
		    VarNew = (*ParseFn) (VarPtr, (snint *) & (Answer->errstat));

		/* Was there an error? */
		if ((Answer->errstat != SNMP_ERR_NOERROR) ||
		    (VarNew == NULL)) {
		    Answer->errindex = index;
		    debug(49, 5) ("snmpAgentParse: successful.\n");
		    /* Just copy the rest of the variables.  Quickly. */
		    *RespVars = VarPtr;
		    *VarPtrP = NULL;
		    return (Answer);
		}
		/* No error.  Insert this var at the end, and move on to the next.
		 */
		*RespVars = VarNew;
		RespVars = &(VarNew->next_variable);
	    }
	    return (Answer);
	} else if (PDU->command == SNMP_PDU_GETNEXT) {
	    oid *NextOidName = NULL;
	    int NextOidNameLen = 0;

	    ParseFn = snmpTreeNext(PDU->variables->name, PDU->variables->name_length,
		&(NextOidName), (snint *) & NextOidNameLen);

	    if (ParseFn == NULL) {
		Answer->errstat = SNMP_ERR_NOSUCHNAME;
		debug(49, 5) ("snmpAgentResponse: No such oid: ");
		snmpDebugOid(5, PDU->variables->name, PDU->variables->name_length);
	    } else {
		xfree(PDU->variables->name);
		PDU->variables->name = NextOidName;
		PDU->variables->name_length = NextOidNameLen;
		VarNew = (*ParseFn) (PDU->variables, (snint *) & Answer->errstat);
	    }

	    /* Was there an error? */
	    if (Answer->errstat != SNMP_ERR_NOERROR) {
		Answer->errindex = 1;
		Answer->variables = PDU->variables;
		PDU->variables = NULL;
	    } else {
		Answer->variables = VarNew;
	    }

	} else {
	    snmp_free_pdu(Answer);
	    Answer = NULL;
	}
    }
    return (Answer);
}

oid_ParseFn *
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
	while ((mibTreeEntry) && (count < CurrentLen)) {
	    mibTreeEntry = snmpTreeEntry(Current[count], count, mibTreeEntry);
	    count++;
	}
    }
    if (mibTreeEntry) {
	Fn = mibTreeEntry->parsefunction;
    }
    debug(49, 5) ("snmpTreeGet: return\n");
    return (Fn);
}

oid_ParseFn *
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
	while ((mibTreeEntry) && (count < CurrentLen)) {
	    mibTreeEntry = snmpTreeEntry(Current[count], count, mibTreeEntry);
	    count++;
	}
	debug(49, 5) ("snmpTreeNext: Recursed down to requested object\n");

	if ((mibTreeEntry) && (mibTreeEntry->parsefunction)) {
	    count--;
	    nextoid = snmpTreeSiblingEntry(Current[count], count, mibTreeEntry->parent);
	    if (nextoid) {
		mibTreeEntry = nextoid;
		count++;
	    } else {
		debug(49, 5) ("snmpTreeNext: Attempting to recurse up for next object\n");
		while (!nextoid) {
		    count--;
		    nextoid = mibTreeEntry->parent;
		    mibTreeEntry = snmpTreeEntry(Current[count] + 1, count, nextoid->parent);
		    if (!mibTreeEntry) {
			mibTreeEntry = nextoid;
			nextoid = NULL;
		    }
		}
	    }
	}
	debug(49, 5) ("snmpTreeNext: Past Second\n");

	while ((mibTreeEntry) && (!mibTreeEntry->parsefunction)) {
	    mibTreeEntry = mibTreeEntry->leaves[0];
	}

	if ((mibTreeEntry) && (mibTreeEntry->children == 1))
	    mibTreeEntry = mibTreeEntry->leaves[0];
    }
    if (mibTreeEntry) {
	*Next = snmpOidDup(mibTreeEntry->name, mibTreeEntry->len);
	*NextLen = mibTreeEntry->len;
	Fn = mibTreeEntry->parsefunction;
    }
    debug(49, 5) ("snmpTreeNext: return\n");
    return (Fn);
}

mib_tree_entry *
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

mib_tree_entry *
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
 * Utility functions
 */

/*
 * Tree utility functions. 
 */

/*
 * Adds a node to the MIB tree structure and adds the appropriate children
 */
#if STDC_HEADERS
mib_tree_entry *
snmpAddNode(oid * name, int len, oid_ParseFn * parsefunction, int children,...)
{
    va_list args;
    int loop;
    mib_tree_entry *entry = NULL;
    va_start(args, children);

#else
mib_tree_entry *
snmpAddNode(va_alist)
     va_dcl
{
    va_list args;
    oid *name = NULL;
    int len = 0, children = 0, loop;
    oid_ParseFn *parsefunction = NULL;
    mib_tree_entry *entry = NULL;

    va_start(args);
    name = va_arg(args, oid *);
    len = va_arg(args, int);
    parsefunction = va_arg(args, oid_ParseFn *);
    children = va_arg(args, int);
#endif

    debug(49, 6) ("snmpAddNode: Children : %d, Oid : \n", children);
    snmpDebugOid(6, name, len);

    va_start(args, children);
    entry = xmalloc(sizeof(mib_tree_entry));
    entry->name = snmpOidDup(name, len);
    entry->len = len;
    entry->parsefunction = parsefunction;
    entry->children = children;

    if (children > 0) {
	entry->leaves = xmalloc(sizeof(mib_tree_entry *) * children);
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
#if STDC_HEADERS
oid *
snmpCreateOid(int length,...)
{
    va_list args;
    oid *new_oid;
    int loop;

    va_start(args, length);
#else
oid *
snmpCreateOid(va_alist)
     va_dcl
{
    va_list args;
    int length = 0, loop;
    oid *new_oid;

    va_start(args);
    length va_arg(args, int);
#endif

    new_oid = xmalloc(sizeof(oid) * length);

    if (length > 0) {
	for (loop = 0; loop < length; loop++) {
	    new_oid[loop] = va_arg(args, int);
	}
    }
    return (new_oid);
}

/*
 * Allocate space for, and copy, an OID.  Returns new oid.
 */
oid *
snmpOidDup(oid * A, snint ALen)
{
    oid *Ans = xmalloc(sizeof(oid) * ALen);
    xmemcpy(Ans, A, (sizeof(oid) * ALen));
    return Ans;
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
	strncat(objid, mbuf, sizeof(objid));
    }

    debug(49, lvl) ("   oid = %s\n", objid);
}

static void
snmpSnmplibDebug(int lvl, char *buf)
{
    debug(49, lvl) ("%s", buf);
}
