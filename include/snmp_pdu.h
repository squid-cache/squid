#ifndef SQUID_SNMP_PDU_H
#define SQUID_SNMP_PDU_H

/**********************************************************************
 *
 *           Copyright 1997 by Carnegie Mellon University
 * 
 *                       All Rights Reserved
 * 
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * 
 * Author: Ryan Troll <ryan+@andrew.cmu.edu>
 * 
 * $Id: snmp_pdu.h,v 1.11 2003/01/23 00:36:48 robertc Exp $
 * 
 **********************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sockaddr_in ipaddr;

/* An SNMP PDU */
struct snmp_pdu {
    int command;		/* Type of this PDU */
    ipaddr address;		/* Address of peer */

    int reqid;			/* Integer32: Request id */
    int errstat;		/* INTEGER:   Error status */
    int errindex;		/* INTEGER:   Error index */

    /* SNMPv2 Bulk Request */
    int non_repeaters;		/* INTEGER: */
    int max_repetitions;	/* INTEGER: */

    struct variable_list *variables;	/* Variable Bindings */

    /* Trap information */
    oid *enterprise;		/* System OID */
    int enterprise_length;
    ipaddr agent_addr;		/* address of object generating trap */
    int trap_type;		/* generic trap type */
    int specific_type;		/* specific type */
    u_int time;			/* Uptime */
};

struct snmp_pdu *snmp_pdu_create(int);
struct snmp_pdu *snmp_pdu_clone(struct snmp_pdu *);
struct snmp_pdu *snmp_pdu_fix(struct snmp_pdu *, int);
struct snmp_pdu *snmp_fix_pdu(struct snmp_pdu *, int);
void snmp_free_pdu(struct snmp_pdu *);
void snmp_pdu_free(struct snmp_pdu *);

u_char *snmp_pdu_encode(u_char *, int *, struct snmp_pdu *);
u_char *snmp_pdu_decode(u_char *, int *, struct snmp_pdu *);

    /* Add a NULL Variable to a PDU */
void snmp_add_null_var(struct snmp_pdu *, oid *, int);

/* RFC 1905: Protocol Operations for SNMPv2
 *
 * RFC 1157: A Simple Network Management Protocol (SNMP)
 *
 * PDU Types
 */
#define SNMP_PDU_GET	    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0)
#define SNMP_PDU_GETNEXT    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x1)
#define SNMP_PDU_RESPONSE   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x2)
#ifdef UNUSED_CODE
#define SNMP_PDU_SET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x3)
#define TRP_REQ_MSG	    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x4)	/*Obsolete */
#endif
#define SNMP_PDU_GETBULK    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x5)
#ifdef UNUSED_CODE
#define SNMP_PDU_INFORM     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x6)
#define SNMP_PDU_V2TRAP     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x7)
#define SNMP_PDU_REPORT     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x8)
#endif
#define MAX_BINDINGS 2147483647	/* PDU Defaults */
#define SNMP_DEFAULT_ERRSTAT	    -1
#define SNMP_DEFAULT_ERRINDEX	    -1
#define SNMP_DEFAULT_ADDRESS	    0
#define SNMP_DEFAULT_REQID	    0

/* RFC 1907: Management Information Base for SNMPv2
 *
 * RFC 1157: A Simple Network Management Protocol (SNMP)
 *
 * Trap Types
 */
#if UNUSED_CODE
#define SNMP_TRAP_COLDSTART             (0x0)
#define SNMP_TRAP_WARMSTART             (0x1)
#define SNMP_TRAP_LINKDOWN              (0x2)
#define SNMP_TRAP_LINKUP                (0x3)
#define SNMP_TRAP_AUTHENTICATIONFAILURE (0x4)
#define SNMP_TRAP_EGPNEIGHBORLOSS       (0x5)
#define SNMP_TRAP_ENTERPRISESPECIFIC    (0x6)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SQUID_SNMP_PDU_H */
