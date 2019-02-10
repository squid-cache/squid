/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * SNMP PDU Encoding
 *
 * Complies with:
 *
 * RFC 1902: Structure of Management Information for SNMPv2
 *
 */

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
 **********************************************************************/

#include "squid.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_GNUMALLOC_H
#include <gnumalloc.h>
#elif HAVE_MALLOC_H
#include <malloc.h>
#endif
#if HAVE_MEMORY_H
#include <memory.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if HAVE_BSTRING_H
#include <bstring.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_api_error.h"
#include "snmp_error.h"
#include "snmp_msg.h"
#include "snmp_pdu.h"
#include "snmp_vars.h"

#include "util.h"

/* #define DEBUG_PDU 1 */
/* #define DEBUG_PDU_DECODE 1 */
/* #define DEBUG_PDU_ENCODE 1 */

#define ASN_PARSE_ERROR(x) {  return(x); }

/**********************************************************************/

/* Create a PDU.
 */

struct snmp_pdu *
snmp_pdu_create(int command) {
    struct snmp_pdu *pdu;

#if DEBUG_PDU
    snmplib_debug(8, "PDU:  Creating\n");
#endif

    pdu = (struct snmp_pdu *) xmalloc(sizeof(struct snmp_pdu));
    if (pdu == NULL) {
        snmp_set_api_error(SNMPERR_OS_ERR);
        return (NULL);
    }
    memset((char *) pdu, '\0', sizeof(struct snmp_pdu));

    pdu->command = command;
    pdu->errstat = SNMP_DEFAULT_ERRSTAT;
    pdu->errindex = SNMP_DEFAULT_ERRINDEX;
    pdu->address.sin_addr.s_addr = SNMP_DEFAULT_ADDRESS;
    pdu->enterprise = NULL;
    pdu->enterprise_length = 0;
    pdu->variables = NULL;

#if DEBUG_PDU
    snmplib_debug(8, "PDU:  Created %x\n", (unsigned int) pdu);
#endif

    return (pdu);
}

/**********************************************************************/

/* Clone an existing PDU.
 */
struct snmp_pdu *
snmp_pdu_clone(struct snmp_pdu *Src) {
    struct snmp_pdu *Dest;

#if DEBUG_PDU
    snmplib_debug(8, "PDU %x:  Cloning\n", (unsigned int) Src);
#endif

    Dest = (struct snmp_pdu *) xmalloc(sizeof(struct snmp_pdu));
    if (Dest == NULL) {
        snmp_set_api_error(SNMPERR_OS_ERR);
        return (NULL);
    }
    memcpy((char *) Dest, (char *) Src, sizeof(struct snmp_pdu));

#if DEBUG_PDU
    snmplib_debug(8, "PDU %x:  Created %x\n", (unsigned int) Src, (unsigned int) Dest);
#endif
    return (Dest);
}

/**********************************************************************/

/*
 * If there was an error in the input pdu, creates a clone of the pdu
 * that includes all the variables except the one marked by the errindex.
 * The command is set to the input command and the reqid, errstat, and
 * errindex are set to default values.
 * If the error status didn't indicate an error, the error index didn't
 * indicate a variable, the pdu wasn't a get response message, or there
 * would be no remaining variables, this function will return NULL.
 * If everything was successful, a pointer to the fixed cloned pdu will
 * be returned.
 */
struct snmp_pdu *
snmp_pdu_fix(struct snmp_pdu *pdu, int command) {
    return (snmp_fix_pdu(pdu, command));
}

struct snmp_pdu *
snmp_fix_pdu(struct snmp_pdu *pdu, int command) {
    struct variable_list *var, *newvar;
    struct snmp_pdu *newpdu;
    int i;
    int copied = 0;

#if DEBUG_PDU
    snmplib_debug(8, "PDU %x:  Fixing.  Err index is %d\n",
                  (unsigned int) pdu, (unsigned int) pdu->errindex);
#endif

    if (pdu->command != SNMP_PDU_RESPONSE ||
            pdu->errstat == SNMP_ERR_NOERROR ||
            pdu->errindex <= 0) {
        snmp_set_api_error(SNMPERR_UNABLE_TO_FIX);
        return (NULL);
    }
    /* clone the pdu */
    newpdu = snmp_pdu_clone(pdu);
    if (newpdu == NULL)
        return (NULL);

    newpdu->variables = 0;
    newpdu->command = command;
    newpdu->reqid = SNMP_DEFAULT_REQID;
    newpdu->errstat = SNMP_DEFAULT_ERRSTAT;
    newpdu->errindex = SNMP_DEFAULT_ERRINDEX;

    /* Loop through the variables, removing whatever isn't necessary */

    var = pdu->variables;
    i = 1;

    /* skip first variable if necessary */
    if (pdu->errindex == i) {
        var = var->next_variable;
        i++;
    }
    if (var != NULL) {

        /* VAR is the first uncopied variable */

        /* Clone this variable */
        newpdu->variables = snmp_var_clone(var);
        if (newpdu->variables == NULL) {
            snmp_pdu_free(newpdu);
            return (NULL);
        }
        copied++;

        newvar = newpdu->variables;

        /* VAR has been copied to NEWVAR. */
        while (var->next_variable) {

            /* Skip the item that was bad */
            if (++i == pdu->errindex) {
                var = var->next_variable;
                continue;
            }
            /* Copy this var */
            newvar->next_variable = snmp_var_clone(var->next_variable);
            if (newvar->next_variable == NULL) {
                snmp_pdu_free(newpdu);
                return (NULL);
            }
            /* Move to the next one */
            newvar = newvar->next_variable;
            var = var->next_variable;
            copied++;
        }
        newvar->next_variable = NULL;
    }
    /* If we didn't copy anything, free the new pdu. */
    if (i < pdu->errindex || copied == 0) {
        snmp_free_pdu(newpdu);
        snmp_set_api_error(SNMPERR_UNABLE_TO_FIX);
        return (NULL);
    }
#if DEBUG_PDU
    snmplib_debug(8, "PDU %x:  Fixed PDU is %x\n",
                  (unsigned int) pdu, (unsigned int) newpdu);
#endif
    return (newpdu);
}

/**********************************************************************/

void
snmp_pdu_free(struct snmp_pdu *pdu)
{
    snmp_free_pdu(pdu);
}

/*
 * Frees the pdu and any xmalloc'd data associated with it.
 */
void
snmp_free_pdu(struct snmp_pdu *pdu)
{
    struct variable_list *vp, *ovp;

    vp = pdu->variables;
    while (vp) {
        ovp = vp;
        vp = vp->next_variable;
        snmp_var_free(ovp);
    }

    if (pdu->enterprise)
        xfree((char *) pdu->enterprise);
    xfree((char *) pdu);
}

/**********************************************************************/

/* Encode this PDU into DestBuf.
 *
 * Returns a pointer to the next byte in the buffer (where the Variable
 * Bindings belong.)
 */

/*
 * RFC 1902: Structure of Management Information for SNMPv2
 *
 *   PDU ::=
 *    SEQUENCE {
 *      request-id   INTEGER32
 *      error-status INTEGER
 *      error-index  INTEGER
 *      Variable Bindings
 *    }
 *
 * BulkPDU ::=
 *    SEQUENCE {
 *      request-id      INTEGER32
 *      non-repeaters   INTEGER
 *      max-repetitions INTEGER
 *      Variable Bindings
 *    }
 */

/*
 * RFC 1157: A Simple Network Management Protocol (SNMP)
 *
 *   PDU ::=
 *    SEQUENCE {
 *      request-id   INTEGER
 *      error-status INTEGER
 *      error-index  INTEGER
 *      Variable Bindings
 *    }
 *
 *   TrapPDU ::=
 *    SEQUENCE {
 *      enterprise    NetworkAddress
 *      generic-trap  INTEGER
 *      specific-trap INTEGER
 *      time-stamp    TIMETICKS
 *      Variable Bindings
 *    }
 */

u_char *
snmp_pdu_encode(u_char * DestBuf, int *DestBufLen,
                struct snmp_pdu *PDU)
{
    u_char *bufp;

#if DEBUG_PDU_ENCODE
    snmplib_debug(8, "PDU: Encoding %d\n", PDU->command);
#endif

    /* ASN.1 Header */
    switch (PDU->command) {

        /**********************************************************************/
#if TRP_REQ_MSG
    case TRP_REQ_MSG:

        /* SNMPv1 Trap */

        /* enterprise */
        bufp = asn_build_objid(DestBuf, DestBufLen,
                               (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
                               (oid *) PDU->enterprise, PDU->enterprise_length);
        if (bufp == NULL)
            return (NULL);

        /* agent-addr */
        bufp = asn_build_string(bufp, DestBufLen,
                                (u_char) (SMI_IPADDRESS | ASN_PRIMITIVE),
                                (u_char *) & PDU->agent_addr.sin_addr.s_addr,
                                sizeof(PDU->agent_addr.sin_addr.s_addr));
        if (bufp == NULL)
            return (NULL);

        /* generic trap */
        bufp = asn_build_int(bufp, DestBufLen,
                             (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                             (int *) &PDU->trap_type, sizeof(PDU->trap_type));
        if (bufp == NULL)
            return (NULL);

        /* specific trap */
        bufp = asn_build_int(bufp, DestBufLen,
                             (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                             (int *) &PDU->specific_type,
                             sizeof(PDU->specific_type));
        if (bufp == NULL)
            return (NULL);

        /* timestamp */
        bufp = asn_build_unsigned_int(bufp, DestBufLen,
                                      (u_char) (SMI_TIMETICKS | ASN_PRIMITIVE),
                                      &PDU->time, sizeof(PDU->time));
        if (bufp == NULL)
            return (NULL);
        break;
#endif

    /**********************************************************************/

    case SNMP_PDU_GETBULK:

        /* SNMPv2 Bulk Request */

        /* request id */
        bufp = asn_build_int(DestBuf, DestBufLen,
                             (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                             &PDU->reqid, sizeof(PDU->reqid));
        if (bufp == NULL)
            return (NULL);

        /* non-repeaters */
        bufp = asn_build_int(bufp, DestBufLen,
                             (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                             &PDU->non_repeaters,
                             sizeof(PDU->non_repeaters));
        if (bufp == NULL)
            return (NULL);

        /* max-repetitions */
        bufp = asn_build_int(bufp, DestBufLen,
                             (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                             &PDU->max_repetitions,
                             sizeof(PDU->max_repetitions));
        if (bufp == NULL)
            return (NULL);
        break;

    /**********************************************************************/

    default:

        /* Normal PDU Encoding */

        /* request id */
#if DEBUG_PDU_ENCODE
        snmplib_debug(8, "PDU: Request ID %d (0x%x)\n", PDU->reqid, DestBuf);
#endif
        bufp = asn_build_int(DestBuf, DestBufLen,
                             (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                             &PDU->reqid, sizeof(PDU->reqid));
        if (bufp == NULL)
            return (NULL);

        /* error status */
#if DEBUG_PDU_ENCODE
        snmplib_debug(8, "PDU: Error Status %d (0x%x)\n", PDU->errstat, bufp);
#endif
        bufp = asn_build_int(bufp, DestBufLen,
                             (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                             &PDU->errstat, sizeof(PDU->errstat));
        if (bufp == NULL)
            return (NULL);

        /* error index */
#if DEBUG_PDU_ENCODE
        snmplib_debug(8, "PDU: Error index %d (0x%x)\n", PDU->errindex, bufp);
#endif
        bufp = asn_build_int(bufp, DestBufLen,
                             (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                             &PDU->errindex, sizeof(PDU->errindex));
        if (bufp == NULL)
            return (NULL);
        break;
    }               /* End of encoding */

    return (bufp);
}

/**********************************************************************/

/* Decodes PDU from Packet into PDU.
 *
 * Returns a pointer to the next byte of the packet, which is where the
 * Variable Bindings start.
 */
u_char *
snmp_pdu_decode(u_char * Packet,    /* data */
                int *Length,        /* &length */
                struct snmp_pdu * PDU)
{   /* pdu */
    u_char *bufp;
    u_char PDUType;
    u_char ASNType;
#if UNUSED_CODE
    int four;
    oid objid[MAX_NAME_LEN];
#endif

    bufp = asn_parse_header(Packet, Length, &PDUType);
    if (bufp == NULL)
        ASN_PARSE_ERROR(NULL);

#if DEBUG_PDU_DECODE
    snmplib_debug(8, "PDU Type: %d\n", PDUType);
#endif

    PDU->command = PDUType;
    switch (PDUType) {

#if TRP_REQ_MSG
    case TRP_REQ_MSG:

        /* SNMPv1 Trap Message */

        /* enterprise */
        PDU->enterprise_length = MAX_NAME_LEN;
        bufp = asn_parse_objid(bufp, Length,
                               &ASNType, objid, &PDU->enterprise_length);
        if (bufp == NULL)
            ASN_PARSE_ERROR(NULL);

        PDU->enterprise = (oid *) xmalloc(PDU->enterprise_length * sizeof(oid));
        if (PDU->enterprise == NULL) {
            snmp_set_api_error(SNMPERR_OS_ERR);
            return (NULL);
        }
        memcpy((char *) PDU->enterprise, (char *) objid,
               PDU->enterprise_length * sizeof(oid));

        /* Agent-addr */
        four = 4;
        bufp = asn_parse_string(bufp, Length,
                                &ASNType,
                                (u_char *) & PDU->agent_addr.sin_addr.s_addr,
                                &four);
        if (bufp == NULL)
            ASN_PARSE_ERROR(NULL);

        /* Generic trap */
        bufp = asn_parse_int(bufp, Length,
                             &ASNType,
                             (int *) &PDU->trap_type,
                             sizeof(PDU->trap_type));
        if (bufp == NULL)
            ASN_PARSE_ERROR(NULL);

        /* Specific Trap */
        bufp = asn_parse_int(bufp, Length,
                             &ASNType,
                             (int *) &PDU->specific_type,
                             sizeof(PDU->specific_type));
        if (bufp == NULL)
            ASN_PARSE_ERROR(NULL);

        /* Timestamp */
        bufp = asn_parse_unsigned_int(bufp, Length,
                                      &ASNType,
                                      &PDU->time, sizeof(PDU->time));
        if (bufp == NULL)
            ASN_PARSE_ERROR(NULL);
        break;
#endif

    /**********************************************************************/

    case SNMP_PDU_GETBULK:

        /* SNMPv2 Bulk Request */

        /* request id */
        bufp = asn_parse_int(bufp, Length,
                             &ASNType,
                             &PDU->reqid, sizeof(PDU->reqid));
        if (bufp == NULL)
            ASN_PARSE_ERROR(NULL);

        /* non-repeaters */
        bufp = asn_parse_int(bufp, Length,
                             &ASNType,
                             &PDU->non_repeaters, sizeof(PDU->non_repeaters));
        if (bufp == NULL)
            ASN_PARSE_ERROR(NULL);

        /* max-repetitions */
        bufp = asn_parse_int(bufp, Length,
                             &ASNType,
                             &PDU->max_repetitions, sizeof(PDU->max_repetitions));
        if (bufp == NULL)
            ASN_PARSE_ERROR(NULL);
        break;

    /**********************************************************************/

    default:

        /* Normal PDU Encoding */

        /* request id */
        bufp = asn_parse_int(bufp, Length,
                             &ASNType,
                             &PDU->reqid, sizeof(PDU->reqid));
        if (bufp == NULL)
            ASN_PARSE_ERROR(NULL);

#if DEBUG_PDU_DECODE
        snmplib_debug(8, "PDU Request ID: %d\n", PDU->reqid);
#endif

        /* error status */
        bufp = asn_parse_int(bufp, Length,
                             &ASNType,
                             &PDU->errstat, sizeof(PDU->errstat));
        if (bufp == NULL)
            ASN_PARSE_ERROR(NULL);

#if DEBUG_PDU_DECODE
        snmplib_debug(8, "PDU Error Status: %d\n", PDU->errstat);
#endif

        /* error index */
        bufp = asn_parse_int(bufp, Length,
                             &ASNType,
                             &PDU->errindex, sizeof(PDU->errindex));
        if (bufp == NULL)
            ASN_PARSE_ERROR(NULL);

#if DEBUG_PDU_DECODE
        snmplib_debug(8, "PDU Error Index: %d\n", PDU->errindex);
#endif

        break;
    }

    return (bufp);
}

/*
 * Add a null variable with the requested name to the end of the list of
 * variables for this pdu.
 */
void
snmp_add_null_var(struct snmp_pdu *pdu, oid * name, int name_length)
{
    struct variable_list *vars;
    struct variable_list *ptr;

    vars = snmp_var_new(name, name_length);
    if (vars == NULL) {
        perror("snmp_add_null_var:xmalloc");
        return;
    }
    if (pdu->variables == NULL) {
        pdu->variables = vars;
    } else {

        /* Insert at the end */
        for (ptr = pdu->variables;
                ptr->next_variable;
                ptr = ptr->next_variable)
            /*EXIT */ ;
        ptr->next_variable = vars;
    }

    return;
}

