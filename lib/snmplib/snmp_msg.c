/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * SNMP Message Encoding Routines
 *
 * Complies with:
 *
 * RFC 1901: Introduction to Community-based SNMPv2
 * RFC 1157: A Simple Network Management Protocol (SNMP)
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
#include "snmp_msg.h"
#include "snmp_pdu.h"
#include "snmp_vars.h"

/*
 * RFC 1901: Introduction to Community-based SNMPv2
 *
 *  Message ::=
 *    SEQUENCE {
 *      version   INTEGER
 *      community OCTET STRING
 *      data
 *    }
 *
 * RFC 1157: A Simple Network Management Protocol (SNMP)
 *
 *  Message ::=
 *    SEQUENCE {
 *      version   INTEGER
 *      community OCTET STRING
 *      data
 *    }
 *
 */

/* Encode a SNMP Message Header.  Return a pointer to the beginning of the
 * data.
 */

#define ASN_PARSE_ERROR(x) {  return(x); }

/* Encode an SNMP Message
 *
 * Returns a pointer to the end of the message, or NULL.
 *
 * *BufLenP (Second Argument) will contain the amount of space left
 *          in the buffer.
 */

u_char *
snmp_msg_Encode(u_char * Buffer, int *BufLenP,
                u_char * Community, int CommLen,
                int Version,
                struct snmp_pdu *PDU)
{
    u_char *bufp, *tmp;
    u_char *PDUHeaderPtr, *VARHeaderPtr;
    u_char *PDUDataStart, *VARDataStart;
    u_char *MsgPtr;
    int FakeArg = 1024;

    snmplib_debug(4, "Buffer=%p BufLenP=%p, buflen=%d\n", Buffer, BufLenP,
                  *BufLenP);
    /* Header for the entire thing, with a false, large length */
    bufp = asn_build_header(Buffer, BufLenP,
                            (u_char) (ASN_SEQUENCE |
                                      ASN_CONSTRUCTOR),
                            (*BufLenP));
    if (bufp == NULL) {
        snmplib_debug(4, "snmp_msg_Encode:Error encoding SNMP Message Header (Header)!\n");
        return (NULL);
    }
    MsgPtr = bufp;

    /* Version */
    bufp = asn_build_int(bufp, BufLenP,
                         (u_char) (ASN_UNIVERSAL |
                                   ASN_PRIMITIVE |
                                   ASN_INTEGER),
                         (int *) (&Version), sizeof(Version));
    if (bufp == NULL) {
        snmplib_debug(4, "snmp_msg_Encode:Error encoding SNMP Message Header (Version)!\n");
        return (NULL);
    }
    snmplib_debug(8, "snmp_msg_Encode: Encoding community (%s) (%d)\n", Community, CommLen);

    /* Community */
    bufp = asn_build_string(bufp, BufLenP,
                            (u_char) (ASN_UNIVERSAL |
                                      ASN_PRIMITIVE |
                                      ASN_OCTET_STR),
                            Community, CommLen);
    if (bufp == NULL) {
        snmplib_debug(4, "snmp_msg_Encode:Error encoding SNMP Message Header (Community)!\n");
        return (NULL);
    }
    /* Encode the rest. */

    /* A nice header for this PDU.
     * Encoded with the wrong length.  We'll fix it later.
     */
    snmplib_debug(8, "snmp_msg_Encode:Encoding PDU Header at 0x%p (fake len %d) (%d bytes so far)\n",
                  bufp, *BufLenP, *BufLenP);
    PDUHeaderPtr = bufp;
    bufp = asn_build_header(bufp, BufLenP,
                            (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                            (*BufLenP));
    if (bufp == NULL)
        return (NULL);

    /* Encode this PDU. */
    PDUDataStart = bufp;
    bufp = snmp_pdu_encode(bufp, BufLenP, PDU);
    if (bufp == NULL)
        return (NULL);      /* snmp_pdu_encode registered failure */

    VARHeaderPtr = bufp;
    bufp = asn_build_header(bufp, BufLenP,
                            (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                            FakeArg);
    if (bufp == NULL)
        return (NULL);
    VARDataStart = bufp;

    /* And build the variables */
    bufp = snmp_var_EncodeVarBind(bufp, BufLenP, PDU->variables, Version);
    if (bufp == NULL)
        return (NULL);      /* snmp_var_EncodeVarBind registered failure */

    /* Cool.  Now insert the appropriate lengths.
     */
#if DEBUG_MSG_ENCODE
    snmplib_debug(9, "Msg:  Vars returned 0x%x.  PDU Started at 0x%x\n",
                  bufp, PDUHeaderPtr);
    snmplib_debug(9, "MSG:  Entire PDU length is %d (0x%x - 0x%x)\n",
                  (int) (bufp - PDUDataStart), PDUHeaderPtr, bufp);
#endif
    tmp = asn_build_header(PDUHeaderPtr, &FakeArg,
                           (u_char) PDU->command,
                           (int) (bufp - PDUDataStart));
    /* Length of the PDU and Vars */
    if (tmp == NULL)
        return (NULL);

#if DEBUG_MSG_ENCODE
    snmplib_debug(9, "MSG:  Entire message length is %d (0x%x - 0x%x)\n",
                  (int) (bufp - MsgPtr), MsgPtr, bufp);
#endif
    tmp = asn_build_header(Buffer,
                           &FakeArg,
                           (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                           (bufp - MsgPtr));    /* Length of everything */
    if (tmp == NULL)
        return (NULL);

    tmp = asn_build_header(VARHeaderPtr,
                           &FakeArg,
                           (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                           (bufp - VARDataStart));  /* Length of everything */
    if (tmp == NULL)
        return (NULL);

    *BufLenP = (bufp - Buffer);
    return (u_char *) bufp;
}

/**********************************************************************/

u_char *
snmp_msg_Decode(u_char * Packet, int *PacketLenP,
                u_char * Community, int *CommLenP,
                int *Version, struct snmp_pdu * PDU)
{
    u_char *bufp;
    u_char type;

    bufp = asn_parse_header(Packet, PacketLenP, &type);
    if (bufp == NULL) {
        snmplib_debug(4, "snmp_msg_Decode:Error decoding SNMP Message Header (Header)!\n");
        ASN_PARSE_ERROR(NULL);
    }
    if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
        snmplib_debug(4, "snmp_msg_Decode:Error decoding SNMP Message Header (Header)!\n");
        ASN_PARSE_ERROR(NULL);
    }
    bufp = asn_parse_int(bufp, PacketLenP,
                         &type,
                         (int *) Version, sizeof(*Version));
    if (bufp == NULL) {
        snmplib_debug(4, "snmp_msg_Decode:Error decoding SNMP Message Header (Version)!\n");
        ASN_PARSE_ERROR(NULL);
    }
    bufp = asn_parse_string(bufp, PacketLenP, &type, Community, CommLenP);
    if (bufp == NULL) {
        snmplib_debug(4, "snmp_msg_Decode:Error decoding SNMP Message Header (Community)!\n");
        ASN_PARSE_ERROR(NULL);
    }
    Community[*CommLenP] = '\0';

    if ((*Version != SNMP_VERSION_1) &&
            (*Version != SNMP_VERSION_2)) {

        /* Don't know how to handle this one. */
        snmplib_debug(4, "snmp_msg_Decode:Unable to parse Version %u\n", *Version);
        snmplib_debug(4, "snmp_msg_Decode:Continuing anyway\n");
    }
    /* Now that we know the header, decode the PDU */

    /* XXXXX -- More than one PDU? */
    bufp = snmp_pdu_decode(bufp, PacketLenP, PDU);
    if (bufp == NULL)
        /* snmp_pdu_decode registered failure */
        return (NULL);

    bufp = snmp_var_DecodeVarBind(bufp, PacketLenP, &(PDU->variables), *Version);
    if (bufp == NULL)
        /* snmp_var_DecodeVarBind registered failure */
        return (NULL);

    return (u_char *) bufp;
}

