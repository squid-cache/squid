/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
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

#include "snmp-internal.h"
#include "snmp_error.h"
#include "snmp_impl.h"
#include "snmp_msg.h"
#include "snmp_pdu.h"
#include "snmp_session.h"
#include "snmp_vars.h"

#include "snmp_api.h"
#include "snmp_api_error.h"
#include "snmp_api_util.h"

#include "util.h"

/**********************************************************************/

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the encoded packet in out_length.  If an error
 * occurs, -1 is returned.  If all goes well, 0 is returned.
 */
int
snmp_build(session, pdu, packet, out_length)
struct snmp_session *session;
struct snmp_pdu *pdu;
u_char *packet;
int *out_length;
{
    u_char *bufp;

    bufp = snmp_msg_Encode(packet, out_length,
                           session->community, session->community_len,
                           session->Version,
                           pdu);
    snmplib_debug(8, "LIBSNMP: snmp_build():  Packet len %d (requid %d)\n",
                  *out_length, pdu->reqid);

    if (bufp == NULL)
        return (-1);

    return (0);
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, NULL is returned.  If not, the community is.
 */
u_char *
snmp_parse(struct snmp_session * session,
           struct snmp_pdu * pdu,
           u_char * data,
           int length)
{
    u_char Community[128];
    u_char *bufp;
    int CommunityLen = 128;

    /* Decode the entire message. */
    data = snmp_msg_Decode(data, &length,
                           Community, &CommunityLen,
                           &session->Version, pdu);
    if (data == NULL)
        return (NULL);

    bufp = (u_char *) xmalloc(CommunityLen + 1);
    if (bufp == NULL)
        return (NULL);

    strncpy((char *) bufp, (char *) Community, CommunityLen);
    bufp[CommunityLen] = '\0';

    session->community = bufp;
    session->community_len = CommunityLen;

    return (bufp);
}

