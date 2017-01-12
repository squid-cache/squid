/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * RFC 1908: Coexistence between SNMPv1 and SNMPv2
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
#include "snmp_pdu.h"
#include "snmp_vars.h"

#include "util.h"

/*
 * RFC 1908: Coexistence between SNMPv1 and SNMPv2
 *
 * These convert:
 *
 *   V1 PDUs from an ** AGENT **   to V2 PDUs for an ** MANAGER **
 *   V2 PDUs from an ** MANAGER ** to V1 PDUs for an ** AGENT **
 *
 * We will never convert V1 information from a manager into V2 PDUs.  V1
 * requests are always honored by V2 agents, and the responses will be
 * valid V1 responses.  (I think. XXXXX)
 *
 */
int
snmp_coexist_V2toV1(struct snmp_pdu *PDU)
{
    /* Per 3.1.1:
     */
    switch (PDU->command) {

    case SNMP_PDU_GET:
    case SNMP_PDU_GETNEXT:
#if SNMP_PDU_SET
    case SNMP_PDU_SET:
#endif
        return (1);
        break;

    case SNMP_PDU_GETBULK:
        PDU->non_repeaters = 0;
        PDU->max_repetitions = 0;
        PDU->command = SNMP_PDU_GETNEXT;
        return (1);
        break;

    default:
        snmplib_debug(2, "Unable to translate PDU %d to SNMPv1!\n", PDU->command);
        snmp_set_api_error(SNMPERR_PDU_TRANSLATION);
        return (0);
    }
}

