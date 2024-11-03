/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_INCLUDE_SNMP_API_H
#define SQUID_INCLUDE_SNMP_API_H

/***********************************************************
    Copyright 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/

/*
 * snmp_api.h - API for access to snmp.
 */

/*
 * Set fields in session and pdu to the following to get a default or unconfigured value.
 */
#define SNMP_DEFAULT_COMMUNITY_LEN  0   /* to get a default community name */
#define SNMP_DEFAULT_RETRIES        3
#define SNMP_DEFAULT_TIMEOUT        1
#define SNMP_DEFAULT_REMPORT        0
#define SNMP_DEFAULT_PEERNAME       NULL
#define SNMP_DEFAULT_ENTERPRISE_LENGTH  0
#define SNMP_DEFAULT_TIME       0
#define SNMP_DEFAULT_MAXREPETITIONS 5
#define SNMP_DEFAULT_MACREPEATERS   0

#ifdef __cplusplus
extern "C" {
#endif

/* Parse the buffer pointed to by arg3, of length arg4, into pdu arg2.
 *
 * Returns the community of the incoming PDU, or NULL
 */
u_char *snmp_parse(struct snmp_session *, struct snmp_pdu *, u_char *, int);

/* Encode pdu arg2 into buffer arg3.  arg4 contains the size of
 * the buffer.
 */
int snmp_build(struct snmp_session *, struct snmp_pdu *, u_char *, int *);

#ifdef __cplusplus
}

#endif

#endif /* SQUID_INCLUDE_SNMP_API_H */

