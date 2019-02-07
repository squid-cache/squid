/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SNMP_API_ERROR_H
#define SQUID_SNMP_API_ERROR_H

/***************************************************************************
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
 ***************************************************************************/

/* Error return values */
#define SNMPERR_GENERR      -1
#define SNMPERR_BAD_LOCPORT -2  /* local port was already in use */
#define SNMPERR_BAD_ADDRESS -3
#define SNMPERR_BAD_SESSION -4
#define SNMPERR_TOO_LONG    -5  /* data too long for provided buffer */

#define SNMPERR_ASN_ENCODE      -6
#define SNMPERR_ASN_DECODE      -7
#define SNMPERR_PDU_TRANSLATION -8
#define SNMPERR_OS_ERR          -9
#define SNMPERR_INVALID_TXTOID  -10

#define SNMPERR_UNABLE_TO_FIX   -11
#define SNMPERR_UNSUPPORTED_TYPE -12
#define SNMPERR_PDU_PARSE        -13
#define SNMPERR_PACKET_ERR      -14
#define SNMPERR_NO_RESPONSE     -15

#define SNMPERR_LAST            -16 /* Last error message */

#ifdef __cplusplus
extern "C" {
#endif

/* extern int snmp_errno */

const char *snmp_api_error(int);
int snmp_api_errno(void);

const char *api_errstring(int); /* Backwards compatibility */
void snmp_set_api_error(int);

#ifdef __cplusplus
}

#endif

#endif              /* SQUID_SNMP_API_ERROR_H */

