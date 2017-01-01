/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Error routines concerning the error status of the SNMP API.
 *
 * Sometimes things don't work out the way we wanted.
 *
 */
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

#include "squid.h"
#include "snmp_api_error.h"

int snmp_errno = 0;

static const char *api_errors[17] = {
    "Unknown Error",
    "Generic Error",
    "Invalid local port",
    "Unknown host",
    "Unknown session",
    "Too Long",

    "Encoding ASN.1 Information",   /* 6 */
    "Decoding ASN.1 Information",   /* 7 */
    "PDU Translation error",
    "OS Error",
    "Invalid Textual OID",

    "Unable to fix PDU",
    "Unsupported SNMP Type",
    "Unable to parse PDU",
    "Packet Error",
    "No Response From Host",

    "Unknown Error"
};

void
snmp_set_api_error(int x)
{
    snmp_errno = x;
}

const char *
snmp_api_error(int err)
{
    int foo = (err * -1);
    if ((foo < SNMPERR_GENERR) ||
            (foo > SNMPERR_LAST))
        foo = 0;

    return (api_errors[foo]);
}

int
snmp_api_errno(void)
{
    return (snmp_errno);
}

const char *
api_errstring(int snmp_errnumber)
{
    return (snmp_api_error(snmp_errnumber));
}

