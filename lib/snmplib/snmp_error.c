/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * The possible SNMP Error messages, from the SNMP Protocol Operations
 * [ RFC 1905 ]
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
#include "snmp_error.h"

static const char *error_string[25] = {
    /* 0x00 - 0x05 */
    "No Error",
    "Response message would have been too large.",
    "There is no such variable name in this MIB.",
    "The value given has the wrong type, length, or value",
    "This variable is read only",
    "A general failure occurred",

    /* 0x06 - 0x09 */
    /* SNMPv2 Errors */
    "NOACCESS",
    "WRONGTYPE",
    "WRONGLENGTH",
    "WRONGENCODING",

    /* 0x0A - 0x0F */
    "UNDEFINED",
    "UNDEFINED",
    "UNDEFINED",
    "UNDEFINED",
    "UNDEFINED",
    "UNDEFINED",

    /* 0x10 - 0x18 */
    "WRONGVALUE",
    "NOCREATION",
    "INCONSISTENTVALUE",
    "RESOURCEUNAVAILABLE",
    "COMMITFAILED",
    "UNDOFAILED",
    "AUTHORIZATIONERROR",
    "NOTWRITABLE",
    "INCONSISTENTNAME",

};

const char *
snmp_errstring(int errstat)
{
    if ((errstat <= (SNMP_ERR_INCONSISTENTNAME)) &&
            (errstat >= (SNMP_ERR_NOERROR))) {
        return error_string[errstat];
    } else {
        return "Unknown Error";
    }
}

