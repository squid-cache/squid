/* -*- c++ -*- */
#ifndef SQUID_SNMP_ERROR_H
#define SQUID_SNMP_ERROR_H

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

/*
 * RFC 1905: Protocol Operations for SNMPv2
 *
 * PDU : Error Status Values
 */

#define SNMP_ERR_NOERROR             (0x0)
#define SNMP_ERR_TOOBIG              (0x1)
#define SNMP_ERR_NOSUCHNAME          (0x2)
#define SNMP_ERR_BADVALUE            (0x3)
#define SNMP_ERR_READONLY            (0x4)
#define SNMP_ERR_GENERR              (0x5)
#define SNMP_ERR_NOACCESS            (0x6)
#define SNMP_ERR_WRONGTYPE           (0x7)
#define SNMP_ERR_WRONGLENGTH         (0x8)
#define SNMP_ERR_WRONGENCODING       (0x9)
/* 0x0A - 0x0F undefined */
#define SNMP_ERR_WRONGVALUE          (0x10)
#define SNMP_ERR_NOCREATION          (0x11)
#define SNMP_ERR_INCONSISTENTVALUE   (0x12)
#define SNMP_ERR_RESOURCEUNAVAILABLE (0x13)
#define SNMP_ERR_COMMITFAILED        (0x14)
#define SNMP_ERR_UNDOFAILED          (0x15)
#define SNMP_ERR_AUTHORIZATIONERROR  (0x16)
#define SNMP_ERR_NOTWRITABLE         (0x17)
#define SNMP_ERR_INCONSISTENTNAME    (0x18)

#ifdef __cplusplus

extern "C" {
#endif

    const char *snmp_errstring(int);

#ifdef __cplusplus
}
#endif

#endif				/* SQUID_SNMP_ERROR_H */
