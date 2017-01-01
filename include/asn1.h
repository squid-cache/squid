/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SNMP_ASN1_H
#define SQUID_SNMP_ASN1_H

/*
 * Definitions for Abstract Syntax Notation One, ASN.1
 * As defined in ISO/IS 8824 and ISO/IS 8825
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
 **********************************************************************/

#ifndef EIGHTBIT_SUBIDS
typedef u_int oid;
#define MAX_SUBID   0xFFFFFFFF
#else
typedef u_char oid;
#define MAX_SUBID   0xFF
#endif

#define MAX_OID_LEN     128 /* max subid's in an oid, per SNMP spec. */

#define ASN_BOOLEAN     (0x01)
#define ASN_INTEGER     (0x02)
#define ASN_BIT_STR     (0x03)
#define ASN_OCTET_STR       (0x04)
#define ASN_NULL        (0x05)
#define ASN_OBJECT_ID       (0x06)
#define ASN_SEQUENCE        (0x10)
#define ASN_SET         (0x11)

#define ASN_UNIVERSAL       (0x00)
#define ASN_APPLICATION     (0x40)
#define ASN_CONTEXT     (0x80)
#define ASN_PRIVATE     (0xC0)

#define ASN_PRIMITIVE       (0x00)
#define ASN_CONSTRUCTOR     (0x20)

#define ASN_LONG_LEN        (0x80)
#define ASN_EXTENSION_ID    (0x1F)
#define ASN_BIT8        (0x80)

#define IS_CONSTRUCTOR(byte)    ((byte) & ASN_CONSTRUCTOR)
#define IS_EXTENSION_ID(byte)   (((byte) & ASN_EXTENSION_ID) == ASN_EXTENSION_ID)

#ifdef __cplusplus
extern "C" {
#endif

u_char *asn_build_header(u_char *, int *, u_char, int);
u_char *asn_parse_int(u_char *, int *, u_char *, int *, int);
u_char *asn_parse_unsigned_int(u_char *, int *, u_char *, u_int *, int);
u_char *asn_build_int(u_char *, int *, u_char, int *, int);
u_char *asn_build_unsigned_int(u_char *, int *, u_char, u_int *, int);
u_char *asn_parse_string(u_char *, int *, u_char *, u_char *, int *);
u_char *asn_build_string(u_char *, int *, u_char, u_char *, int);
u_char *asn_parse_header(u_char *, int *, u_char *);
u_char *asn_build_header_with_truth(u_char *, int *, u_char, int, int);

u_char *asn_parse_length(u_char *, u_int *);
u_char *asn_build_length(u_char *, int *, int, int);
u_char *asn_parse_objid(u_char *, int *, u_char *, oid *, int *);
u_char *asn_build_objid(u_char *, int *, u_char, oid *, int);
u_char *asn_parse_null(u_char *, int *, u_char *);
u_char *asn_build_null(u_char *, int *, u_char);

#if 0
u_char *asn_parse_bitstring(u_char *, int *, u_char *, u_char *, int *);
u_char *asn_build_bitstring(u_char *, int *, u_char, u_char *, int);

#endif
u_char *asn_build_exception(u_char *, int *, u_char);

#ifdef __cplusplus
}

#endif

#endif  /* SQUID_SNMP_ASN1_H */

