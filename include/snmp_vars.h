/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SNMP_VARS_H
#define SQUID_SNMP_VARS_H

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

#include "asn1.h"

#ifdef __cplusplus
extern "C" {
#endif

struct variable_list {
    struct variable_list *next_variable;    /* NULL for last variable */
    oid *name;          /* Object identifier of variable */
    int name_length;        /* number of subid's in name */
    u_char type;        /* ASN type of variable */
    union {         /* value of variable */
        int *integer;
        u_char *string;
        oid *objid;
    } val;
    int val_len;
};

struct variable_list *snmp_var_new(oid *, int);
struct variable_list *snmp_var_new_integer(oid *, int, int, unsigned char);
struct variable_list *snmp_var_clone(struct variable_list *);
void snmp_var_free(struct variable_list *);

u_char *snmp_var_EncodeVarBind(u_char *, int *, struct variable_list *, int);
u_char *snmp_var_DecodeVarBind(u_char *, int *, struct variable_list **, int);

#define MAX_NAME_LEN    64  /* number of subid's in a objid */

/* RFC 1902: Structure of Management Information for SNMPv2
 *
 * Defined Types
 */
#define SMI_INTEGER     ASN_INTEGER
#define SMI_STRING      ASN_OCTET_STR
#define SMI_OBJID       ASN_OBJECT_ID
#define SMI_NULLOBJ     ASN_NULL
#define SMI_IPADDRESS  (ASN_APPLICATION | 0)    /* OCTET STRING, net byte order */
#define SMI_COUNTER32  (ASN_APPLICATION | 1)    /* INTEGER */
#define SMI_GAUGE32    (ASN_APPLICATION | 2)    /* INTEGER */
#define SMI_UNSIGNED32 SMI_GAUGE32
#define SMI_TIMETICKS  (ASN_APPLICATION | 3)    /* INTEGER */
#define SMI_OPAQUE     (ASN_APPLICATION | 4)    /* OCTET STRING */
#define SMI_COUNTER64  (ASN_APPLICATION | 6)    /* INTEGER */

/* constants for enums for the MIB nodes
 * cachePeerAddressType (InetAddressType / ASN_INTEGER)
 * cacheClientAddressType (InetAddressType / ASN_INTEGER)
 * Defined Types
 */

#ifndef INETADDRESSTYPE_ENUMS
#define INETADDRESSTYPE_ENUMS

#define INETADDRESSTYPE_UNKNOWN  0
#define INETADDRESSTYPE_IPV4  1
#define INETADDRESSTYPE_IPV6  2
#define INETADDRESSTYPE_IPV4Z  3
#define INETADDRESSTYPE_IPV6Z  4
#define INETADDRESSTYPE_DNS  16

#endif                          /* INETADDRESSTYPE_ENUMS */

/*
 * RFC 1905: Protocol Operations for SNMPv2
 *
 * Variable binding.
 *
 * VarBind ::=
 *   SEQUENCE {
 *     name ObjectName
 *     CHOICE {
 *       value ObjectSyntax
 *       unSpecified NULL
 *       noSuchObject[0] NULL
 *       noSuchInstance[1] NULL
 *       endOfMibView[2] NULL
 *     }
 *   }
 */
#define SMI_NOSUCHOBJECT   (ASN_CONTEXT | ASN_PRIMITIVE | 0x0) /* noSuchObject[0] */
#define SMI_NOSUCHINSTANCE (ASN_CONTEXT | ASN_PRIMITIVE | 0x1) /* noSuchInstance[1] */
#define SMI_ENDOFMIBVIEW   (ASN_CONTEXT | ASN_PRIMITIVE | 0x2) /* endOfMibView[2] */
typedef struct variable variable;
typedef struct variable_list variable_list;

#ifdef __cplusplus
}
#endif

#endif /* SQUID_SNMP_VARS_H */

