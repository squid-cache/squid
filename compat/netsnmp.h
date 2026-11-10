/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_NETSNMP_H
#define SQUID_COMPAT_NETSNMP_H

#if SQUID_SNMP

#define NET_SNMP_CONFIG_H 1
#define NETSNMP_ATTRIBUTE_DEPRECATED /*[[deprecated]]*/

#if defined(__cplusplus)
#define NETSNMP_IMPORT extern "C"
#else
#define NETSNMP_IMPORT extern
#endif

#if HAVE_NET_SNMP_TYPES_H
#include <net-snmp/types.h>
#if defined(FREE) && FREE == 4
#undef FREE
#endif

/*************************************************************
 * RFC 1902 constants for enums for the MIB node
 * tcpListenerLocalAddressType (InetAddressType / ASN_INTEGER)
 *
 * since a Textual Convention may be referenced more than once in a
 * MIB, protect againt redefinitions of the enum values.
 */
#ifndef INETADDRESSTYPE_ENUMS
#define INETADDRESSTYPE_ENUMS

#define INETADDRESSTYPE_UNKNOWN  0
#define INETADDRESSTYPE_IPV4  1
#define INETADDRESSTYPE_IPV6  2
#define INETADDRESSTYPE_IPV4Z  3
#define INETADDRESSTYPE_IPV6Z  4
#define INETADDRESSTYPE_DNS  16

#endif /* INETADDRESSTYPE_ENUMS */
#endif /* HAVE_NET_SNMP_TYPES_H */
#endif /* SQUID_SNMP */
#endif /* SQUID_COMPAT_NETSNMP_H */
