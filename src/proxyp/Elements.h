/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PROXYP_ELEMENTS_H
#define SQUID_PROXYP_ELEMENTS_H

#include "sbuf/SBuf.h"

// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
namespace ProxyProtocol {
namespace Two {

/// numeric IDs of registered PROXY protocol TLV types and pseudo headers
typedef enum {
    htUnknown = 0x00,

    // The PROXY protocol specs list these TLV types as already registered.
    htAlpn = 0x01, // PP2_TYPE_ALPN
    htAuthority = 0x02, // PP2_TYPE_AUTHORITY
    htCrc32c = 0x03, // PP2_TYPE_CRC32C
    htNoop = 0x04, // PP2_TYPE_NOOP
    htSsl = 0x20, // PP2_TYPE_SSL
    htSslVersion = 0x21, // PP2_SUBTYPE_SSL_VERSION
    htSslCn = 0x22, // PP2_SUBTYPE_SSL_CN
    htSslCipher = 0x23, // PP2_SUBTYPE_SSL_CIPHER
    htSslSigAlg = 0x24, // PP2_SUBTYPE_SSL_SIG_ALG
    htSslKeyAlg = 0x25, // PP2_SUBTYPE_SSL_KEY_ALG
    htNetns = 0x30, // PP2_TYPE_NETNS

    // IDs for PROXY protocol header pseudo-headers.
    // Larger than 255 to avoid clashes with possible TLV type IDs.
    htPseudoBegin = 0x101, // smallest pseudo-header value (for iteration)
    htPseudoVersion,
    htPseudoCommand,
    htPseudoSrcAddr,
    htPseudoDstAddr,
    htPseudoSrcPort,
    htPseudoDstPort,
    htPseudoEnd // largest pseudo-header value plus 1 (for iteration)
} FieldType;

/// PROXY protocol 'command' field value
typedef enum {
    cmdLocal = 0x00,
    cmdProxy = 0x01
} Command;

typedef enum {
    /// corresponds to a local connection or an unsupported protocol family
    afUnspecified = 0x00,
    afInet = 0x1,
    afInet6 = 0x2,
    afUnix = 0x3
} AddressFamily;

typedef enum {
    tpUnspecified = 0x00,
    tpStream = 0x1,
    tpDgram = 0x2
} TransportProtocol;

/// a single Type-Length-Value (TLV) block from PROXY protocol specs
class Tlv
{
public:
    typedef uint8_t value_type;

    Tlv(const value_type t, const SBuf &val): value(val), type(t) {}

    SBuf value;
    value_type type;
};

} // namespace Two

/// \returns human-friendly PROXY protocol field name for the given field type
/// from the [htPseudoBegin,htPseudoEnd) range
const SBuf &PseudoFieldTypeToFieldName(const Two::FieldType);

/// Parses human-friendly PROXY protocol field type representation.
/// Only pseudo headers can (and should) be represented by their names.
Two::FieldType FieldNameToFieldType(const SBuf &nameOrId);

} // namespace ProxyProtocol

#endif

