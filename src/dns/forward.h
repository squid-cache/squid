/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_DNS_FORWARD_H
#define SQUID_SRC_DNS_FORWARD_H

#include "ip/forward.h"
#include "sbuf/forward.h"

class rfc1035_rr;

typedef void IDNSCB(void *cbdata, const rfc1035_rr *answer, const int recordsInAnswer, const char *error, bool lastAnswer);

/// generic DNS API
namespace Dns
{

class LookupDetails;

void Init(void);

/// A DNS domain name as described in RFC 1034 and RFC 1035.
///
/// The object creator is responsible for removing any encodings (e.g., URI
/// percent-encoding) other than ASCII Compatible Encoding (ACE; RFC 5890) prior
/// to creating a DomainName object. Domain names are stored as dot-separated
/// ASCII substrings, with each substring representing a domain name label.
/// DomainName strings are suitable for creating DNS queries and byte-by-byte
/// case-insensitive comparison with configured dstdomain ACL parameters.
///
/// Even though an empty domain name is valid in DNS, DomainName objects are
/// never empty.
///
/// The first label of a DomainName object may be a "*" wildcard (RFC 9525
/// Section 6.3) if and only if the object creator explicitly allows wildcards.
using DomainName = SBuf;

} // namespace Dns

// internal DNS client API
void idnsALookup(const char *, IDNSCB *, void *);
void idnsPTRLookup(const Ip::Address &, IDNSCB *, void *);

#endif /* SQUID_SRC_DNS_FORWARD_H */

