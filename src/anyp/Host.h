/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ANYP_HOST_H
#define SQUID_SRC_ANYP_HOST_H

#include "dns/forward.h"
#include "ip/Address.h"
#include "sbuf/SBuf.h"

#include <iosfwd>
#include <optional>
#include <variant>

namespace AnyP
{

/// either a domain name (as defined in DNS RFC 1034) or an IP address
class Host
{
public:
    /// converts an already parsed IP address to a Host object
    static std::optional<Host> ParseIp(const Ip::Address &);

    /// Parses input as a literal ASCII domain name (A-labels OK; see RFC 5890).
    /// Does not allow wildcards; \sa ParseWildDomainName().
    static std::optional<Host> ParseSimpleDomainName(const SBuf &);

    /// Same as ParseSimpleDomainName() but allows the first label to be a
    /// wildcard (RFC 9525 Section 6.3).
    static std::optional<Host> ParseWildDomainName(const SBuf &);

    // Accessor methods below are mutually exclusive: Exactly one method is
    // guaranteed to return a result other than std::nullopt.

    /// stored IPv or IPv6 address (if any)
    ///
    /// Ip::Address::isNoAddr() may be true for the returned address.
    /// Ip::Address::isAnyAddr() may be true for the returned address.
    auto ip() const { return std::get_if<Ip::Address>(&raw_); }

    /// stored domain name (if any)
    auto domainName() const { return std::get_if<SBuf>(&raw_); }

private:
    using Storage = std::variant<Ip::Address, Dns::DomainName>;

    static std::optional<Host> ParseDomainName(const SBuf &);

    // use a Parse*() function to create Host objects
    Host(const Storage &raw): raw_(raw) {}

    Storage raw_; ///< the host we are providing access to
};

/// helps print Host value in RFC 3986 Section 3.2.2 format, with square
/// brackets around an IPv6 address (if the Host value is an IPv6 address)
class Bracketed
{
public:
    explicit Bracketed(const Host &aHost): host(aHost) {}
    const Host &host;
};

/// prints Host value _without_ square brackets around an IPv6 address (even
/// when the Host value is an IPv6 address); \sa Bracketed
std::ostream &operator <<(std::ostream &, const Host &);

/// prints Host value _without_ square brackets around an IPv6 address (even
/// when the Host value is an IPv6 address); \sa Bracketed
std::ostream &operator <<(std::ostream &, const Bracketed &);

} // namespace Anyp

#endif /* SQUID_SRC_ANYP_HOST_H */

