/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ANYP_URISCHEME_H
#define SQUID_ANYP_URISCHEME_H

#include "anyp/ProtocolType.h"

#include <iosfwd>

namespace AnyP
{

/** This class represents a URI Scheme such as http:// https://, wais://, urn: etc.
 * It does not represent the PROTOCOL that such schemes refer to.
 */
class UriScheme
{
public:
    UriScheme() : theScheme_(AnyP::PROTO_NONE) {}
    UriScheme(AnyP::ProtocolType const aScheme) : theScheme_(aScheme) {}
    ~UriScheme() {}

    operator AnyP::ProtocolType() const { return theScheme_; }

    bool operator != (AnyP::ProtocolType const & aProtocol) const { return theScheme_ != aProtocol; }

    /** Get a char string representation of the scheme.
     * Does not include the ':' or '://" terminators.
     *
     * An upper bound length of BUFSIZ bytes converted. Remainder will be truncated.
     * The result of this call will remain usable only until any subsequest call
     * and must be copied if persistence is needed.
     */
    char const *c_str() const;

private:
    /// This is a typecode pointer into the enum/registry of protocols handled.
    AnyP::ProtocolType theScheme_;
};

} // namespace AnyP

inline std::ostream &
operator << (std::ostream &os, AnyP::UriScheme const &scheme)
{
    os << scheme.c_str();
    return os;
}

#endif /* SQUID_ANYP_URISCHEME_H */

