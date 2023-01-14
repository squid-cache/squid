/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 78    DNS lookups */

#ifndef SQUID_DNS_LOOKUPDETAILS_H
#define SQUID_DNS_LOOKUPDETAILS_H

#include "sbuf/SBuf.h"

#include <optional>

namespace Dns
{

/// encapsulates DNS lookup results
class LookupDetails
{
public:
    LookupDetails() : wait(-1) {} ///< no error, no lookup delay (i.e., no lookup)
    LookupDetails(const SBuf &anError, const int aWait):
        error(anError.isEmpty() ? std::nullopt : std::make_optional(anError)),
        wait(aWait)
    {}

    std::ostream &print(std::ostream &os) const;

public:
    std::optional<SBuf> error; ///< error message (if any)
    int wait; ///< msecs spent waiting for the lookup (if any) or -1 (if none)
};

} // namespace Dns

inline std::ostream &
operator <<(std::ostream &os, const Dns::LookupDetails &dns)
{
    return dns.print(os);
}

#endif /* SQUID_DNS_LOOKUPDETAILS_H */

