/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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
    /// no lookup attempt: no error and no lookup delay
    LookupDetails(): wait(-1) {}

    /// details a possible lookup attempt
    /// \param anError either a failed attempt error message or an empty string
    /// \param aWait \copydoc wait
    LookupDetails(const SBuf &anError, const int aWait):
        error(anError.isEmpty() ? std::nullopt : std::make_optional(anError)),
        wait(aWait)
    {}

    std::ostream &print(std::ostream &os) const;

public:
    const std::optional<SBuf> error; ///< error message (if any)
    int wait; ///< msecs spent waiting for the lookup (if any) or -1 (if none)
};

inline std::ostream &
operator <<(std::ostream &os, const LookupDetails &dns)
{
    return dns.print(os);
}

} // namespace Dns

#endif /* SQUID_DNS_LOOKUPDETAILS_H */

