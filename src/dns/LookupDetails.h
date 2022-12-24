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

#include "SquidString.h"

namespace Dns
{

/// encapsulates DNS lookup results
class LookupDetails
{
public:
    LookupDetails() : wait(-1) {} ///< no error, no lookup delay (i.e., no lookup)
    LookupDetails(const String &anError, int aWait) : error(anError), wait(aWait) {}

    std::ostream &print(std::ostream &os) const;

public:
    String error; ///< error message for unsuccessful lookups; empty otherwise
    int wait; ///< msecs spent waiting for the lookup (if any) or -1 (if none)
};

} // namespace Dns

inline std::ostream &
operator <<(std::ostream &os, const Dns::LookupDetails &dns)
{
    return dns.print(os);
}

#endif /* SQUID_DNS_LOOKUPDETAILS_H */

