/*
 * DEBUG: section 78    DNS lookups
 */

#ifndef SQUID_DNS_LOOKUP_DETAILS_H
#define SQUID_DNS_LOOKUP_DETAILS_H

#include "typedefs.h"
#include "SquidString.h"

/// encapsulates DNS lookup results
class DnsLookupDetails
{
public:
    DnsLookupDetails(); ///< no error, no lookup delay (i.e., no lookup)
    DnsLookupDetails(const String &error, int wait);

    std::ostream &print(std::ostream &os) const;

public:
    String error; ///< error message for unsuccessdul lookups; empty otherwise
    int wait; ///< msecs spent waiting for the lookup (if any) or -1 (if none)
};

inline
std::ostream &operator << (std::ostream &os, const DnsLookupDetails &dns)
{
    return dns.print(os);
}

#endif
