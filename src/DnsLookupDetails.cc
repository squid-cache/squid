/*
 * DEBUG: section 78    DNS lookups
 */

#include "squid.h"
#include "DnsLookupDetails.h"

DnsLookupDetails::DnsLookupDetails(): wait(-1)
{
}

DnsLookupDetails::DnsLookupDetails(const String &e, int w):
        error(e), wait(w)
{
}

std::ostream &
DnsLookupDetails::print(std::ostream &os) const
{
    if (wait > 0)
        os << "lookup_wait=" << wait;
    if (error.size())
        os << " lookup_err=" << error;
    return os;
}
