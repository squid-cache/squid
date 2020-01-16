/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 78    DNS lookups */

#include "squid.h"
#include "dns/LookupDetails.h"

std::ostream &
Dns::LookupDetails::print(std::ostream &os) const
{
    if (wait > 0)
        os << "lookup_wait=" << wait;
    if (error.size())
        os << " lookup_err=" << error;
    return os;
}

