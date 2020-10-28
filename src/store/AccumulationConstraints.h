/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORE_ACCUMULATION_CONSTRAINTS_H
#define SQUID_STORE_ACCUMULATION_CONSTRAINTS_H

#include <iosfwd>

namespace Store {

/// whether (and how) to obey read_ahead_gap and delay_pools limits
/// store accumulation is unrelated to client_delay_pools, response_delay_pool
class AccumulationConstraints
{
public:
    /* default values place no additional constraints */

    /// overwrites (more restrictive) read_ahead_gap-related checks
    /// (to make sure the current parser can give clients something to consume)
    size_t parserMinimum = 0;

    // XXX: Use or remove.
    /// whether to skip all read_ahead_gap-related checks
    /// (because the caller context is outside that directive scope)
    bool ignoreReadAheadGap = false;

    /// whether to skip all delay_pools-related checks
    /// (because the caller context is outside that directive scope)
    bool ignoreDelayPools = false;
};

std::ostream &operator <<(std::ostream &, const AccumulationConstraints &);

} // namespace Store

#endif /* SQUID_STORE_ACCUMULATION_CONSTRAINTS_H */

