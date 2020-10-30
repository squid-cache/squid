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
#include <limits>

namespace Store {

/// whether (and how) to obey read_ahead_gap and delay_pools limits
/// store accumulation is unrelated to client_delay_pools, response_delay_pool
class AccumulationConstraints
{
public:
    /// no allowance may exceed the given maximum; may be called many times
    /// \param reason why the given maximum should be enforced (for debugging)
    void enforceHardMaximum(uint64_t maximum, const char *reason);

    /// honor read_ahead_gap configuration, given the current read-ahead gap
    void enforceReadAheadLimit(int64_t currentGap);

    /// overwrites (more restrictive) read_ahead_gap-related checks
    /// (to make sure the current parser can give clients something to consume)
    void enforceParserProgress(size_t bytesBuffered, size_t lookAheadMinimum);

    /// the maximum number of new bytes that still meet accumulation constraints
    uint64_t allowance() const { return allowance_; }

    /* the default values place no constraints */

    /// whether to skip all read_ahead_gap-related checks
    /// (because the caller context is outside that directive scope)
    bool ignoreReadAheadGap = false;

    /// whether to skip all delay_pools-related checks
    /// (because the caller context is outside that directive scope)
    bool ignoreDelayPools = false;

private:
    /// the minimum number of bytes required for the parser to make progress
    size_t parserMinimum_ = 0;

    /// the current/cached allowance() value
    uint64_t allowance_ = std::numeric_limits<uint64_t>::max();
};

std::ostream &operator <<(std::ostream &, const AccumulationConstraints &);

} // namespace Store

#endif /* SQUID_STORE_ACCUMULATION_CONSTRAINTS_H */

