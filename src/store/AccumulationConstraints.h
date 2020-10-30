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
    void noteHardMaximum(uint64_t, const char *restrictionDescription);

    /// adjusts the given allowance using the configured hard maximum
    uint64_t applyHardMaximum(uint64_t rawAllowance) const;

    /* default values place no additional constraints */

    /// overwrites (more restrictive) read_ahead_gap-related checks
    /// (to make sure the current parser can give clients something to consume)
    size_t parserMinimum = 0;

    /// whether to skip all read_ahead_gap-related checks
    /// (because the caller context is outside that directive scope)
    bool ignoreReadAheadGap = false;

    /// whether to skip all delay_pools-related checks
    /// (because the caller context is outside that directive scope)
    bool ignoreDelayPools = false;

private:
    // When parserMinimum exceeds hardMaximum_, we ignore parserMinimum:
    // Incoming data often passes through a serious of buffers. parserMinimum is
    // based on the first (parsing) buffer, which may be empty. hardMaximum_
    // often protects the last (BodyPipe) buffer, which may be full. We cannot
    // overflow any buffer and lack code to split data between the two buffers
    // (see commit 254f393), so we stall parsing (honoring hardMaximum_) and
    // hope that, when a full buffer is drained, the caller will be notified and
    // will resume reading (hence, eventually satisfying parserMinimum).

    /// no allowance may exceed this value
    uint64_t hardMaximum_ = std::numeric_limits<uint64_t>::max();
};

std::ostream &operator <<(std::ostream &, const AccumulationConstraints &);

} // namespace Store

#endif /* SQUID_STORE_ACCUMULATION_CONSTRAINTS_H */

