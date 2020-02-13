/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_NFMARKCONFIG_H
#define SQUID_NFMARKCONFIG_H

#include "ip/forward.h"

class SBuf;

namespace Ip
{

/// a netfilter mark/mask pair
class NfMarkConfig
{
public:
    /// creates an empty object
    NfMarkConfig() {}
    /// creates an object with specified mark and mask
    NfMarkConfig(nfmark_t mark_val, nfmark_t mask_val): mark(mark_val), mask(mask_val) {}

    /// parses a token and returns an object, expects a "mark[/mask]" format
    static NfMarkConfig Parse(const SBuf &token);
    /// whether the 'm' matches the configured mark/mask
    bool matches(const nfmark_t m) const { return (m & mask) == mark; }
    /// whether the netfilter mark is unset
    bool isEmpty() const { return mark == 0; }
    /// whether the mask is set
    bool hasMask() const { return mask != 0xffffffff; }
    /// Applies configured mark/mask to previously set mark (m).
    /// m is ANDed with the negated mask and then ORed with the configured mark.
    /// \returns new mark. This is similar to what iptables --set-mark does.
    nfmark_t applyToMark(nfmark_t m) const;

    nfmark_t mark = 0;
    nfmark_t mask = 0xffffffff;
};

} // namespace Ip

std::ostream &operator <<(std::ostream &os, const Ip::NfMarkConfig connmark);

#endif // SQUID_NFMARKCONFIG_H

