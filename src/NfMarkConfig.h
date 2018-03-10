/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_NFMARKCONFIG_H
#define SQUID_NFMARKCONFIG_H

#include "ip/forward.h"

class SBuf;

/// a netfilter mark/mask pair
class NfMarkConfig
{
public:
    /// parses a token and returns an object, expects a "mark[/mask]" format
    static NfMarkConfig Parse(const SBuf &token);
    /// whether the 'm' matches the configured mark/mask
    bool matches(const nfmark_t m) const { return (m & mask) == mark; }
    /// returns an empty configuration
    static NfMarkConfig Empty() { return {0, 0xffffffff}; }
    /// whether the netfilter mark is unset
    bool isEmpty() const { return mark == 0; }
    /// whether the mask is set
    bool hasMask() const { return mask != 0xffffffff; }

    nfmark_t mark;
    nfmark_t mask;
};

std::ostream &operator <<(std::ostream &os, const NfMarkConfig connmark);

#endif // SQUID_NFMARKCONFIG_H
