/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CONNMARKCONFIG_H
#define SQUID_CONNMARKCONFIG_H

#include "ip/forward.h"
#include "sbuf/SBuf.h"

/// a netfilter connection mark/mask pair (a.k.a. connmark)
class ConnMarkConfig
{
public:
    /// expects a "mark[/mask]" format
    static ConnMarkConfig Parse(const SBuf &token);
    /// whether the connection 'mark' matches the configured mark/mask
    bool matches(const nfmark_t mark) const { return (mark & nfmask) == nfmark; }

    nfmark_t nfmark;
    nfmark_t nfmask;
};

std::ostream &operator <<(std::ostream &os, const ConnMarkConfig connmark);

#endif // SQUID_CONNMARKCONFIG_H
