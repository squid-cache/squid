/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_DNS_RESOLVCONF_H
#define _SQUID_SRC_DNS_RESOLVCONF_H

#include "base/Packable.h"
#include "base/RunnersRegistry.h"
#include "sbuf/List.h"

#if HAVE_RESOLV_H
#include <resolv.h>
#endif

namespace Dns
{

/// system-wide DNS configuration from /etc/resolv.conf
class ResolvConf : public IndependentRunner
{
public:
    /// there can only be one resolv.conf configuration
    static ResolvConf &Current();

    /// (re)load settings from /etc/resolv.conf
    void load();

    void dump(Packable *);

    /* RegisteredRunner API */
    virtual void startReconfigure() override { load(); }

public:
    SBufList search;
    SBufList nameservers;

    class Options {
    public:
        /// restore resolv.conf default option values
        void clear() { *this = Options(); }

    public:
        int ndots = 0;
    } options;
};

} // namespace Dns

#endif /* _SQUID_SRC_DNS_RESOLVCONF_H */
