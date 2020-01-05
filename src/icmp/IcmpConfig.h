/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration Settings */

#ifndef ICMPCONFIG_H
#define ICMPCONFIG_H

#if USE_ICMP

#include "cache_cf.h"
#include "sbuf/SBuf.h"

/**
 * Squid pinger Configuration settings
 */
class IcmpConfig
{
public:
    IcmpConfig() : enable(0) {}
    ~IcmpConfig() {}

    void clear() {enable=0; program.clear();}
    void parse();

    /** pinger helper application path */
    SBuf program;

    /** Whether the pinger helper is enabled for use or not */
    int enable;
};

extern IcmpConfig IcmpCfg;

/* wrappers for the legacy squid.conf parser */
#define dump_icmp(e,n,v) \
        if (!(v).program.isEmpty()) { \
            (e)->append((n), strlen((n))); \
            (e)->append(" ", 1); \
            (e)->append((v).program.rawContent(), (v).program.length()); \
            (e)->append("\n", 1); \
        } else {}
#define parse_icmp(v) (v)->parse()
#define free_icmp(x) (x)->clear()

#endif /* USE_ICMP */
#endif /* ICMPCONFIG_H */

