/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration Settings */

#include "squid.h"

#if USE_ICMP
#include "cfg/Exceptions.h"
#include "ConfigParser.h"
#include "IcmpConfig.h"

IcmpConfig IcmpCfg;

void
IcmpConfig::parse()
{
    if (char *token = ConfigParser::NextQuotedOrToEol()) {
        program.clear();
        program.append(token);
    } else
        throw Cfg::FatalError("missing ICMP helper parameter");
}

#endif /* USE_ICMP */

