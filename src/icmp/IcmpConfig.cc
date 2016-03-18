/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 03    Configuration Settings */

#include "squid.h"

#if USE_ICMP
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
        self_destruct();
}

#endif /* USE_ICMP */

