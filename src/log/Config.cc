/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "log/Config.h"

Log::LogConfig Log::TheConfig;

void
Log::LogConfig::parseFormats()
{
    char *name, *def;

    if ((name = ConfigParser::NextToken()) == NULL)
        self_destruct();

    ::Format::Format *nlf = new ::Format::Format(name);

    ConfigParser::EnableMacros();
    if ((def = ConfigParser::NextQuotedOrToEol()) == NULL) {
        self_destruct();
        return;
    }
    ConfigParser::DisableMacros();

    debugs(3, 2, "Log Format for '" << name << "' is '" << def << "'");

    if (!nlf->parse(def)) {
        self_destruct();
        return;
    }

    // add to global config list
    nlf->next = logformats;
    logformats = nlf;
}

