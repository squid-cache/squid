/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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

    if (!(name = ConfigParser::NextToken())) {
        debugs(3, DBG_CRITICAL, "FATAL: missing logformat details in " << cfg_filename << " line " << config_lineno);
        self_destruct();
        return;
    }

    // check for re-definition of built-in formats
    if (strcmp(name, "squid") == 0 ||
            strcmp(name, "common") == 0 ||
            strcmp(name, "combined") == 0 ||
            strcmp(name, "useragent") == 0 ||
            strcmp(name, "referrer") == 0) {
        debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: logformat " << name << " is already defined. Ignoring.");
        return;
    }

    // check for re-definition of custom formats
    for (auto i = logformats; i ; i = i->next) {
        if (strcmp(i->name, name) == 0) {
            debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: logformat " << name << " is already defined. Ignoring.");
            return;
        }
    }

    ::Format::Format *nlf = new ::Format::Format(name);

    ConfigParser::EnableMacros();
    if (!(def = ConfigParser::NextQuotedOrToEol())) {
        delete nlf;
        self_destruct();
        return;
    }
    ConfigParser::DisableMacros();

    debugs(3, 2, "Log Format for '" << name << "' is '" << def << "'");

    if (!nlf->parse(def)) {
        delete nlf;
        self_destruct();
        return;
    }

    // add to global config list
    nlf->next = logformats;
    logformats = nlf;
}

