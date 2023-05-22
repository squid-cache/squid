/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "log/Config.h"

Log::LogConfig Log::TheConfig;

const char *
Log::LogConfig::BuiltInFormatName(const Format::log_type logformatType)
{
    switch (logformatType) {
    case Format::CLF_UNKNOWN:
    case Format::CLF_NONE:
    case Format::CLF_CUSTOM:
        return nullptr; // the above types are not built-in

    case Format::CLF_SQUID:
        return "squid";

    case Format::CLF_COMBINED:
        return "combined";

    case Format::CLF_COMMON:
        return "common";

#if ICAP_CLIENT
    case Format::CLF_ICAP_SQUID:
        return "icap_squid";
#endif

    case Format::CLF_USERAGENT:
        return "useragent";

    case Log::Format::CLF_REFERER:
        return "referrer";
    }

    // forgotten (by developers) type, invalid type, or unreachable code
    return nullptr;
}

Log::Format::log_type
Log::LogConfig::FindBuiltInFormat(const char *logformatName)
{
    assert(logformatName);

    if (strcmp(logformatName, "auto") == 0) {
        debugs(0, DBG_CRITICAL, "WARNING: Log format 'auto' no longer exists. Using 'squid' instead.");
        return Format::CLF_SQUID;
    }

    if (strcmp(logformatName, "squid") == 0)
        return Format::CLF_SQUID;

    if (strcmp(logformatName, "common") == 0)
        return Format::CLF_COMMON;

    if (strcmp(logformatName, "combined") == 0)
        return Format::CLF_COMBINED;

#if ICAP_CLIENT
    if (strcmp(logformatName, "icap_squid") == 0)
        return Format::CLF_ICAP_SQUID;
#endif

    if (strcmp(logformatName, "useragent") == 0)
        return Format::CLF_USERAGENT;

    if (strcmp(logformatName, "referrer") == 0)
        return Format::CLF_REFERER;

    // CLF_NONE, CLF_UNKNOWN, CLF_CUSTOM types cannot be specified explicitly.
    // TODO: Ban "none" and "unknown" custom logformat names to avoid confusion.
    return Format::CLF_UNKNOWN;
}

Format::Format *
Log::LogConfig::findCustomFormat(const char *logformatName) const
{
    assert(logformatName);
    for (auto i = logformats; i ; i = i->next) {
        if (strcmp(i->name, logformatName) == 0)
            return i;
    }
    return nullptr;
}

bool
Log::LogConfig::knownFormat(const char *logformatName) const
{
    return FindBuiltInFormat(logformatName) || findCustomFormat(logformatName);
}

void
Log::LogConfig::parseFormats()
{
    char *name, *def;

    if (!(name = ConfigParser::NextToken())) {
        debugs(3, DBG_CRITICAL, "FATAL: missing logformat details in " << cfg_filename << " line " << config_lineno);
        self_destruct();
        return;
    }

    if (FindBuiltInFormat(name)) {
        debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: logformat " << name << " is a built-in format. Ignoring redefinition attempt.");
        return;
    }

    if (findCustomFormat(name)) {
        debugs(3, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: logformat " << name << " is already defined. Ignoring redefinition attempt.");
        return;
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

