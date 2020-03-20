/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "cache_cf.h"
#include "cfg/Exceptions.h"
#include "ConfigParser.h"
#include "debug/Stream.h"
#include "format/Config.h"

#include <list>

Format::FmtConfig Format::TheConfig;

void
Format::FmtConfig::parseFormats()
{
    char *name = ConfigParser::NextToken();
    if (!name)
        throw Cfg::FatalError("missing format name");

    char *def = ConfigParser::NextQuotedOrToEol();

    if (!def)
        throw Cfg::FatalError("missing format specification");

    debugs(3, 2, "Custom Format for '" << name << "' is '" << def << "'");

    Format *nlf = new Format(name);
    nlf->parse(def);// XXX: throws and leaks nlf on errors

    // add to global config list
    nlf->next = formats;
    formats = nlf;
}

void
Format::FmtConfig::registerTokens(const SBuf &nsName, TokenTableEntry const *tokenArray)
{
    debugs(46, 2, "register format tokens for '" << nsName << "'");
    if (tokenArray)
        tokens.emplace_back(TokenNamespace(nsName, tokenArray));
    else
        debugs(0, DBG_CRITICAL, "ERROR: Squid BUG: format tokens for '" << nsName << "' missing!");
}

