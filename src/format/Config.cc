/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "cache_cf.h"
#include "debug/Stream.h"
#include "format/Config.h"

Format::FmtConfig Format::TheConfig;

void
Format::FmtConfig::registerTokens(const SBuf &nsName, TokenTableEntry const *tokenArray)
{
    debugs(46, 2, "register format tokens for '" << nsName << "'");
    if (tokenArray)
        tokens.emplace_back(TokenNamespace(nsName, tokenArray));
    else
        debugs(0, DBG_CRITICAL, "ERROR: Squid BUG: format tokens for '" << nsName << "' missing!");
}

