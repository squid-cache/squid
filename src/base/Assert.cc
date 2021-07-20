/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Assert.h"
#include "base/TextException.h"
#include "Debug.h"

[[ noreturn ]] void
ReportAndThrow_(const int debugLevel, const char *description, const SourceLocation &location)
{
    const TextException ex(description, location);
    debugs(0, debugLevel, "check failed: " << ex);
    throw ex;
}

