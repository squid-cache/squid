/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Assure.h"
#include "base/TextException.h"
#include "debug/Stream.h"

[[ noreturn ]] void
ReportAndThrow_(const int debugLevel, const char *description, const SourceLocation &location)
{
    const TextException ex(description, location);
    const auto label = debugLevel <= DBG_IMPORTANT ? "ERROR: Squid BUG: " : "";
    // TODO: Consider also printing the number of BUGs reported so far. It would
    // require GC, but we could even print the number of same-location reports.
    debugs(0, debugLevel, label << ex);
    throw ex;
}

