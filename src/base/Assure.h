/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_ASSURE_H
#define SQUID_SRC_BASE_ASSURE_H

#include "base/Here.h"

/// Reports the description (at the given debugging level) and throws
/// the corresponding exception. Reduces compiled code size of Assure() and
/// Must() callers. Do not call directly; use Assure() instead.
/// \param description explains the condition (i.e. what MUST happen)
[[ noreturn ]] void ReportAndThrow_(int debugLevel, const char *description, const SourceLocation &);

/// Calls ReportAndThrow() if needed. Reduces caller code duplication.
/// Do not call directly; use Assure() instead.
/// \param description c-string explaining the condition (i.e. what MUST happen)
#define Assure_(debugLevel, condition, description, location) \
    while (!(condition)) \
        ReportAndThrow_((debugLevel), (description), (location))

#if !defined(NDEBUG)

/// Like assert() but throws an exception instead of aborting the process. Use
/// this macro to detect code logic mistakes (i.e. bugs) where aborting the
/// current AsyncJob or a similar task is unlikely to jeopardize Squid service
/// integrity. For example, this macro is _not_ appropriate for detecting bugs
/// that indicate a dangerous global state corruption which may go unnoticed by
/// other jobs after the current job or task is aborted.
#define Assure(condition) \
        Assure2((condition), #condition)

/// Like Assure() but allows the caller to customize the exception message.
/// \param description string literal describing the condition (i.e. what MUST happen)
#define Assure2(condition, description) \
        Assure_(0, (condition), ("assurance failed: " description), Here())

#else

/* do-nothing implementations for NDEBUG builds */
#define Assure(condition) ((void)0)
#define Assure2(condition, description) ((void)0)

#endif /* NDEBUG */

#endif /* SQUID_SRC_BASE_ASSURE_H */

