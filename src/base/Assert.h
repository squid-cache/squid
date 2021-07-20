/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_ASSERT_H
#define SQUID_SRC_BASE_ASSERT_H

#include "base/Here.h"

/// Reports the described assertion (at the given debugging level) and throws
/// the corresponding exception. Reduces compiled code size of Assert() and
/// Must() callers. Do not call directly; use Assert() instead.
/// \param description explains the condition (i.e. what MUST happen)
[[ noreturn ]] void ReportAndThrow_(int debugLevel, const char *description, const SourceLocation &);

/// Calls ReportAndThrow() if needed. Reduces caller code duplication.
/// Do not call directly; use Assert() instead.
/// \param description c-string explaining the condition (i.e. what MUST happen)
#define Assert_(debugLevel, condition, description, location) \
    while (!(condition)) \
        ReportAndThrow_((debugLevel), (description), (location))

#if !defined(NODEBUG)

/// Like assert() but throws an exception instead of aborting the process.
/// Use this macro to detect code logic mistakes (i.e. bugs) where aborting
/// the current AsyncJob or a similar task does not create a threat to the
/// Squid service integrity. For example, this macro is not appropriate for
/// detecting bugs that indicate a dangerous global state corruption that
/// may go unnoticed by other jobs after the current job or task is aborted.
#define Assert(condition) \
        Assert_(0, (condition), #condition, Here())

/// Like Assert() but allows the caller to customize the exception message.
/// \param description c-string explaining the condition (i.e. what MUST happen)
#define Assert2(condition, description) \
        Assert_(0, (condition), (description), Here())

#else

/* do-nothing implementations for NODEBUG builds */
#define Assert(condition) ((void)0)
#define Assert2(condition, description) ((void)0)

#endif /* NODEBUG */

#endif /* SQUID_SRC_BASE_ASSERT_H */

