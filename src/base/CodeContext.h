/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS code_contexts for details.
 */

#ifndef SQUID_BASE_CODE_CONTEXT_H
#define SQUID_BASE_CODE_CONTEXT_H

#include "base/InstanceId.h"
#include "base/RefCount.h"
#include "base/Stopwatch.h"

#include <iosfwd>

/** \file
 *
 * Most error-reporting code cannot know what transaction or task Squid was
 * working on when the error occurred. For example, when Squid HTTP request
 * parser discovers a malformed header field, the parser can report the field
 * contents, but that information is often useless for the admin without
 * processing context details like which client sent the request or what the
 * requested URL was. Moreover, even when the error reporting code does have
 * access to some context details, it cannot separate important facts from noise
 * because such classification is usually deployment-specific (i.e. cannot be
 * hard-coded) and requires human expertise. The situation is aggravated by a
 * busy Squid instance constantly switching from one processing context to
 * another.
 *
 * To solve these problems, Squid assigns a CodeContext object to a processing
 * context. When Squid switches to another processing context, it switches the
 * current CodeContext object as well. When Squid prints a level-0 or level-1
 * message to cache.log, it asks the current CodeContext object (if any) to
 * report context details, allowing the admin to correlate the cache.log message
 * with an access.log record.
 *
 * Squid also reports processing context changes to cache.log when Squid
 * level-5+ debugging is enabled.
 *
 * CodeContext is being retrofitted into existing code with lots of places that
 * switch processing context. Identifying and adjusting all those places takes
 * time. Until then, there will be incorrect and missing context attributions.
 *
 * @{
 **/

/// Interface for reporting what Squid code is working on.
/// Such reports are usually requested outside creator's call stack.
/// They are especially useful for attributing low-level errors to transactions.
class CodeContext: public RefCountable
{
public:
    typedef RefCount<CodeContext> Pointer;

    /// \returns the known global context or, to indicate unknown context, nil
    static const Pointer &Current();

    /// forgets the current context, setting it to nil/unknown
    static void Reset();

    /// changes the current context; nil argument sets it to nil/unknown
    static void Reset(const Pointer);

    ~CodeContext() override {}

    /// \returns a small, permanent ID of the current context
    /// gists persist forever and are suitable for passing to other SMP workers
    virtual ScopedId codeContextGist() const = 0;

    /// appends human-friendly context description line(s) to a cache.log record
    virtual std::ostream &detailCodeContext(std::ostream &os) const = 0;

    /// time spent in this context (see also: %busy_time)
    Stopwatch busyTime;

private:
    static void ForgetCurrent();
    static void Entering(const Pointer &codeCtx);
    static void Leaving();
};

/// by default, only small context gist is printed
inline
std::ostream &operator <<(std::ostream &os, const CodeContext &ctx)
{
    return os << ctx.codeContextGist();
}

/* convenience context-reporting wrappers that also reduce linking problems */
std::ostream &CurrentCodeContextBrief(std::ostream &os);
std::ostream &CurrentCodeContextDetail(std::ostream &os);

/// Convenience class that automatically restores the current/outer CodeContext
/// when leaving the scope of the new-context following/inner code. \see Run().
class CodeContextGuard
{
public:
    CodeContextGuard(const CodeContext::Pointer &newContext): savedCodeContext(CodeContext::Current()) { CodeContext::Reset(newContext); }
    ~CodeContextGuard() { CodeContext::Reset(savedCodeContext); }

    // no copying of any kind (for simplicity and to prevent accidental copies)
    CodeContextGuard(CodeContextGuard &&) = delete;

    CodeContext::Pointer savedCodeContext;
};

/// Executes service `callback` in `callbackContext`. If an exception occurs,
/// the callback context is preserved, so that the exception is associated with
/// the callback that triggered them (rather than with the service).
///
/// Service code running in its own service context should use this function.
template <typename Fun>
inline void
CallBack(const CodeContext::Pointer &callbackContext, Fun &&callback)
{
    // TODO: Consider catching exceptions and letting CodeContext handle them.
    const auto savedCodeContext(CodeContext::Current());
    CodeContext::Reset(callbackContext);
    callback();
    CodeContext::Reset(savedCodeContext);
}

/// Executes `service` in `serviceContext` but due to automatic caller context
/// restoration, service exceptions are associated with the caller that suffered
/// from (and/or caused) them (rather than with the service itself).
///
/// Service code running in caller's context should use this function to escape
/// into service context (e.g., for submitting caller-agnostic requests).
template <typename Fun>
inline void
CallService(const CodeContext::Pointer &serviceContext, Fun &&service)
{
    // TODO: Consider catching exceptions and letting CodeContext handle them.
    CodeContextGuard guard(serviceContext);
    service();
}

/// Executes context `creator` in the service context. If an exception occurs,
/// the creator context is preserved, so that the exception is associated with
/// the creator that triggered them (rather than with the service).
///
/// Service code running in its own context should use this function to create
/// new code contexts. TODO: Use or, if this pattern is not repeated, remove.
template <typename Fun>
inline void
CallContextCreator(Fun &&creator)
{
    const auto savedCodeContext(CodeContext::Current());
    creator();
    CodeContext::Reset(savedCodeContext);
}

/// @}

#endif

