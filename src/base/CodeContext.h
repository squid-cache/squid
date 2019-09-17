/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS code_contexts for details.
 */

#ifndef SQUID_BASE_CODE_CONTEXT_H
#define SQUID_BASE_CODE_CONTEXT_H

#include "base/RefCount.h"

#include <iosfwd>

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

    virtual ~CodeContext() {}

    /// writes a word or two to help identify code context in debug messages
    virtual std::ostream &briefCodeContext(std::ostream &os) const = 0;

    /// appends human-friendly context description line(s) to a cache.log record
    virtual std::ostream &detailCodeContext(std::ostream &os) const = 0;
};

/* convenience context-reporting wrappers that also reduce linking problems */
std::ostream &CurrentCodeContextBrief(std::ostream &os);
std::ostream &CurrentCodeContextDetail(std::ostream &os);

#endif

