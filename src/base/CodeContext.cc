/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS code_contexts for details.
 */

#include "squid.h"
#include "base/CodeContext.h"
#include "Debug.h"

/// guarantees forever pointer existence starting from the first use
static CodeContext::Pointer &
Instance()
{
    static const auto Instance = new CodeContext::Pointer(nullptr);
    return *Instance;
}

const CodeContext::Pointer &
CodeContext::Current()
{
    return Instance();
}

/// Switches the current context to the given known context. Improves debugging
/// output by replacing omni-directional "Reset" with directional "Entering".
void
CodeContext::Entering(const Pointer &codeCtx)
{
    Instance() = codeCtx;
    debugs(1, 5, CurrentCodeContextBrief);
}

/// Forgets the current known context. Improves debugging output by replacing
/// omni-directional "Reset" with directional "Leaving".
void
CodeContext::Leaving()
{
    debugs(1, 7, CurrentCodeContextBrief);
    Instance() = nullptr;
}

void
CodeContext::Reset()
{
    if (Instance())
        Leaving();
}

void
CodeContext::Reset(const Pointer codeCtx)
{
    if (codeCtx == Current())
        return; // context has not actually changed

    if (!codeCtx)
        return Leaving();

    Entering(codeCtx);
}

std::ostream &
CurrentCodeContextBrief(std::ostream &os)
{
    if (const auto ctx = CodeContext::Current())
        ctx->briefCodeContext(os);
    return os;
}

std::ostream &
CurrentCodeContextDetail(std::ostream &os)
{
    if (const auto ctx = CodeContext::Current())
        ctx->detailCodeContext(os);
    return os;
}

