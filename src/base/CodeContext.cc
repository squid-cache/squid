/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS code_contexts for details.
 */

#include "squid.h"
#include "base/CodeContext.h"
#include "Debug.h"

/// represents a being-forgotten CodeContext (while it may be being destroyed)
class FadingCodeContext: public CodeContext
{
public:
    /* CodeContext API */
    virtual ScopedId codeContextGist() const override { return gist; }
    virtual std::ostream &detailCodeContext(std::ostream &os) const override { return os << gist; }

    ScopedId gist; ///< identifies the being-forgotten CodeContext
};

/// guarantees the forever existence of the pointer, starting from the first use
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

/// Forgets the current known context, possibly triggering its destruction.
/// Preserves the gist of the being-forgotten context during its destruction.
/// Knows nothing about the next context -- the caller must set it.
void
CodeContext::ForgetCurrent()
{
    static const RefCount<FadingCodeContext> fadingCodeContext = new FadingCodeContext();
    auto &current = Instance();
    assert(current);
    fadingCodeContext->gist = current->codeContextGist();
    current = fadingCodeContext;
}

/// Switches the current context to the given known context. Improves debugging
/// output by replacing omni-directional "Reset" with directional "Entering".
void
CodeContext::Entering(const Pointer &codeCtx)
{
    auto &current = Instance();
    if (current)
        ForgetCurrent(); // ensure orderly closure of the old context
    current = codeCtx;
    debugs(1, 5, codeCtx->codeContextGist());
}

/// Forgets the current known context. Improves debugging output by replacing
/// omni-directional "Reset" with directional "Leaving".
void
CodeContext::Leaving()
{
    ForgetCurrent();
    auto &current = Instance();
    debugs(1, 7, *current);
    current = nullptr;
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
CurrentCodeContextDetail(std::ostream &os)
{
    if (const auto ctx = CodeContext::Current())
        ctx->detailCodeContext(os);
    return os;
}

