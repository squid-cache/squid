/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_PRECOMPUTEDCODECONTEXT_H
#define SQUID_SRC_BASE_PRECOMPUTEDCODECONTEXT_H

#include "base/CodeContext.h"
#include "base/InstanceId.h"
#include "sbuf/SBuf.h"

#include <ostream>

/// CodeContext with constant details known at construction time
class PrecomputedCodeContext: public CodeContext
{
public:
    typedef RefCount<PrecomputedCodeContext> Pointer;

    PrecomputedCodeContext(const char *gist, const SBuf &detail): gist_(gist), detail_(detail)
    {}

    /* CodeContext API */
    ScopedId codeContextGist() const override { return ScopedId(gist_); }
    std::ostream &detailCodeContext(std::ostream &os) const override { return os << Debug::Extra << detail_; }

private:
    const char *gist_; ///< the id used in codeContextGist()
    const SBuf detail_; ///< the detail used in detailCodeContext()
};

#endif /* SQUID_SRC_BASE_PRECOMPUTEDCODECONTEXT_H */

