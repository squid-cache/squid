/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "Debug.h"

/*
 * RAII wrapper for ctx_enter / ctx_exit
 */
class DebugContext {
    Ctx context_;
    public:
    DebugContext(const char *descr) {
        context_ = ctx_enter(descr);
    };
    ~DebugContext() {
        ctx_exit(context_);
    }
};
