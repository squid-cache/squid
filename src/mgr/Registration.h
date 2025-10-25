/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_SRC_MGR_REGISTRATION_H
#define SQUID_SRC_MGR_REGISTRATION_H

#include "mgr/ActionFeatures.h"
#include "mgr/forward.h"

namespace Mgr
{

/// Creates a function-based action profile and adds it to the cache manager
/// collection (once across all calls with the same action name).
void RegisterAction(char const * action, char const * desc,
                    OBJH * handler,
                    Protected, Atomic, Format);

/// wrapper for legacy Format-unaware function-based action registration code
inline void
RegisterAction(const char * const action, const char * const desc,
               OBJH * handler,
               int pw_req_flag, int atomic)
{
    return RegisterAction(action, desc, handler,
                          (pw_req_flag ? Protected::yes : Protected::no),
                          (atomic ? Atomic::yes : Atomic::no),
                          Format::informal);
}

/// Creates a class-based action profile and adds it to the cache manager
/// collection (once across all calls with the same action name).
void RegisterAction(char const * action, char const * desc,
                    ClassActionCreationHandler *handler,
                    Protected, Atomic, Format);

/// wrapper for legacy Format-unaware class-based action registration code
inline void
RegisterAction(const char * const action, const char * const desc,
               ClassActionCreationHandler *handler,
               int pw_req_flag, int atomic)
{
    return RegisterAction(action, desc, handler,
                          (pw_req_flag ? Protected::yes : Protected::no),
                          (atomic ? Atomic::yes : Atomic::no),
                          Format::informal);
}

} // namespace Mgr

#endif /* SQUID_SRC_MGR_REGISTRATION_H */

