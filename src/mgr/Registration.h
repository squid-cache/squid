/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_SRC_MGR_REGISTRATION_H
#define SQUID_SRC_MGR_REGISTRATION_H

#include "mgr/forward.h"

namespace Mgr
{

// Scoped enumeration declarations below solve two problems with ActionProfile
// constructor and related RegisterAction() function calls, making long argument
// lists both readable and safe:
// 1. They eliminate dangerous guessing of f(..., 0, 1, false) meaning by
//    converting each anonymous constant into a named one (e.g., Atomic::no).
// 2. They prevent accidental argument reordering by prohibiting implicit value
//    casts (e.g., both f(1, false) and f(false, 1) would otherwise compile).

/// whether default cachemgr_passwd configuration denies the Action
enum class Protected { no, yes };

/// whether Action::dump() writes the entire report before returning
enum class Atomic { no, yes };

/// whether Action report uses valid YAML or unspecified/legacy formatting
enum class Format { informal, yaml };

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

