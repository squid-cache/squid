/*
 * Copyright (C) 1996-2024 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MGR_ACTIONFEATURES_H
#define SQUID_SRC_MGR_ACTIONFEATURES_H

namespace Mgr
{

// Scoped enumeration declarations below solve two problems with ActionProfile
// constructor, RegisterAction(), and related function calls, making argument
// lists readable and safe:
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

} // namespace Mgr

#endif /* SQUID_SRC_MGR_ACTIONFEATURES_H */

