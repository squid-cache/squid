/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_TOCPP_H
#define SQUID_SRC_BASE_TOCPP_H

/// Defines a C++ equivalent of an extern "C" function.
/// The defined C++ function name uses a _cpp suffix.
#define CtoCpp1(function, argument)                     \
    extern "C++" inline void function##_cpp(argument a) \
    {                                                   \
        function(a);                                    \
    }

#endif /* SQUID_SRC_BASE_TOCPP_H */

