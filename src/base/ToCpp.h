/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef BASE_TOCPP_H
#define BASE_TOCPP_H

#ifdef __cplusplus

/// Defines a C++ equivalent of an extern "C" function.
/// The defined C++ function name uses a _cpp suffix.
#define CtoCpp1(function, argument)                     \
    extern "C++" inline void function##_cpp(argument a) \
    {                                                   \
        function(a);                                    \
    }

#endif /* __cplusplus */
#endif /* BASE_TOCPP_H */