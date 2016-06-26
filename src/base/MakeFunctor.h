/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_MAKEFUNCTOR_H
#define SQUID_BASE_MAKEFUNCTOR_H

// Macro to be used to define a C++ functor of an extern "C"
// function. The C++ functor is suffixed with the _functor extension
#define UniaryFunctor(function, argument_type) \
        struct function ## _functor { \
            void operator()(argument_type a) { function(a); } \
        }

/// DeAllocator functor for pointers that need free(3) from the std C library
UniaryFunctor(xfree, char *);

#endif // SQUID_BASE_MAKEFUNCTOR_H

