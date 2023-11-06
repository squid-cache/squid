/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_VALGRIND_H
#define SQUID_VALGRIND_H

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

/*
 * valgrind debug support
 */
#if WITH_VALGRIND
# include <valgrind/memcheck.h>
/* A little glue for older valgrind version prior to 3.2.0 */
# ifndef VALGRIND_MAKE_MEM_NOACCESS
#  define VALGRIND_MAKE_MEM_NOACCESS VALGRIND_MAKE_NOACCESS
#  define VALGRIND_MAKE_MEM_UNDEFINED VALGRIND_MAKE_WRITABLE
#  define VALGRIND_MAKE_MEM_DEFINED VALGRIND_MAKE_READABLE
#  define VALGRIND_CHECK_MEM_IS_ADDRESSABLE VALGRIND_CHECK_WRITABLE
# else
#  undef VALGRIND_MAKE_NOACCESS
#  undef VALGRIND_MAKE_WRITABLE
#  undef VALGRIND_MAKE_READABLE
# endif
#else
# define VALGRIND_MAKE_MEM_NOACCESS(a,b) (0)
# define VALGRIND_MAKE_MEM_UNDEFINED(a,b) (0)
# define VALGRIND_MAKE_MEM_DEFINED(a,b) (0)
# define VALGRIND_CHECK_MEM_IS_ADDRESSABLE(a,b) (0)
# define VALGRIND_CHECK_MEM_IS_DEFINED(a,b) (0)
# define VALGRIND_MALLOCLIKE_BLOCK(a,b,c,d)
# define VALGRIND_FREELIKE_BLOCK(a,b)
# define RUNNING_ON_VALGRIND 0
#endif /* WITH_VALGRIND */

#endif /* SQUID_CONFIG_H */

