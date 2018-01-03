/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_TYPES_H
#define SQUID_TYPES_H

/*
 * Here are defined several known-width types, obtained via autoconf
 * from system locations or various attempts. This is just a convenience
 * header to include which takes care of proper preprocessor stuff
 *
 * This file is only intended to be included via compat/compat.h, do
 * not include directly.
 */

/* This should be in synch with what we have in acinclude.m4 */
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_LINUX_TYPES_H
#include <linux/types.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STDDEF_H
#include <stddef.h>
#endif
#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#if HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
/* Several OS require types declared by in_systm.h without including it themselves. */
#include <netinet/in_systm.h>
#endif

#if __cplusplus && HAVE_TR1_RANDOM
#if !HAVE_STD_UNIFORM_INT_DISTRIBUTION && !HAVE_STD_UNIFORM_REAL_DISTRIBUTION
#include <tr1/random>
#endif
#endif

/******************************************************/
/* Typedefs for missing entries on a system           */
/******************************************************/

/*
 * Ensure that standard type limits are defined for use
 */
#if __cplusplus >= 201103L
#include <cstdint>
#elif HAVE_STDINT_H
#include <stdint.h>
#endif

/* explicit bit sizes */
#if !defined(UINT32_MIN)
#define UINT32_MIN    0x00000000L
#endif
#if !defined(UINT32_MAX)
#define UINT32_MAX    0xFFFFFFFFL
#endif

#if !defined(INT_MAX)
#define INT_MAX    0x7FFFFFFFL // hack but a safe bet (32-bit signed integer)
#endif

#if !defined(INT64_MIN)
/* Native 64 bit system without strtoll() */
#if defined(LONG_MIN) && (SIZEOF_LONG == 8)
#define INT64_MIN    LONG_MIN
#else
/* 32 bit system */
#define INT64_MIN    (-9223372036854775807LL-1LL)
#endif
#endif

#if !defined(INT64_MAX)
/* Native 64 bit system without strtoll() */
#if defined(LONG_MAX) && (SIZEOF_LONG == 8)
#define INT64_MAX    LONG_MAX
#else
/* 32 bit system */
#define INT64_MAX    9223372036854775807LL
#endif
#endif

/*
 * ISO C99 Standard printf() macros for 64 bit integers
 * On some 64 bit platform, HP Tru64 is one, for printf must be used
 * "%lx" instead of "%llx"
 */
#ifndef PRId64
#if _SQUID_WINDOWS_
#define PRId64 "I64d"
#elif SIZEOF_INT64_T > SIZEOF_LONG
#define PRId64 "lld"
#else
#define PRId64 "ld"
#endif
#endif

#ifndef PRIu64
#if _SQUID_WINDOWS_
#define PRIu64 "I64u"
#elif SIZEOF_INT64_T > SIZEOF_LONG
#define PRIu64 "llu"
#else
#define PRIu64 "lu"
#endif
#endif

#ifndef PRIX64
#if _SQUID_WINDOWS_
#define PRIX64 "I64X"
#elif SIZEOF_INT64_T > SIZEOF_LONG
#define PRIX64 "llX"
#else
#define PRIX64 "lX"
#endif
#endif

#ifndef PRIuSIZE
// NP: configure checks for support of %zu and defines where possible
#if SIZEOF_SIZE_T == 4 && _SQUID_MINGW_
#define PRIuSIZE "I32u"
#elif SIZEOF_SIZE_T == 4
#define PRIuSIZE "u"
#elif SIZEOF_SIZE_T == 8 && _SQUID_MINGW_
#define PRIuSIZE "I64u"
#elif SIZEOF_SIZE_T == 8
#define PRIuSIZE "lu"
#else
#error size_t is not 32-bit or 64-bit
#endif
#endif /* PRIuSIZE */

#ifndef HAVE_MODE_T
typedef unsigned short mode_t;
#endif

#ifndef HAVE_FD_MASK
typedef unsigned long fd_mask;
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

#ifndef HAVE_MTYP_T
typedef long mtyp_t;
#endif

#ifndef NULL
#define NULL 0
#endif

/***********************************************************/
/* uniform_int_distribution backward compatibility wrapper */
/***********************************************************/
#if HAVE_STD_UNIFORM_INT_DISTRIBUTION
#define xuniform_int_distribution std::uniform_int_distribution
#else
#define xuniform_int_distribution std::tr1::uniform_int
#endif

#if HAVE_STD_UNIFORM_REAL_DISTRIBUTION
#define xuniform_real_distribution std::uniform_real_distribution
#else
#define xuniform_real_distribution std::tr1::uniform_real
#endif

#endif /* SQUID_TYPES_H */

