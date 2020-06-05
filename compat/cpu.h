/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_CPU_H
#define SQUID_COMPAT_CPU_H

#if HAVE_ERRNO_H
#include <errno.h> /* for ENOTSUP */
#endif
#if HAVE_SCHED_H
#include <sched.h>
#endif

#if !HAVE_CPU_AFFINITY
/* failing replacements to minimize the number of if-HAVE_CPU_AFFINITYs */
#if !HAVE_CPU_SET_T
typedef struct {
    int bits;
} cpu_set_t;
#endif
inline int sched_setaffinity(int, size_t, cpu_set_t *) { return ENOTSUP; }
inline int sched_getaffinity(int, size_t, cpu_set_t *) { return ENOTSUP; }
#endif /* HAVE_CPU_AFFINITY */

#if !defined(CPU_ZERO)
#define CPU_ZERO(set) (void)0
#endif

#if !defined(CPU_SET)
#define CPU_SET(cpu, set) (void)0
#endif

#endif /* SQUID_COMPAT_CPU_H */
