/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_CPU_H
#define SQUID_COMPAT_CPU_H

#if HAVE_CPU_AFFINITY

#if HAVE_SCHED_H
#include <sched.h>
#endif

// glibc prior to 2.6 lacks CPU_COUNT
#ifndef CPU_COUNT
#define CPU_COUNT(set) CpuCount(set)
/// CPU_COUNT replacement
inline int
CpuCount(const cpu_set_t *set)
{
    int count = 0;
    for (int i = 0; i < CPU_SETSIZE; ++i) {
        if (CPU_ISSET(i, set))
            ++count;
    }
    return count;
}
#endif /* CPU_COUNT */

// glibc prior to 2.7 lacks CPU_AND
#ifndef CPU_AND
#define CPU_AND(destset, srcset1, srcset2) CpuAnd((destset), (srcset1), (srcset2))
/// CPU_AND replacement
inline void
CpuAnd(cpu_set_t *destset, const cpu_set_t *srcset1, const cpu_set_t *srcset2)
{
    for (int i = 0; i < CPU_SETSIZE; ++i) {
        if (CPU_ISSET(i, srcset1) && CPU_ISSET(i, srcset2))
            CPU_SET(i, destset);
        else
            CPU_CLR(i, destset);
    }
}
#endif /* CPU_AND */

#else /* HAVE_CPU_AFFINITY */

#if HAVE_ERRNO_H
#include <errno.h> /* for ENOTSUP */
#endif

/* failing replacements to minimize the number of if-HAVE_CPU_AFFINITYs */
typedef struct {
    int bits;
} cpu_set_t;
#define CPU_SETSIZE 0
#define CPU_COUNT(set) 0
#define CPU_AND(destset, srcset1, srcset2) (void)0
#define CPU_ZERO(set) (void)0
#define CPU_SET(cpu, set) (void)0
#define CPU_CLR(cpu, set) (void)0
inline int sched_setaffinity(int, size_t, cpu_set_t *) { return ENOTSUP; }
inline int sched_getaffinity(int, size_t, cpu_set_t *) { return ENOTSUP; }

#endif /* HAVE_CPU_AFFINITY */

#endif /* SQUID_COMPAT_CPU_H */

