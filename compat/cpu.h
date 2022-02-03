/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_CPU_H
#define SQUID_COMPAT_CPU_H

#if HAVE_SCHED_H
#include <sched.h>
#endif

#if HAVE_STDBOOL_H
#include <stdbool.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_CPUSET_H
#include <sys/cpuset.h>
#endif

#if !HAVE_CPU_SET_T
#if HAVE_CPUSET_T
typedef cpuset_t cpu_set_t;
#else
typedef struct {
    int bits;
} cpu_set_t;
#endif
#endif

#if !HAVE_SCHED_SETAFFINITY
inline void
CpuAnd(cpu_set_t *destset, const cpu_set_t *srcset1, const cpu_set_t *srcset2)
{
    CPU_COPY(srcset1, destset);
    CPU_AND(destset, srcset2);
}

int sched_setaffinity(pid_t, size_t, cpu_set_t *);
int sched_getaffinity(pid_t, size_t, cpu_set_t *);

#else /* HAVE_SCHED_SETAFFINITY */
#if !defined(CPU_SETSIZE)
#define CPU_SETSIZE 0
#endif

#if !defined(CPU_ZERO)
#define CPU_ZERO(set) (void)0
#endif

#if !defined(CPU_SET)
#define CPU_SET(cpunum, cpuset) CpuSet(cpunum, cpuset)
inline void CpuSet(int, const cpu_set_t *) {}
#endif

#if !defined(CPU_CLR)
#define CPU_CLR(cpu, set) (void)0
#endif

#if !defined(CPU_ISSET)
#define CPU_ISSET(cpunum, cpuset) CpuIsSet(cpunum, cpuset)
inline bool CpuIsSet(int, const cpu_set_t *) { return false; }
#endif

// glibc prior to 2.6 lacks CPU_COUNT
#if !defined(CPU_COUNT)
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
#if !defined(CPU_AND)
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

#endif /* HAVE_SCHED_SETAFFINITY */
#endif /* SQUID_COMPAT_CPU_H */
