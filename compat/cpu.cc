/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if !HAVE_SCHED_SETAFFINITY

#include "compat/cpu.h"

/**
 * Reimplementation of sched_getaffinity/sched_setaffinity
 * for systems having a similar feature but with
 * a different api's set primarly.
 *
 * Otherwise, falling back to the ENOTSUP versions.
 */

#if HAVE_ERRNO_H
#include <errno.h> /* for ENOTSUP */
#endif

int
sched_setaffinity(pid_t pid, size_t csize, cpu_set_t *c)
{
#if HAVE_CPUSET_SETAFFINITY
	if (pid == 0) // "current thread" in caller's sched_setaffinity() API
            pid = -1; // "current thread" in caller's cpuset_setaffinity() API
	return cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, pid, csize, c);
#else
	return ENOTSUP;
#endif
}

int
sched_getaffinity(pid_t pid, size_t csize, cpu_set_t *c)
{
#if HAVE_CPUSET_SETAFFINITY
	if (pid == 0) // "current thread" in caller's sched_getaffinity() API
            pid = -1; // "current thread" in caller's cpuset_getaffinity() API
	return cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, pid, csize, c);
#else
	return ENOTSUP;
#endif
}
#endif

