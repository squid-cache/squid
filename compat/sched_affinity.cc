/*
 * Copyright (C) 2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if !HAVE_SCHED_SETAFFINITY

#include "compat/sched_affinity.h"

int sched_setaffinity(int pid, size_t csize, cpu_set_t *c) {
#if HAVE_CPUSET_SETAFFINITY
	/* -1 in the cpuset's api context the calling thread */
	if (pid == 0)
            pid = -1;
	return cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, pid, csize, const_cast<cpuset_t *>(c));
#else
	return ENOTSUP;
#endif
}

int sched_getaffinity(int pid, size_t csize, cpu_set_t *c) {
#if HAVE_CPUSET_SETAFFINITY
	/* -1 in the cpuset's api context the calling thread */
	if (pid == 0)
            pid = -1;
	return cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, pid, csize, c);
#else
	return ENOTSUP;
#endif
}
#endif

