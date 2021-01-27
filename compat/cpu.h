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
#else
#include "compat/sched_affinity.h"
#endif

#endif /* SQUID_COMPAT_CPU_H */

