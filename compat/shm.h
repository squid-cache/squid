/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_SHM_H
#define SQUID_COMPAT_SHM_H

#if HAVE_SHM

#if HAVE_SYS_STAT_H
#include <sys/stat.h> /* for mode constants */
#endif

#if HAVE_FCNTL_H
#include <fcntl.h> /* for O_* constants */
#endif

#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#else /* HAVE_SHM */

#if HAVE_ERRNO_H
#include <errno.h>
#endif

extern "C" {

    inline int
    shm_open(const char *, int, mode_t) {
        errno = ENOTSUP;
        return -1;
    }

    inline int
    shm_unlink(const char *) {
        errno = ENOTSUP;
        return -1;
    }

} /* extern "C" */

#endif /* HAVE_SHM */

/// Determines whether segment names are iterpreted as full file paths.
bool shm_portable_segment_name_is_path();

#endif /* SQUID_COMPAT_CPU_H */

