/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_UNISTD_H
#define SQUID_COMPAT_UNISTD_H

#if HAVE_PATHS_H
#include <paths.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

/// POSIX close(2) equivalent
int xclose(int fd);

/// POSIX gethostname(2) equivalent
int xgethostname(char *name, size_t namelen);

/// POSIX open(2) equivalent
int xopen(const char *filename, int oflag, int pmode = 0);

/// POSIX read(2) equivalent
int xread(int fd, void * buf, size_t sz);

/// POSIX write(2) equivalent
int xwrite(int fd, const void * buf, size_t sz);

#if _SQUID_WINDOWS_ || _SQUID_MINGW_

#if !defined(_PATH_DEVNULL)
#define _PATH_DEVNULL "NUL"
#endif

#else /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */

inline int
xclose(int fd)
{
    return close(fd);
}

inline int
xgethostname(char *name, size_t namelen)
{
    return gethostname(name, namelen);
}

inline int
xopen(const char *filename, int oflag, int pmode)
{
    return open(filename, oflag, pmode);
}

inline int
xread(int fd, void * buf, size_t sz)
{
    return read(fd, buf, sz);
}

inline int
xwrite(int fd, const void * buf, size_t sz)
{
    return write(fd, buf, sz);
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */
#endif /* SQUID_COMPAT_UNISTD_H */
