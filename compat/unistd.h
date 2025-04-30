/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_UNISTD_H
#define SQUID_COMPAT_UNISTD_H

#if HAVE_FCNTL_H
#include <fcntl.h>
#endif

// MSVC might not define these
#ifndef _S_IREAD
#define _S_IREAD 0x0100
#endif

#ifndef _S_IWRITE
#define _S_IWRITE 0x0080
#endif

/// Provide POSIX close(2) API on MinGW and Visual Studio build environments
int xclose(int fd);

int xgethostname(char *name, size_t namelen);

int xopen(const char *filename, int oflag, int pmode = 0);

int xread(int fd, void * buf, size_t sz);

int xwrite(int fd, const void * buf, size_t sz);

#if (_SQUID_WINDOWS_ || _SQUID_MINGW_)

#ifndef _PATH_DEVNULL
#define _PATH_DEVNULL "NUL"
#endif

#else /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */
// Windows and MinGW implementations are in compat/unistd.cc

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
