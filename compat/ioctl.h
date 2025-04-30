/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_IOCTL_H
#define SQUID_COMPAT_IOCTL_H

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

/// POSIX ioctl(2) equivalent
int xioctl(int fd, int io, void * arg);

#if !(_SQUID_WINDOWS_ || _SQUID_MINGW_)

inline int
xioctl(int fd, int io, void * arg)
{
    return ioctl(fd, io, arg);
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */

#endif /* SQUID_COMPAT_IOCTL_H */
