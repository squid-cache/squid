/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_UNISTD_H
#define SQUID_COMPAT_UNISTD_H

/// Provide POSIX close(2) API on MinGW and Visual Studio build environments
int xclose(int fd);

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

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */
#endif /* SQUID_COMPAT_UNISTD_H */
