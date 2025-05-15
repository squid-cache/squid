/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_SELECT_H
#define SQUID_COMPAT_SELECT_H

#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

/// POSIX select(2) equivalent
int xselect(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval * timeout);

#if !(_SQUID_WINDOWS_ || _SQUID_MINGW_)

inline int
xselect(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval * timeout)
{
    return select(nfds, readfds, writefds, exceptfds, timeout);
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */

#endif /* SQUID_COMPAT_SELECT_H */
