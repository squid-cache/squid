/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_OS_SOCKET_H
#define SQUID_COMPAT_OS_SOCKET_H

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if _SQUID_WINDOWS_ || _SQUID_MINGW_

int xaccept(int s, struct sockaddr *a, socklen_t *l);

#else /* !(_SQUID_WINDOWS_ || _SQUID_MINGW_) */

inline xaccept(int s, struct sockaddr *a, socklen_t *l)
{
    return accept(s,a,l);
}

#endif /* !(_SQUID_WINDOWS_ || _SQUID_MINGW_) */

#endif /* SQUID_COMPAT_OS_SOCKET_H */
