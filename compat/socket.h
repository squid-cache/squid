/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_SOCKET_H
#define SQUID_COMPAT_SOCKET_H

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if _SQUID_WINDOWS_ || _SQUID_MINGW_

int
xaccept(int s, struct sockaddr *a, socklen_t *l);

int
xbind(int s, const struct sockaddr * n, socklen_t l);

int
xconnect(int s, const struct sockaddr * n, socklen_t l);

int
xclose(int fd);

struct hostent *
xgethostbyname(const char *n);

int
xsetsockopt(int s, int l, int o, const void *v, socklen_t n);
// for windows/mingw calls referring to INVALID_SOCKET, use setsockopt()

#else /* !(_SQUID_WINDOWS_ || _SQUID_MINGW_) */

inline int
xaccept(int s, struct sockaddr *a, socklen_t *l)
{
    return accept(s,a,l);
}

inline int
xbind(int s, const struct sockaddr * n, socklen_t l)
{
    return bind(s,n,l);
}

inline int
xclose(int fd)
{
    return close(fd);
}

inline int
xconnect(int s, const struct sockaddr * n, socklen_t l)
{
    return connect(s,n,l);
}

inline struct hostent *
xgethostbyname(const char *n)
{
    return gethostbyname(n);
}

inline int
xsetsockopt(int s, int l, int o, const void *v, socklen_t n)
{
    return setsockopt(s, l, o, v, n);
}

#endif /* !(_SQUID_WINDOWS_ || _SQUID_MINGW_) */

#endif /* SQUID_COMPAT_SOCKET_H */
