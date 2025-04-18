/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_XACCEPT_H
#define SQUID_COMPAT_XACCEPT_H

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

int
xconnect(int s, const struct sockaddr * n, socklen_t l)
{
    return connect(s,n,l);
}

inline struct hostent *
xgethostbyname(const char *n)
{
    return gethostbyname(n);
}

#endif /* !(_SQUID_WINDOWS_ || _SQUID_MINGW_) */

#endif /* SQUID_COMPAT_XACCEPT_H */
