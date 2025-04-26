/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
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

/// Provide POSIX accept(2) API on MinGW and Visual Studio build environments
int xaccept(int socketFd, struct sockaddr *, socklen_t *);

/// Provide POSIX bind(2) API on MinGW and Visual Studio build environments
int xbind(int socketFd, const struct sockaddr *, socklen_t);

/// Provide POSIX connect(2) API on MinGW and Visual Studio build environments
int xconnect(int socketFd, const struct sockaddr *, socklen_t);

int xgetsockname(int sockfd, struct sockaddr * name, socklen_t * namelen);

/// Provide POSIX setsockopt(2) API on MinGW and Visual Studio build environments
int xsetsockopt(int socketFd, int level, int option_name, const void * value, socklen_t len);

/// Provide POSIX socket(2) API on MinGW and Visual Studio build environments
int xsocket(int domain, int type, int protocol);

#if !(_SQUID_WINDOWS_ || _SQUID_MINGW_)
// Windows and MinGW implementations are in compat/socket.cc

inline int
xaccept(int socketFd, struct sockaddr *a, socklen_t *l)
{
    return accept(socketFd, a, l);
}

inline int
xbind(int socketFd, const struct sockaddr * n, socklen_t l)
{
    return bind(socketFd, n, l);
}

inline int
xconnect(int socketFd, const struct sockaddr * n, socklen_t l)
{
    return connect(socketFd, n, l);
}

inline int
xgetsockname(int sockfd, struct sockaddr * name, socklen_t * namelen)
{
    return ::getsockname(sockfd, name, namelen);
}

inline int
xsetsockopt(int socketFd, int l, int o, const void *v, socklen_t n)
{
    return setsockopt(socketFd, l, o, v, n);
}

inline int
xsocket(int domain, int type, int protocol)
{
    return ::socket(domain, type, protocol);
}

#endif /* !(_SQUID_WINDOWS_ || _SQUID_MINGW_) */

#endif /* SQUID_COMPAT_SOCKET_H */
