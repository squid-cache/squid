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

int xgetsockopt(int socket, int level, int option_name, void * option_value, socklen_t * option_len);

int xgetsockname(int sockfd, struct sockaddr * name, socklen_t * namelen);

int xlisten(int socketFd, int backlog);

ssize_t xrecv(int socketFd, void * buf, size_t len, int flags);

ssize_t xrecvfrom(int socketFd, void * buf, size_t len, int flags, struct sockaddr * from, socklen_t * fromlen);

int xsend(int socketFd, const void * buf, size_t len, int flags);

ssize_t xsendto(int socketFd, const void * buf, size_t len, int flags, const struct sockaddr * to, socklen_t l);

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
xlisten(int socketFd, int backlog)
{
    return ::listen(socketFd, backlog);
}

inline int
xgetsockopt(int socket, int level, int option_name, void * option_value, socklen_t * option_len)
{
    return ::getsockopt(socket, level, option_name, option_value, option_len);
}

inline ssize_t
xrecv(int socketFd, void * buf, size_t len, int flags)
{
    return ::recv(socketFd, static_cast<char *>(buf), static_cast<int>(len), flags);
}

inline ssize_t
xrecvfrom(int socketFd, void * buf, size_t len, int flags, struct sockaddr * from, socklen_t * fromlen)
{
    return ::recvfrom(socketFd, static_cast<char *>(buf), static_cast<int>(len), flags, from, fromlen);
}

inline int
xsend(int socketFd, const void * buf, size_t len, int flags)
{
    return ::send(socketFd, static_cast<const char *>(buf), static_cast<int>(len), flags);
}

inline ssize_t
xsendto(int socketFd, const void * buf, size_t len, int flags, const struct sockaddr * to, socklen_t l)
{
    return ::sendto(socketFd, static_cast<const char *>(buf), static_cast<int>(len), flags, to, l);
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
