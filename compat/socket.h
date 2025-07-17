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

/// POSIX accept(2) equivalent
int xaccept(int socketFd, struct sockaddr *sa, socklen_t *saLength);

/// POSIX bind(2) equivalent
int xbind(int socketFd, const struct sockaddr *sa, socklen_t saLength);

/// POSIX connect(2) equivalent
int xconnect(int socketFd, const struct sockaddr *sa, socklen_t saLength);

/// POSIX getsockopt(2) equivalent
int xgetsockopt(int socketFd, int level, int optionName, void * optionValue, socklen_t * optionLength);

/// POSIX getsockname(2) equivalent
int xgetsockname(int socketFd, struct sockaddr * sa, socklen_t * saLength);

/// POSIX listen(2) equivalent
int xlisten(int socketFd, int backlog);

/// POSIX recv(2) equivalent
ssize_t xrecv(int socketFd, void * buf, size_t bufLength, int flags);

/// POSIX recvfrom(2) equivalent
ssize_t xrecvfrom(int socketFd, void * buf, size_t bufLength, int flags, struct sockaddr * from, socklen_t * fromLength);

/// POSIX send(2) equivalent
int xsend(int socketFd, const void * buf, size_t bufLength, int flags);

/// POSIX sendto(2) equivalent
ssize_t xsendto(int socketFd, const void * buf, size_t bufLength, int flags, const struct sockaddr * to, socklen_t toLength);

/// POSIX setsockopt(2) equivalent
int xsetsockopt(int socketFd, int level, int option, const void * value, socklen_t valueLength);

/// POSIX socket(2) equivalent
int xsocket(int domain, int type, int protocol);

// Solaris and possibly others lack MSG_NOSIGNAL optimization
// TODO: move this into compat/? Use a dedicated compat file to avoid dragging
// sys/socket.h into the rest of Squid??
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#if !(_SQUID_WINDOWS_ || _SQUID_MINGW_)

inline int
xaccept(int socketFd, struct sockaddr *sa, socklen_t *saLength)
{
    return accept(socketFd, sa, saLength);
}

inline int
xbind(int socketFd, const struct sockaddr *sa, socklen_t saLength)
{
    return bind(socketFd, sa, saLength);
}

inline int
xconnect(int socketFd, const struct sockaddr *sa, socklen_t saLength)
{
    return connect(socketFd, sa, saLength);
}

inline int
xgetsockname(int socketFd, struct sockaddr * sa, socklen_t * saLength)
{
    return getsockname(socketFd, sa, saLength);
}

inline int
xlisten(int socketFd, int backlog)
{
    return listen(socketFd, backlog);
}

inline int
xgetsockopt(int socketFd, int level, int optionName, void * optionValue, socklen_t * optionLength)
{
    return getsockopt(socketFd, level, optionName, optionValue, optionLength);
}

inline ssize_t
xrecv(int socketFd, void * buf, size_t bufLength, int flags)
{
    return recv(socketFd, buf, bufLength, flags);
}

inline ssize_t
xrecvfrom(int socketFd, void * buf, size_t bufLength, int flags, struct sockaddr * from, socklen_t * fromLength)
{
    return recvfrom(socketFd, buf, bufLength, flags, from, fromLength);
}

inline int
xsend(int socketFd, const void * buf, size_t bufLength, int flags)
{
    return send(socketFd, buf, bufLength, flags);
}

inline ssize_t
xsendto(int socketFd, const void * buf, size_t bufLength, int flags, const struct sockaddr * to, socklen_t l)
{
    return sendto(socketFd, buf, bufLength, flags, to, l);
}

inline int
xsetsockopt(int socketFd, int level, int option, const void *value, socklen_t valueLength)
{
    return setsockopt(socketFd, level, option, value, valueLength);
}

inline int
xsocket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

#else

static_assert(SOCKET_ERROR == -1);

inline bool
isValidSocketHandle(intptr_t handle)
{
    return handle != intptr_t(INVALID_HANDLE_VALUE);
}

#endif /* !(_SQUID_WINDOWS_ || _SQUID_MINGW_) */

#endif /* SQUID_COMPAT_SOCKET_H */
