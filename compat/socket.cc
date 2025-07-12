/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/socket.h"
#include "compat/wserrno.h"

#if _SQUID_WINDOWS_ || _SQUID_MINGW_
#include <unordered_map>

int
xaccept(int socketFd, struct sockaddr *a, socklen_t *l)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    const auto result = accept(handle, a, l);
    if (result == INVALID_SOCKET) {
        SetErrnoFromWsaError();
        return SOCKET_ERROR;
    }
    const auto rv = _open_osfhandle(result, 0);
    if (rv == -1)
        errno = EBADF;
    return rv;
}

int
xbind(int socketFd, const struct sockaddr * n, socklen_t l)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    const auto result = bind(handle,n,l);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

int
xconnect(int socketFd, const struct sockaddr * n, socklen_t l)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    const auto result = connect(handle,n,l);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

int
xgetsockname(int sockfd, struct sockaddr * addr, socklen_t * addrlen)
{
    const auto handle = _get_osfhandle(sockfd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    auto al = static_cast<int>(*addrlen);
    const auto result = getsockname(handle, addr, &al);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    *addrlen = static_cast<socklen_t>(al);
    return result;
}

int
xgetsockopt(int socket, int level, int option_name, void * option_value, socklen_t * option_len)
{
    const auto handle = _get_osfhandle(socket);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    auto ol = static_cast<int>(*option_len);
    const auto result = getsockopt(handle, level, option_name, static_cast<char *>(option_value), &ol);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    *option_len = static_cast<socklen_t>(ol);
    return result;
}

int
xlisten(int socketFd, int backlog)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    const auto result = listen(handle, backlog);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

ssize_t
xrecv(int socketFd, void * buf, size_t len, int flags)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    assert(len <= INT_MAX);
    const auto result = recv(handle, static_cast<char *>(buf), static_cast<int>(len), flags);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

ssize_t
xrecvfrom(int socketFd, void * buf, size_t len, int flags, struct sockaddr * from, socklen_t * fromlen)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    auto fl = static_cast<int>(*fromlen);
    assert(len <= INT_MAX);
    const auto result = recvfrom(handle, static_cast<char *>(buf), static_cast<int>(len), flags, from, &fl);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    *fromlen = static_cast<socklen_t>(fl);
    return result;
}

int
xsend(int socketFd, const void * buf, size_t len, int flags)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    assert(len <= INT_MAX);
    const auto result = send(handle, static_cast<const char *>(buf), static_cast<int>(len), flags);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

ssize_t
xsendto(int socketFd, const void * buf, size_t len, int flags, const struct sockaddr * to, socklen_t l)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    assert(len <= INT_MAX);
    const auto result = sendto(handle, static_cast<const char *>(buf), static_cast<int>(len), flags, to, l);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

int
xsetsockopt(int socketFd, int l, int o, const void *v, socklen_t n)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    const auto result = setsockopt(handle, l, o, static_cast<const char *>(v), n);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

int
xsocket(int domain, int type, int protocol)
{
    auto result = socket(domain, type, protocol);
    if (result == INVALID_SOCKET) {
        SetErrnoFromWsaError();
        return SOCKET_ERROR;
    }
    const auto rv = _open_osfhandle(result, 0);
    if (rv == -1)
        errno = EBADF;
    return rv;
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */
