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
xaccept(int socketFd, struct sockaddr *sa, socklen_t *saLen)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    int al = 0;
    int *alp = nullptr;
    if (saLen) {
        assert(*saLen <= INT_MAX);
        al = static_cast<int>(*saLen);
        alp = &al;
    }
    const auto result = accept(handle, sa, alp);
    if (result == INVALID_SOCKET) {
        SetErrnoFromWsaError();
        return SOCKET_ERROR;
    }
    const auto rv = _open_osfhandle(result, 0);
    if (rv == -1)
        errno = EBADF;
    if (saLen)
        *saLen = static_cast<socklen_t>(al);
    return rv;
}

int
xbind(int socketFd, const struct sockaddr *sa, socklen_t saLen)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    assert(saLen <= INT_MAX);
    const auto result = bind(handle, sa, static_cast<int>(saLen));
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

int
xconnect(int socketFd, const struct sockaddr *sa, socklen_t saLen)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    assert(saLen <= INT_MAX);
    const auto result = connect(handle, sa, static_cast<int>(saLen));
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

int
xgetsockname(int socketFd, struct sockaddr * sa, socklen_t * saLen)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    int al = 0;
    int *alp = nullptr;
    if (saLen) {
        assert(*saLen <= INT_MAX);
        al = static_cast<int>(*saLen);
        alp = &al;
    }
    const auto result = getsockname(handle, sa, alp);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    if (saLen)
        *saLen = static_cast<socklen_t>(al);
    return result;
}

int
xgetsockopt(int socketFd, int level, int optionName, void * optionValue, socklen_t * optionLen)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    int ol = 0;
    int *olp = nullptr;
    if (optionLen) {
        assert(*optionLen <= INT_MAX);
        ol = static_cast<int>(*optionLen);
        olp = &ol;
    }
    const auto result = getsockopt(handle, level, optionName, static_cast<char *>(optionValue), &olp);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    if (optionLen)
        *optionLen = static_cast<socklen_t>(ol);
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
xrecv(int socketFd, void * buf, size_t bufLen, int flags)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    assert(bufLen <= INT_MAX);
    const auto result = recv(handle, static_cast<char *>(buf), static_cast<int>(bufLen), flags);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

ssize_t
xrecvfrom(int socketFd, void * buf, size_t bufLen, int flags, struct sockaddr * from, socklen_t * fromLen)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    assert(bufLen <= INT_MAX);
    int fl = 0;
    int *flp = nullptr;
    if (fromLen) {
        assert(*fromLen <= INT_MAX);
        fl = static_cast<int>(*fromLen);
        flp = &fl;
    }
    const auto result = recvfrom(handle, static_cast<char *>(buf), static_cast<int>(bufLen), flags, from, flp);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    if (fromLen)
        *fromLen = static_cast<socklen_t>(fl);
    return result;
}

int
xsend(int socketFd, const void * buf, size_t bufLen, int flags)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    assert(bufLen <= INT_MAX);
    const auto result = send(handle, static_cast<const char *>(buf), static_cast<int>(bufLen), flags);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

ssize_t
xsendto(int socketFd, const void * buf, size_t bufLen, int flags, const struct sockaddr * to, socklen_t toLen)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    assert(bufLen <= INT_MAX);
    assert(toLen <= INT_MAX);
    const auto result = sendto(handle, static_cast<const char *>(buf), static_cast<int>(bufLen), flags, to, static_cast<int>(toLen));
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

int
xsetsockopt(int socketFd, int level, int option, const void *value, socklen_t valueLen)
{
    const auto handle = _get_osfhandle(socketFd);
    if (!isValidSocketHandle(handle)) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    assert(option <= INT_MAX);
    const auto result = setsockopt(handle, level, option, static_cast<const char *>(value), static_cast<int>(valueLen));
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

int
xsocket(int domain, int type, int protocol)
{
    const auto result = socket(domain, type, protocol);
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
