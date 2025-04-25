/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/socket.h"

#if _SQUID_WINDOWS_ || _SQUID_MINGW_
#include <unordered_map>

static_assert(SOCKET_ERROR == -1);

// use to test errors for _get_osfhandle() without needing type casting
static const auto INVALID_HANDLE = (intptr_t)INVALID_HANDLE_VALUE;

/**
 * Squid socket code is written to handle POSIX errno codes.
 * Set errno to the relevant POSIX or WSA code.
 */
static void
SetErrnoFromWsaError()
{
    // POSIX codes which socket API users may care about
    static const auto *CodeMap = new std::unordered_map<int, int> {

        // values checked for by accept(2) callers
        { WSAECONNABORTED, ECONNABORTED },

        // values checked for by connect(2) callers
        { WSAEINPROGRESS, EINPROGRESS },
        { WSAEAFNOSUPPORT, EAFNOSUPPORT },
        { WSAEINVAL, EINVAL },
        { WSAEISCONN, EISCONN },

        // values checked by ignoreErrno()
        { WSAEWOULDBLOCK, EWOULDBLOCK },
        // WSAEAGAIN not defined
        { WSAEALREADY, EALREADY },
        { WSAEINTR, EINTR },
        // WSARESTART not defined

        // values checked by limitError()
        { WSAEMFILE, EMFILE },
        // WSAENFILE not defined

        // values checked by TunnelStateData::Connection::debugLevelForError()
        { WSAECONNRESET, ECONNRESET }
    };

    const auto wsa = WSAGetLastError();
    const auto itr = CodeMap->find(wsa);
    if (itr != CodeMap->cend())
        errno = itr->second;
    else
        errno = wsa;
}

int
xaccept(int socketFd, struct sockaddr *a, socklen_t *l)
{
    const auto handle = _get_osfhandle(socketFd);
    if (handle == INVALID_HANDLE) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    const auto result = ::accept(handle, a, l);
    if (result == INVALID_SOCKET) {
        SetErrnoFromWsaError();
        return SOCKET_ERROR;
    } else {
        return _open_osfhandle(result, 0);
    }
}

int
xbind(int socketFd, const struct sockaddr * n, socklen_t l)
{
    const auto handle = _get_osfhandle(socketFd);
    if (handle == INVALID_HANDLE) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    const auto result = ::bind(handle,n,l);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

int
xconnect(int socketFd, const struct sockaddr * n, socklen_t l)
{
    const auto handle = _get_osfhandle(socketFd);
    if (handle == INVALID_HANDLE) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    const auto result = ::connect(handle,n,l);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

int
xsetsockopt(int socketFd, int l, int o, const void *v, socklen_t n)
{
    const auto handle = _get_osfhandle(socketFd);
    if (handle == INVALID_HANDLE) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
    }
    const auto result = ::setsockopt(handle, l, o, static_cast<const char *>(v), n);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

int
xsocket(int domain, int type, int protocol)
{
    auto result = ::socket(domain, type, protocol);
    if (result == INVALID_SOCKET) {
        SetErrnoFromWsaError();
        return SOCKET_ERROR;
    } else {
        return _open_osfhandle(result, 0);
    }
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */
