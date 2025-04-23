/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/socket.h"

#if _SQUID_WINDOWS_ || _SQUID_MINGW_
#include <map>

static_assert(SOCKET_ERROR == -1);

/**
 * Squid socket code is written to handle POSIX errno codes.
 * Set errno to the relevant POSIX or WSA code.
 */
static void
SetErrnoFromWsaError()
{
    // POSIX codes which socket API users may care about
    static const auto *CodeMap = new std::map<int, int> {

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
xaccept(int s, struct sockaddr *a, socklen_t *l)
{
    const auto result = ::accept(_get_osfhandle(s), a, l);
    if (result == INVALID_SOCKET) {
        SetErrnoFromWsaError();
        return SOCKET_ERROR;
    } else {
        return _open_osfhandle(result, 0);
    }
}

int
xbind(int s, const struct sockaddr * n, socklen_t l)
{
    const auto result = ::bind(_get_osfhandle(s),n,l);
    if (result == SOCKET_ERROR)
        errno = WSAGetLastError();
    return result;
}

int
xclose(int fd)
{
    char l_so_type[sizeof(int)];
    int l_so_type_siz = sizeof(l_so_type);
    auto sock = _get_osfhandle(fd);

    if (::getsockopt(sock, SOL_SOCKET, SO_TYPE, l_so_type, &l_so_type_siz) == 0) {
        const auto result = closesocket(sock);
        if (result == SOCKET_ERROR)
            errno = WSAGetLastError();
        return result;
    } else {
        return _close(fd);
    }
}

int
xconnect(int s, const struct sockaddr * n, socklen_t l)
{
    const auto result = ::connect(_get_osfhandle(s),n,l);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

struct hostent *
xgethostbyname(const char *n)
{
    auto result = ::gethostbyname(n);
    if (!result)
        errno = WSAGetLastError();
    return result;
}

int
xsetsockopt(int s, int l, int o, const void *v, socklen_t n)
{
    const auto result = ::setsockopt(_get_osfhandle(s), l, o, static_cast<const char *>(v), n);
    if (result == SOCKET_ERROR)
        errno = WSAGetLastError();
    return result;
}

int
xsocket(int f, int t, int p)
{
    auto result = ::socket(f, t, p);
    if (result == INVALID_SOCKET) {
        SetErrnoFromWsaError();
        return SOCKET_ERROR;
    } else {
        return _open_osfhandle(result, 0);
    }
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */
