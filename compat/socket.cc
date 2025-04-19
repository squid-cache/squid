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

int
xaccept(int s, struct sockaddr *a, socklen_t *l)
{
    const auto result = ::accept(_get_osfhandle(s), a, l);
    if (result == INVALID_SOCKET) {
        if (WSAEMFILE == (errno = WSAGetLastError()))
            errno = EMFILE;
        return -1;
    } else {
        return _open_osfhandle(result, 0);
    }
}

int
xbind(int s, const struct sockaddr * n, socklen_t l)
{
    static_assert(SOCKET_ERROR == -1);
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
        if (result == SOCKET_ERROR) {
            errno = WSAGetLastError();
            return -1;
        }
        return 0;
    } else {
        return _close(fd);
    }
}

int
xconnect(int s, const struct sockaddr * n, socklen_t l)
{
    const auto result = ::connect(_get_osfhandle(s),n,l);
    if (result == SOCKET_ERROR) {
        errno = WSAGetLastError();
        if (errno == WSAEMFILE)
            errno = EMFILE;
        return -1;
    } else {
        return 0;
    }
}

struct hostent *
xgethostbyname(const char *n) {
    auto result = ::gethostbyname(n);
    if (!result)
        errno = WSAGetLastError();
    return result;
}

int
xsetsockopt(int s, int l, int o, const void *v, socklen_t n)
{
    const auto result = ::setsockopt(_get_osfhandle(s), l, o, static_cast<const char *>(v), n);
    if (result == SOCKET_ERROR) {
        errno = WSAGetLastError();
        return -1;
    } else {
        return 0;
    }
}

#endif
