/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if (_SQUID_WINDOWS_ || _SQUID_MINGW_)

#include "compat/unistd.h"
#include "compat/wserrno.h"

int
xclose(int fd)
{
    auto sock = _get_osfhandle(fd);
    if (sock == intptr_t(INVALID_HANDLE_VALUE)) {
        // errno is already set by _get_osfhandle()
        return -1;
    }

    char l_so_type[sizeof(int)];
    int l_so_type_siz = sizeof(l_so_type);
    if (::getsockopt(sock, SOL_SOCKET, SO_TYPE, l_so_type, &l_so_type_siz) == 0) {
        const auto result = closesocket(sock);
        if (result == SOCKET_ERROR)
            SetErrnoFromWsaError();
        return result;
    } else {
        const auto result = _close(fd);
        if (result)
            SetErrnoFromWsaError();
        return result;
    }
}

int
xopen(const char *filename, int oflag, int pmode)
{
    return _open(filename, oflag, pmode & (_S_IREAD | _S_IWRITE));
}

int
xread(int fd, void * buf, size_t sz)
{
    char l_so_type[sizeof(int)];
    int l_so_type_siz = sizeof(l_so_type);
    SOCKET sock = _get_osfhandle(fd);

    if (::getsockopt(sock, SOL_SOCKET, SO_TYPE, l_so_type, &l_so_type_siz) == 0)
        return ::recv(sock, (char FAR *) buf, (int)sz, 0);
    else
        return _read(fd, buf, (unsigned int)sz);
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */
