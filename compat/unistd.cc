/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/unistd.h"

int
xclose(int fd)
{
    auto sock = _get_osfhandle(fd);
    if (sock == INVALID_HANDLE) {
        // errno is already set by _get_osfhandle()
        return SOCKET_ERROR;
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

