/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if _SQUID_WINDOWS_ || _SQUID_MINGW_

#include "compat/socket.h"
#include "compat/unistd.h"
#include "compat/wserrno.h"

// 2025 MinGW and pre-2022 MSVC do not define these
#ifndef _S_IREAD
#define _S_IREAD 0x0100
#endif

#ifndef _S_IWRITE
#define _S_IWRITE 0x0080
#endif

/// returns true if handle is a valid socket. Preserves errno.
static bool
isSocket(intptr_t handle)
{
    if (!isValidSocketHandle(handle)) {
        // isValidSocketHandle does not touch errno
        return false;
    }

    int value = 0;
    int valueSize = sizeof(value);
    const auto savedErrno = errno;
    // use Windows API directly
    const auto result = (getsockopt(handle, SOL_SOCKET, SO_TYPE, reinterpret_cast<char *>(&value), &valueSize) == 0);
    errno = savedErrno;
    return result;
}

int
xclose(int fd)
{
    const auto sock = _get_osfhandle(fd);
    if (sock == intptr_t(INVALID_HANDLE_VALUE)) {
        // errno is already set by _get_osfhandle()
        return -1;
    }

    if (isSocket(sock)) {
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
xgethostname(char *name, size_t namelen)
{
    assert(namelen <= INT_MAX);
    const auto result = gethostname(name, static_cast<int>(namelen));
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

int
xopen(const char *filename, int oflag, int pmode)
{
    return _open(filename, oflag, pmode & (_S_IREAD | _S_IWRITE));
}

int
xread(int fd, void * buf, size_t sz)
{
    const auto sock = _get_osfhandle(fd);
    if (sock == intptr_t(INVALID_HANDLE_VALUE)) {
        // errno is already set by _get_osfhandle()
        return -1;
    }

    assert(sz <= INT_MAX);
    if (isSocket(sock))
        return xrecv(sock, buf, sz, 0);
    else
        return _read(fd, buf, static_cast<unsigned int>(sz));
}

int
xwrite(int fd, const void * buf, size_t siz)
{
    const auto sock = _get_osfhandle(fd);
    if (sock == intptr_t(INVALID_HANDLE_VALUE)) {
        // errno is already set by _get_osfhandle()
        return -1;
    }

    assert(siz <= INT_MAX);
    if (isSocket(sock))
        return xsend(sock, buf, siz, 0);
    else
        return _write(fd, buf, static_cast<unsigned int>(siz));
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */
