/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/wserrno.h"

#if _SQUID_WINDOWS_ || _SQUID_MINGW_

#include <unordered_map>

void
SetErrnoFromWsaError()
{
    // POSIX codes which socket API users may care about
    static const auto *CodeMap = new std::unordered_map<int, int> {

        { WSAECONNABORTED, ECONNABORTED },

        { WSAEINPROGRESS, EINPROGRESS },
        { WSAEAFNOSUPPORT, EAFNOSUPPORT },
        { WSAEINVAL, EINVAL },
        { WSAEISCONN, EISCONN },

        { WSAEWOULDBLOCK, EWOULDBLOCK },
        // no Windows error code maps to EAGAIN
        { WSAEALREADY, EALREADY },
        { WSAEINTR, EINTR },
        // no Windows error code maps to ERESTART

        { WSAEMFILE, EMFILE },
        // no Windows error code maps to ENFILE

        { WSAECONNRESET, ECONNRESET }
    };

    const auto wsa = WSAGetLastError();
    const auto itr = CodeMap->find(wsa);
    if (itr != CodeMap->cend())
        errno = itr->second;
    else
        errno = wsa;
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */
