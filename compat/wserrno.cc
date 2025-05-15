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

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */
