/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/select.h"
#include "compat/wserrno.h"

#if _SQUID_WINDOWS_ || _SQUID_MINGW_

int
xselect(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval * timeout)
{
    const auto result = select(nfds, readfds, writefds, exceptfds, timeout);
    if (result == SOCKET_ERROR)
        SetErrnoFromWsaError();
    return result;
}

#endif /* _SQUID_WINDOWS_ || _SQUID_MINGW_ */
