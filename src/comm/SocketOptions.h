/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_COMM_SOCKETOPTIONS_H
#define SQUID_SRC_COMM_SOCKETOPTIONS_H

#include "debug/Stream.h"
#include "sbuf/SBuf.h"

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

namespace Comm
{

/// setsockopt(2) wrapper
template <typename Option>
bool
SetSocketOption(const int fd, const int level, const int optName, const Option &optValue, const SBuf &description)
{
    static_assert(std::is_trivially_copyable<Option>::value, "setsockopt() expects POD-like options");
    static_assert(!std::is_same<Option, bool>::value, "setsockopt() uses int to represent boolean options");
    if (setsockopt(fd, level, optName, reinterpret_cast<const char *>(&optValue), sizeof(optValue)) < 0) {
        const auto xerrno = errno;
        debugs(5, DBG_IMPORTANT, "ERROR: setsockopt(2) failure on FD " << fd << " : " << xstrerr(xerrno)
               << Debug::Extra << "setting " << description);
        // TODO: Generalize to throw on errors when some callers need that.
        return false;
    }
    return true;
}

/// setsockopt(2) wrapper for setting typical on/off options
bool SetBooleanSocketOption(const int fd, const int level, const int optName, const bool enable, const SBuf &description);

} // namespace Comm

#endif /* SQUID_SRC_COMM_SOCKETOPTIONS_H */
