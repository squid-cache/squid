/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_COMM_TCP_H
#define SQUID__SRC_COMM_TCP_H

#include "debug/Stream.h"

namespace Comm
{

/// Configuration settings for the TCP keep-alive feature
class TcpKeepAlive
{
public:
    unsigned int idle = 0;
    unsigned int interval = 0;
    unsigned int timeout = 0;
    bool enabled = false;
};

/// apply configured TCP keep-alive settings to the given FD socket
void ApplyTcpKeepAlive(int fd, const TcpKeepAlive &);

/// setsockopt(2) wrapper
template <typename Option>
inline bool
SetSocketOption(const int fd, const int level, const int optName, const Option &optValue)
{
    static_assert(std::is_trivially_copyable<Option>::value, "setsockopt() expects POD-like options");
    static_assert(!std::is_same<Option, bool>::value, "setsockopt() uses int to represent boolean options");
    if (setsockopt(fd, level, optName, reinterpret_cast<char *>(const_cast<Option *>(&optValue)), sizeof(optValue)) < 0) {
        const auto xerrno = errno;
        debugs(5, DBG_IMPORTANT, "ERROR: setsockopt(2) failure: " << xstrerr(xerrno));
        // TODO: Generalize to throw on errors when some callers need that.
        return false;
    }
    return true;
}

/// setsockopt(2) wrapper for setting typical on/off options
inline bool
SetBooleanSocketOption(const int fd, const int level, const int optName, const bool enable)
{
    const int optValue = enable ? 1 :0;
    return SetSocketOption(fd, level, optName, optValue);
}

} // namespace Comm

#endif /* SQUID__SRC_COMM_TCP_H */
