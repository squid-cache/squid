/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    TCP Socket Functions */

#include "squid.h"
#include "comm/Tcp.h"
#include "debug/Stream.h"

#if HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <type_traits>

/// setsockopt(2) wrapper
template <typename Option>
static bool
SetSocketOption(const int fd, const int level, const int optName, const Option &optValue)
{
    static_assert(std::is_trivially_copyable<Option>::value, "setsockopt() expects POD-like options");
    static_assert(!std::is_same<Option, bool>::value, "setsockopt() uses int to represent boolean options");
    if (setsockopt(fd, level, optName, &optValue, sizeof(optValue)) < 0) {
        const auto xerrno = errno;
        debugs(5, DBG_IMPORTANT, "ERROR: setsockopt(2) failure: " << xstrerr(xerrno));
        // TODO: Generalize to throw on errors when some callers need that.
        return false;
    }
    return true;
}

/// setsockopt(2) wrapper for setting typical on/off options
static bool
SetBooleanSocketOption(const int fd, const int level, const int optName, const bool enable)
{
    const int optValue = enable ? 1 :0;
    return SetSocketOption(fd, level, optName, optValue);
}

void
Comm::ApplyTcpKeepAlive(int fd, const TcpKeepAlive &cfg)
{
    if (!cfg.enabled)
        return;

#if defined(TCP_KEEPCNT)
    if (cfg.timeout && cfg.interval) {
        const int count = (cfg.timeout + cfg.interval - 1) / cfg.interval; // XXX: unsigned-to-signed conversion
        (void)SetSocketOption(fd, IPPROTO_TCP, TCP_KEEPCNT, count);
    }
#endif
#if defined(TCP_KEEPIDLE)
    if (cfg.idle) {
        // XXX: TCP_KEEPIDLE expects an int; cfg.idle is unsigned
        (void)SetSocketOption(fd, IPPROTO_TCP, TCP_KEEPIDLE, cfg.idle);
    }
#endif
#if defined(TCP_KEEPINTVL)
    if (cfg.interval) {
        // XXX: TCP_KEEPINTVL expects an int; cfg.interval is unsigned
        (void)SetSocketOption(fd, IPPROTO_TCP, TCP_KEEPINTVL, cfg.interval);
    }
#endif
    (void)SetBooleanSocketOption(fd, SOL_SOCKET, SO_KEEPALIVE, true);
}
