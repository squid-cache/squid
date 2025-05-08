/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    TCP Socket Functions */

#include "squid.h"
#include "comm/Tcp.h"
#include "debug/Stream.h"
#include "sbuf/Stream.h"

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

bool
Comm::SetBooleanSocketOption(const int fd, const int level, const int optName, const bool enable, const SBuf &description)
{
    const int optValue = enable ? 1 :0;
    return SetSocketOption(fd, level, optName, optValue, ToSBuf((enable ? "enable ":"disable "), description));
}

void
Comm::ApplyTcpKeepAlive(int fd, const TcpKeepAlive &cfg)
{
    if (!cfg.enabled)
        return;

#if defined(TCP_KEEPCNT)
    if (cfg.timeout && cfg.interval) {
        const int count = (cfg.timeout + cfg.interval - 1) / cfg.interval; // XXX: unsigned-to-signed conversion
        SetSocketOption(fd, IPPROTO_TCP, TCP_KEEPCNT, count, ToSBuf("TCP_KEEPCNT to ", count));
    }
#endif
#if defined(TCP_KEEPIDLE)
    if (cfg.idle) {
        // XXX: TCP_KEEPIDLE expects an int; cfg.idle is unsigned
        SetSocketOption(fd, IPPROTO_TCP, TCP_KEEPIDLE, cfg.idle, ToSBuf("TCP_KEEPIDLE to ", cfg.idle));
    }
#endif
#if defined(TCP_KEEPINTVL)
    if (cfg.interval) {
        // XXX: TCP_KEEPINTVL expects an int; cfg.interval is unsigned
        SetSocketOption(fd, IPPROTO_TCP, TCP_KEEPINTVL, cfg.interval, ToSBuf("TCP_KEEPINTVL to ", cfg.interval));
    }
#endif
    SetBooleanSocketOption(fd, SOL_SOCKET, SO_KEEPALIVE, true, SBuf("SO_KEEPALIVE"));
}
