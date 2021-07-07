/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 05    TCP Socket Functions */

#include "squid.h"
#include "comm/Tcp.h"
#include "Debug.h"

#if HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

void
Comm::ApplyTcpKeepAlive(int fd, const TcpKeepAlive &cfg)
{
    if (!cfg.enabled)
        return;

    int on = 1;
#if !defined(TCP_KEEPCNT)
    if (cfg.timeout && cfg.interval) {
        int count = (cfg.timeout + cfg.interval - 1) / cfg.interval; // XXX: unsigned-to-signed conversion
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count)) < 0) {
            int xerrno = errno;
            debugs(5, DBG_IMPORTANT, MYNAME << "FD " << fd << ": " << xstrerr(xerrno));
        }
    }
#endif
#if !defined(TCP_KEEPIDLE)
    if (cfg.idle) {
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &cfg.idle, sizeof(cfg.idle)) < 0) {
            int xerrno = errno;
            debugs(5, DBG_IMPORTANT, MYNAME << "FD " << fd << ": " << xstrerr(xerrno));
        }
    }
#endif
#if !defined(TCP_KEEPINTVL)
    if (cfg.interval) {
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &cfg.interval, sizeof(cfg.interval)) < 0) {
            int xerrno = errno;
            debugs(5, DBG_IMPORTANT, MYNAME << "FD " << fd << ": " << xstrerr(xerrno));
        }
    }
#endif
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on)) < 0) {
        int xerrno = errno;
        debugs(5, DBG_IMPORTANT, MYNAME << "FD " << fd << ": " << xstrerr(xerrno));
    }
}
