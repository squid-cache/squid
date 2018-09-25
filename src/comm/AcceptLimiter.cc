/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "comm/AcceptLimiter.h"
#include "comm/Connection.h"
#include "comm/TcpAcceptor.h"
#include "fde.h"
#include "globals.h"

Comm::AcceptLimiter Comm::AcceptLimiter::Instance_;

Comm::AcceptLimiter &
Comm::AcceptLimiter::Instance()
{
    return Instance_;
}

void
Comm::AcceptLimiter::defer(const Comm::TcpAcceptor::Pointer &afd)
{
    debugs(5, 5, "deferring " << afd->conn);
    deferred_.insert(afd);
}

void
Comm::AcceptLimiter::removeDead(const Comm::TcpAcceptor::Pointer &afd)
{
    const auto it = deferred_.find(afd);
    if (it != deferred_.end()) {
        deferred_.erase(it);
        debugs(5, 4, "Abandoned client TCP SYN by closing socket: " << afd->conn);
    }
}

void
Comm::AcceptLimiter::kick()
{
    debugs(5, 5, "size=" << deferred_.size());

    while (deferred_.size() > 0 && fdNFree() >= RESERVED_FD) {
        const auto it = deferred_.begin();
        TcpAcceptor::Pointer temp = *it;
        deferred_.erase(it);
        if (temp.valid()) {
            debugs(5, 5, "doing one.");
            temp->acceptNext();
            break;
        }
    }
}

