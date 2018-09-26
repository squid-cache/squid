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
    deferred_.push_back(afd);
}

void
Comm::AcceptLimiter::removeDead(const Comm::TcpAcceptor::Pointer &afd)
{
    uint64_t abandonedClients = 0;
    for (auto it = deferred_.begin(); it != deferred_.end(); ++it) {
        if (*it == afd) {
            *it = NULL; // fast. kick() will skip empty entries later.
            ++abandonedClients;
        }
    }
    debugs(5,4, "Abandoned " << abandonedClients << " client TCP SYN by closing socket: " << afd->conn);
}

void
Comm::AcceptLimiter::kick()
{
    debugs(5, 5, "size=" << deferred_.size());
    while (deferred_.size() > 0 && fdNFree() >= RESERVED_FD) {
        /* NP: shift() is equivalent to pop_front(). Giving us a FIFO queue. */
        TcpAcceptor::Pointer temp = deferred_.front();
        deferred_.erase(deferred_.begin());
        if (temp.valid()) {
            debugs(5, 5, "doing one.");
            temp->acceptNext();
            break;
        }
    }
}

