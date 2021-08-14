/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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
    debugs(5, 5, afd->conn << "; already queued: " << deferred_.size());
    deferred_.push_back(afd);
}

void
Comm::AcceptLimiter::removeDead(const Comm::TcpAcceptor::Pointer &afd)
{
    for (auto it = deferred_.begin(); it != deferred_.end(); ++it) {
        if (*it == afd) {
            *it = nullptr; // fast. kick() will skip empty entries later.
            debugs(5,4, "Abandoned client TCP SYN by closing socket: " << afd->conn);
            return;
        }
    }
    debugs(5,4, "Not found " << afd->conn << " in queue, size: " << deferred_.size());
}

void
Comm::AcceptLimiter::kick()
{
    debugs(5, 5, "size=" << deferred_.size());
    while (deferred_.size() > 0 && Comm::TcpAcceptor::okToAccept()) {
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

