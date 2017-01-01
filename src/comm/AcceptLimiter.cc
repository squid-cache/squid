/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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
    ++ (afd->isLimited);
    debugs(5, 5, afd->conn << " x" << afd->isLimited);
    deferred_.push_back(afd);
}

void
Comm::AcceptLimiter::removeDead(const Comm::TcpAcceptor::Pointer &afd)
{
    uint64_t abandonedClients = 0;
    for (unsigned int i = 0; i < deferred_.size() && afd->isLimited > 0; ++i) {
        if (deferred_[i] == afd) {
            -- deferred_[i]->isLimited;
            deferred_[i] = NULL; // fast. kick() will skip empty entries later.
            debugs(5, 5, afd->conn << " x" << afd->isLimited);
            ++abandonedClients;
        }
    }
    debugs(5,4, "Abandoned " << abandonedClients << " client TCP SYN by closing socket: " << afd->conn);
}

void
Comm::AcceptLimiter::kick()
{
    // TODO: this could be optimized further with an iterator to search
    //       looking for first non-NULL, followed by dumping the first N
    //       with only one shift()/pop_front operation
    //  OR, by reimplementing as a list instead of Vector.

    debugs(5, 5, "size=" << deferred_.size());
    while (deferred_.size() > 0 && fdNFree() >= RESERVED_FD) {
        /* NP: shift() is equivalent to pop_front(). Giving us a FIFO queue. */
        TcpAcceptor::Pointer temp = deferred_.front();
        deferred_.erase(deferred_.begin());
        if (temp.valid()) {
            debugs(5, 5, "doing one.");
            -- temp->isLimited;
            temp->acceptNext();
            break;
        }
    }
}

