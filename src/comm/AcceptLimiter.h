/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_COMM_ACCEPT_LIMITER_H
#define _SQUID_SRC_COMM_ACCEPT_LIMITER_H

#include "base/AsyncCall.h"

#include <deque>

namespace Comm
{

/**
 * FIFO Queue holding listener socket handlers which have been activated
 * ready to dupe their FD and accept() a new client connection.
 * But when doing so there were not enough FD available to handle the
 * new connection. These handlers are awaiting some FD to become free.
 *
 * defer - used only by Comm layer ConnAcceptor adding themselves when FD are limited.
 * kick - used by Comm layer when FD are closed.
 */
class AcceptLimiter
{

public:
    /** retrieve the global instance of the queue. */
    static AcceptLimiter &Instance();

    /** delay accepting a new client connection. */
    void defer(const AsyncCall::Pointer &);

    /** try to accept and begin processing any delayed client connections. */
    void kick();

private:
    static AcceptLimiter Instance_;

    /** FIFO queue */
    std::deque<AsyncCall::Pointer> deferred_;
};

}; // namespace Comm

#endif /* _SQUID_SRC_COMM_ACCEPT_LIMITER_H */

