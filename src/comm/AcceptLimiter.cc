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
Comm::AcceptLimiter::defer(const AsyncCall::Pointer &call)
{
    debugs(5, 5, call << "; already queued: " << deferred_.size());
    deferred_.push_back(call);
}

void
Comm::AcceptLimiter::kick()
{
    debugs(5, 5, "size=" << deferred_.size());
    if (deferred_.size() > 0 && Comm::TcpAcceptor::okToAccept()) {
        auto call = deferred_.front();
        deferred_.erase(deferred_.begin());
        ScheduleCallHere(call);
    }
}

