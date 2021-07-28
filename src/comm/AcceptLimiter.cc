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

class KickDialer : public CallDialer
{
public:
    virtual bool canDial(AsyncCall &) { return true; }
    virtual void dial(AsyncCall &) { Comm::AcceptLimiter::Instance().kick(); }
    virtual void print(std::ostream &os) const { os << "()"; }
};

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
Comm::AcceptLimiter::removeDead(const AsyncCall::Pointer &call)
{
    int found = 0;
    for (auto &it : deferred_) {
        if (it != call)
            continue;

        it = nullptr;
        debugs(5, 4, call << "; abandoned " << ++found << " client TCP SYN by closing listener FD");
    }

    if (!found)
        debugs(5, 4, call << "; not found in queue, size=" << deferred_.size());
}

void
Comm::AcceptLimiter::kick()
{
    debugs(5, 5, "size=" << deferred_.size());
    if (deferred_.size() == 0)
        return;

    if (!Comm::TcpAcceptor::okToAccept())
        return;

    AsyncCall::Pointer call = deferred_.front();
    deferred_.erase(deferred_.begin());
    ScheduleCallHere(call);

    // Schedule a repeat kick() for AFTER the deferred accept(2) is dialed.
    // This order requirement ensures okToAccept() result is correct.
    AsyncCall::Pointer retry = asyncCall(5, 5, "Comm::AcceptLimiter::kick", KickDialer());
    ScheduleCallHere(retry);
}

