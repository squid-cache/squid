/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_DELAYEDASYNCCALLS_H
#define SQUID_BASE_DELAYEDASYNCCALLS_H

#include "base/AsyncCallList.h"
#include "base/forward.h"

/// a FIFO list of async calls, all to be scheduled in FIFO order (on demand via
/// the kick() method or automatically at object destruction time)
class DelayedAsyncCalls
{
public:
    ~DelayedAsyncCalls() { kick(); }

    /// stores the given call to schedule it at kick() or destruction time
    void delay(const AsyncCallPointer &);

    /// schedules and forgets all async calls previously stored by delay()
    void kick();

private:
    /// delay()-ed calls waiting to be kick()-ed, in delay() call order
    AsyncCallList deferredReads;
};

#endif /* SQUID_BASE_DELAYEDASYNCCALLS_H */

