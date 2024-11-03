/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_DELAYEDASYNCCALLS_H
#define SQUID_SRC_BASE_DELAYEDASYNCCALLS_H

#include "base/AsyncCallList.h"

/// a FIFO list of async calls, all to be scheduled in FIFO order (on demand via
/// the schedule() method or automatically at object destruction time)
class DelayedAsyncCalls
{
public:
    ~DelayedAsyncCalls() { schedule(); }

    /// stores the given call to schedule it at schedule() or destruction time
    void delay(const AsyncCallPointer &);

    /// schedules and forgets all async calls previously stored by delay()
    void schedule();

private:
    /// delay()-ed calls waiting to be scheduled, in delay() call order
    AsyncCallList deferredReads;
};

#endif /* SQUID_SRC_BASE_DELAYEDASYNCCALLS_H */

