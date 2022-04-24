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

#include <vector>

/// maintains a list of async calls and schedules them at once
class DelayedAsyncCalls
{
public:
    ~DelayedAsyncCalls() { kick(); }
    /// stores an async call in a list
    void delay(const AsyncCallPointer &);
    /// schedules all previously stored async calls and clears the list
    void kick();

private:
    AsyncCallList deferredReads;
};

#endif /* SQUID_BASE_DELAYEDASYNCCALLS_H */

