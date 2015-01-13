/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_BASE_SUBSCRIPTION_H
#define _SQUID_BASE_SUBSCRIPTION_H

#include "base/AsyncCall.h"

/** API for creating a series of AsyncCalls.
 * This is necessary because the same AsyncCall callback must not be
 * fired multiple times.
 *
 * The call producer needs to accept and store a Subscription::Pointer.
 * It also should provide some mechanism for adding/removing/changing
 * the stored Subscription::Pointer.
 *
 * The callback() method of Subscription::Pointer will spawn AsyncCall
 * to be filled out and scheduled as needed.
 */
class Subscription: public RefCountable
{
public:
    typedef RefCount<Subscription> Pointer;

    /** returns a call object to be used for the next call back.
     * Child implementations must ensure the Call pointer produced
     * is not NULL.
     */
    virtual AsyncCall::Pointer callback() const = 0;
};

/** Implements Subscription API using Call's copy constructor.
 *
 * The subscriber creates one of these using a specific callback
 * type and instance. The subscription object is then passed to a
 * producer/factory which will use this API to generate calls.
 * A subscription may be passed to multiple producers.
 *
 * Call_ must have a copy constructor.
 * A pointer to Call_ must be convertable to AsyncCall::Pointer
 */
template<class Call_>
class CallSubscription: public Subscription
{
public:
    /// Must be passed an object. nil pointers are not permitted.
    explicit CallSubscription(const RefCount<Call_> &aCall) : call(aCall) { assert(aCall != NULL); }
    virtual AsyncCall::Pointer callback() const { return new Call_(*call); }

private:
    const RefCount<Call_> call; ///< gets copied to create callback calls
};

#endif /* _SQUID_BASE_SUBSCRIPTION_H */

