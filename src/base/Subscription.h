#ifndef _SQUID_BASE_SUBSCRIPTION_H
#define _SQUID_BASE_SUBSCRIPTION_H

#include "RefCount.h"
#include "base/AsyncCall.h"

/**
 * API for classes needing to emit multiple event-driven AsyncCalls.
 *
 * The emitter class needs to accept and store a Subscription::Pointer.
 * The callback() function will spawn AsyncCalls to be filled out and
 * scheduled wth every event happening.
 */
class Subscription: public RefCountable
{
public:
    typedef RefCount<Subscription> Pointer;

    /// returns a call object to be used for the next call back
    virtual AsyncCall::Pointer callback() = 0;
//    virtual AsyncCall::Pointer callback() const = 0;
};

/**
 * Implements Subscription API using Call's copy constructor.
 *
 * A receiver class allocates one of these templated from the Call type
 * to be received (usually AsyncCallT) and passes it to the emitter class
 * which will use it to spawn event calls.
 *
 * To be a subscriber the AsyncCall child must implement a copy constructor.
 */
template<class Call_>
class CallSubscription: public Subscription
{
public:
    CallSubscription(const RefCount<Call_> &aCall) : call(aCall) {};

// XXX: obsolete comment?
    // cant be const sometimes because CommCbFunPtrCallT cant provide a const overload.
    // CommCbFunPtrCallT lists why. boils down to Comm IO syncWithComm() existence
    // NP: we still treat it as const though.
    CallSubscription(RefCount<Call_> &aCall) : call(aCall) {};
    virtual AsyncCall::Pointer callback() { return new Call_(call); };
//    virtual AsyncCall::Pointer callback() const { return new Call_(call); };

private:
    RefCount<Call_> call; ///< gets copied to create callback calls
};

#endif /* _SQUID_BASE_SUBSCRIPTION_H */
