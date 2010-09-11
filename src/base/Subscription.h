#ifndef _SQUID_BASE_SUBSCRIPTION_H
#define _SQUID_BASE_SUBSCRIPTION_H

#include "RefCount.h"
#include "base/AsyncCall.h"

/**
 * API for classes needing to emit multiple event-driven AsyncCalls.
 * A receiver class uses this API to subscribe interest in the
 * events being handled or watched for by the API child.
 *
 * The API child then uses this to create and emit a call as needed.
 */
class Subscription: public RefCountable {
public:
    typedef RefCount<Subscription> Pointer;

    /// returns a call object to be used for the next call back
    virtual AsyncCall::Pointer callback() = 0;
//    virtual AsyncCall::Pointer callback() const = 0;
};

/// implements Subscription API using Call's copy constructor
template<class Call_>
class CallSubscription: public Subscription
{
public:
    // cant be const because CommCbFunPtrCallT cant provide a const overload.
    // CommCbFunPtrCallT lists why. boils down to Comm IO syncWithComm() existence
    CallSubscription(RefCount<Call_> &aCall) : call(aCall) {};
    virtual AsyncCall::Pointer callback() { return new Call_(call); };
//    virtual AsyncCall::Pointer callback() const { return new Call_(call); };

private:
    RefCount<Call_> call; ///< gets copied to create callback calls
};

#endif /* _SQUID_BASE_SUBSCRIPTION_H */
