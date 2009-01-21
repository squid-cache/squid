/*
 * $Id$
 */

#ifndef SQUID_ASYNCCALL_H
#define SQUID_ASYNCCALL_H

//#include "cbdata.h"
#include "event.h"
//#include "TextException.h"

/**
 \defgroup AsynCallsAPI Async-Calls API
 \par
 * A call is asynchronous if the caller proceeds after the call is made,
 * and the callee receives the call during the next main loop iteration.
 * Asynchronous calls help avoid nasty call-me-when-I-call-you loops
 * that humans often have trouble understanding or implementing correctly.
 \par
 * Asynchronous calls are currently implemented via Squid events. The call
 * event stores the pointer to the callback function and cbdata-protected
 * callback data. To call a method of an object, the method is wrapped
 * in a method-specific, static callback function and the pointer to the
 * object is passed to the wrapper. For the method call to be safe, the
 * class must be cbdata-enabled.
 \par
 * You do not have to use the macros below to make or receive asynchronous
 * method calls, but they give you a uniform interface and handy call
 * debugging.
 */

class CallDialer;
class AsyncCallQueue;

/**
 \todo add unique call IDs
 \todo CBDATA_CLASS2 kids
 \ingroup AsyncCallsAPI
 */
class AsyncCall: public RefCountable
{
public:
    typedef RefCount <AsyncCall> Pointer;
    friend class AsyncCallQueue;

    AsyncCall(int aDebugSection, int aDebugLevel, const char *aName);
    virtual ~AsyncCall();

    void make(); // fire if we can; handles general call debugging

    // can be called from canFire() for debugging; always returns false
    bool cancel(const char *reason);

    bool canceled() { return isCanceled != NULL; }

    virtual CallDialer *getDialer() = 0;

    void print(std::ostream &os);

    void setNext(AsyncCall::Pointer aNext) {
        theNext = aNext;
    }

    AsyncCall::Pointer &Next() {
        return theNext;
    }

public:
    const char *const name;
    const int debugSection;
    const int debugLevel;
    const unsigned int id;

protected:
    virtual bool canFire();

    virtual void fire() = 0;

    AsyncCall::Pointer theNext; // used exclusively by AsyncCallQueue

private:
    const char *isCanceled; // set to the cancelation reason by cancel()
    static unsigned int TheLastId;
};

inline
std::ostream &operator <<(std::ostream &os, AsyncCall &call)
{
    call.print(os);
    return os;
}

/**
 \ingroup AsyncCallAPI
 * Interface for all async call dialers
 */
class CallDialer
{
public:
    CallDialer() {}
    virtual ~CallDialer() {}

    // TODO: Add these for clarity when CommCbFunPtrCallT is gone
    //virtual bool canDial(AsyncCall &call) = 0;
    //virtual void dial(AsyncCall &call) = 0;

    virtual void print(std::ostream &os) const = 0;
};

/**
 \ingroup AsyncCallAPI
 * This template implements an AsyncCall using a specified Dialer class
 */
template <class Dialer>
class AsyncCallT: public AsyncCall
{
public:
    AsyncCallT(int aDebugSection, int aDebugLevel, const char *aName,
               const Dialer &aDialer): AsyncCall(aDebugSection, aDebugLevel, aName),
            dialer(aDialer) {}

    CallDialer *getDialer() { return &dialer; }

protected:
    virtual bool canFire() {
        return AsyncCall::canFire() &&
               dialer.canDial(*this);
    }
    virtual void fire() { dialer.dial(*this); }

    Dialer dialer;
};

template <class Dialer>
inline
AsyncCall *
asyncCall(int aDebugSection, int aDebugLevel, const char *aName,
          const Dialer &aDialer)
{
    return new AsyncCallT<Dialer>(aDebugSection, aDebugLevel, aName, aDialer);
}

/** Call scheduling helper. Use ScheduleCallHere if you can. */
extern bool ScheduleCall(const char *fileName, int fileLine, AsyncCall::Pointer &call);

/** Call scheduling helper. */
#define ScheduleCallHere(call) ScheduleCall(__FILE__, __LINE__, (call))


#endif /* SQUID_ASYNCCALL_H */
