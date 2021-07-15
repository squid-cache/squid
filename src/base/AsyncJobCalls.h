/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ASYNCJOBCALLS_H
#define SQUID_ASYNCJOBCALLS_H

#include "base/AsyncJob.h"
#include "base/CbcPointer.h"
#include "Debug.h"

/**
 \ingroup AsyncJobAPI
 * This is a base class for all job call dialers. It does all the job
 * dialing logic (debugging, handling exceptions, etc.) except for calling
 * the job method. The latter requires knowing the number and type of method
 * parameters. Thus, we add a dial() virtual method that the MemFunT templates
 * below implement for us, calling the job's method with the right params.
 */
template <class Job>
class JobDialer: public CallDialer
{
public:
    typedef Job DestClass;
    typedef CbcPointer<Job> JobPointer;

    JobDialer(const JobPointer &aJob);
    JobDialer(const JobDialer &d);

    virtual bool canDial(AsyncCall &call);
    void dial(AsyncCall &call);

    JobPointer job;

protected:
    virtual void doDial() = 0; // actually calls the job method

private:
    // not implemented and should not be needed
    JobDialer &operator =(const JobDialer &);
};

/// schedule an async job call using a dialer; use CallJobHere macros instead
template <class Dialer>
AsyncCall::Pointer
CallJob(int debugSection, int debugLevel, const char *fileName, int fileLine,
        const char *callName, const Dialer &dialer)
{
    AsyncCall::Pointer call = asyncCall(debugSection, debugLevel, callName, dialer);
    ScheduleCall(fileName, fileLine, call);
    return call;
}

#define CallJobHere(debugSection, debugLevel, job, Class, method) \
    CallJob((debugSection), (debugLevel), __FILE__, __LINE__, \
        (#Class "::" #method), \
        JobMemFun<Class>((job), &Class::method))

#define CallJobHere1(debugSection, debugLevel, job, Class, method, arg1) \
    CallJob((debugSection), (debugLevel), __FILE__, __LINE__, \
        (#Class "::" #method), \
        JobMemFun((job), &Class::method, (arg1)))

/// Convenience macro to create a Dialer-based job callback
#define JobCallback(dbgSection, dbgLevel, Dialer, job, method) \
    asyncCall((dbgSection), (dbgLevel), #method, \
        Dialer(CbcPointer<Dialer::DestClass>(job), &method))

/*
 * *MemFunT are member function (i.e., class method) wrappers. They store
 * details of a method call in an object so that the call can be delayed
 * and executed asynchronously.  Details may include the object pointer,
 * the handler method pointer, and parameters.  To simplify, we require
 * all handlers to return void and not be constant.
 */

/*
 * We need one wrapper for every supported member function arity (i.e.,
 * number of handler arguments). The first template parameter is the class
 * type of the handler. That class must be an AsyncJob child.
 */

// Arity names are from http://en.wikipedia.org/wiki/Arity

template <class Job>
class NullaryMemFunT: public JobDialer<Job>
{
public:
    typedef void (Job::*Method)();
    explicit NullaryMemFunT(const CbcPointer<Job> &aJob, Method aMethod):
        JobDialer<Job>(aJob), method(aMethod) {}

    virtual void print(std::ostream &os) const {  os << "()"; }

public:
    Method method;

protected:
    virtual void doDial() { ((&(*this->job))->*method)(); }
};

template <class Job, class Data, class Argument1 = Data>
class UnaryMemFunT: public JobDialer<Job>
{
public:
    typedef void (Job::*Method)(Argument1);
    explicit UnaryMemFunT(const CbcPointer<Job> &aJob, Method aMethod,
                          const Data &anArg1): JobDialer<Job>(aJob),
        method(aMethod), arg1(anArg1) {}

    virtual void print(std::ostream &os) const {  os << '(' << arg1 << ')'; }

public:
    Method method;
    Data arg1;

protected:
    virtual void doDial() { ((&(*this->job))->*method)(arg1); }
};

// ... add more as needed

// Now we add global templated functions that create the member function
// wrappers above. These are for convenience: it is often easier to
// call a templated function than to create a templated object.

template <class C>
NullaryMemFunT<C>
JobMemFun(const CbcPointer<C> &job, typename NullaryMemFunT<C>::Method method)
{
    return NullaryMemFunT<C>(job, method);
}

template <class C, class Argument1>
UnaryMemFunT<C, Argument1>
JobMemFun(const CbcPointer<C> &job, typename UnaryMemFunT<C, Argument1>::Method method,
          Argument1 arg1)
{
    return UnaryMemFunT<C, Argument1>(job, method, arg1);
}

// inlined methods

template<class Job>
JobDialer<Job>::JobDialer(const JobPointer &aJob): job(aJob)
{
}

template<class Job>
JobDialer<Job>::JobDialer(const JobDialer<Job> &d): CallDialer(d), job(d.job)
{
}

template<class Job>
bool
JobDialer<Job>::canDial(AsyncCall &call)
{
    if (!job)
        return call.cancel("job gone");

    return job->canBeCalled(call);
}

template<class Job>
void
JobDialer<Job>::dial(AsyncCall &call)
{
    job->callStart(call);

    try {
        doDial();
    } catch (const std::exception &e) {
        debugs(call.debugSection, 3,
               HERE << call.name << " threw exception: " << e.what());
        job->callException(e);
    }

    job->callEnd(); // may delete job
}

/// manages waiting for an AsyncJob callback
template <class Job>
class JobWait
{
public:
    typedef CbcPointer<Job> JobPointer;

    JobWait() = default;
    ~JobWait() { cancel("owner gone"); }

    /// no copying of any kind: each waiting context needs a dedicated AsyncCall
    JobWait(JobWait &&) = delete;

    explicit operator bool() const { return waiting(); }

    /// whether we are currently waiting for the job to call us back
    /// the job itself may be gone even if this returns true
    bool waiting() const { return bool(callback_); }

    /// starts waiting for the given job to call the given callback
    void start(JobPointer, AsyncCall::Pointer);

    /// ends wait (after receiving the call back)
    /// forgets the job which is likely to be gone by now
    void finish();

    /// aborts wait (if any) before receiving the call back
    /// does nothing if we are not waiting
    void cancel(const char *reason);

    /// \returns a cbdata pointer to the job we are waiting for (or nil)
    /// the returned CbcPointer may be falsy, even if we are still waiting()
    const JobPointer &job() const { return job_; }

    /// summarizes what we are waiting for (for debugging)
    std::ostream &print(std::ostream &) const;

private:
    /// the common part of finish() and cancel()
    void clear() { callback_ = nullptr; job_.clear(); }

    /// the job that we are waiting to call us back (or nil)
    JobPointer job_;

    /// the call we are waiting for the job_ to make (or nil)
    AsyncCall::Pointer callback_;
};

template<class Job>
void
JobWait<Job>::start(const JobPointer aJob, const AsyncCall::Pointer aCall)
{
    // Invariant: The wait will be over. We cannot guarantee that the job will
    // call the callback, of course, but we can check these prerequisites.
    assert(aCall);
    assert(aJob.valid());

    // "Double" waiting state leads to conflicting/mismatching callbacks
    // detailed in finish(). Detect that bug ASAP.
    assert(!waiting());

    assert(!callback_);
    assert(!job_);
    callback_ = aCall;
    job_ = aJob;
}

template<class Job>
void
JobWait<Job>::finish()
{
    // Unexpected callbacks might result in disasters like secrets exposure,
    // data corruption, or expensive message routing mistakes when the callback
    // info is applied to the wrong message part or acted upon prematurely.
    assert(waiting());
    clear();
}

template<class Job>
void
JobWait<Job>::cancel(const char *reason)
{
    if (callback_) {
        callback_->cancel(reason);

        // Instead of AsyncJob, the class parameter could be Job. That would
        // avoid runtime child-to-parent CbcPointer conversion overheads, but
        // complicate support for Jobs with virtual AsyncJob bases (GCC error:
        // "pointer to member conversion via virtual base AsyncJob") and also
        // cache-log "Job::handleStopRequest()" with a non-existent class name.
        CallJobHere(callback_->debugSection, callback_->debugLevel, job_, AsyncJob, handleStopRequest);

        clear();
    }
}

template<class Job>
std::ostream &
JobWait<Job>::print(std::ostream &os) const
{
    // use a backarrow to emphasize that this is a callback: call24<-job6
    if (callback_)
        os << callback_->id << "<-";
    if (const auto rawJob = job_.get())
        os << rawJob->id;
    else
        os << job_; // raw pointer of a gone job may still be useful for triage
    return os;
}

template <class Job>
inline
std::ostream &operator <<(std::ostream &os, const JobWait<Job> &cbPointer)
{
    return cbPointer.print(os);
}

#endif /* SQUID_ASYNCJOBCALLS_H */

