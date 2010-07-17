/*
 * $Id$
 */

#ifndef SQUID_ASYNC_JOB_H
#define SQUID_ASYNC_JOB_H

#include "base/AsyncCall.h"

/**
 \defgroup AsyncJobAPI Async-Jobs API
 \par
 * AsyncJob is an API and a base for a class that implements a stand-alone
 * "job", "task", or "logical processing thread" which receives asynchronous
 * calls.
 */

// See AsyncJobs.dox for details.

/// \ingroup AsyncJobAPI
class AsyncJob
{

public:
    /// starts the job (i.e., makes the job asynchronous)
    static AsyncJob *AsyncStart(AsyncJob *job);

    AsyncJob(const char *aTypeName);
    virtual ~AsyncJob();

    virtual void *toCbdata() = 0;
    void noteStart(); // calls virtual start

protected:
    // XXX: temporary method to replace "delete this" in jobs-in-transition.
    // Will be replaced with calls to mustStop() when transition is complete.
    void deleteThis(const char *aReason);

    // force done() for a reason but continue with the current method
    void mustStop(const char *aReason);

    bool done() const; ///< the job is destroyed in callEnd() when done()

    virtual void start(); ///< called by AsyncStart; do not call directly
    virtual bool doneAll() const; ///< whether positive goal has been reached
    virtual void swanSong() {}; ///< internal cleanup; do not call directly
    virtual const char *status() const; ///< for debugging, starts with space

public:
    bool canBeCalled(AsyncCall &call) const; ///< whether we can be called
    void callStart(AsyncCall &call); ///< called just before the called method
    /// called right after the called job method
    virtual void callEnd(); ///< called right after the called job method
    /// called when the job throws during an async call
    virtual void callException(const std::exception &e);

protected:
    const char *stopReason; ///< reason for forcing done() to be true
    const char *typeName; ///< kid (leaf) class name, for debugging
    AsyncCall::Pointer inCall; ///< the asynchronous call being handled, if any
    const unsigned int id; ///< unique ID across all strand jobs, unless wraps

private:
    static unsigned int TheLastId; ///< makes job IDs unique until it wraps
};


/**
 \ingroup AsyncJobAPI
 * This is a base class for all job call dialers. It does all the job
 * dialing logic (debugging, handling exceptions, etc.) except for calling
 * the job method. The latter is not possible without templates and we
 * want to keep this class simple and template-free. Thus, we add a dial()
 * virtual method that the JobCallT template below will implement for us,
 * calling the job.
 */
class JobDialer: public CallDialer
{
public:
    JobDialer(AsyncJob *aJob);
    JobDialer(const JobDialer &d);
    virtual ~JobDialer();

    virtual bool canDial(AsyncCall &call);
    void dial(AsyncCall &call);

    AsyncJob *job;
    void *lock; // job's cbdata

protected:
    virtual void doDial() = 0; // actually calls the job method

private:
    // not implemented and should not be needed
    JobDialer &operator =(const JobDialer &);
};

#include "base/AsyncJobCalls.h"

template <class Dialer>
bool
CallJob(int debugSection, int debugLevel, const char *fileName, int fileLine,
        const char *callName, const Dialer &dialer)
{
    AsyncCall::Pointer call = asyncCall(debugSection, debugLevel, callName, dialer);
    return ScheduleCall(fileName, fileLine, call);
}


#define CallJobHere(debugSection, debugLevel, job, method) \
    CallJob((debugSection), (debugLevel), __FILE__, __LINE__, #method, \
        MemFun((job), &method))

#define CallJobHere1(debugSection, debugLevel, job, method, arg1) \
    CallJob((debugSection), (debugLevel), __FILE__, __LINE__, #method, \
        MemFun((job), &method, (arg1)))


#endif /* SQUID_ASYNC_JOB_H */
