/*
 * $Id$
 */

#ifndef SQUID_ASYNC_JOB_H
#define SQUID_ASYNC_JOB_H

#include "base/AsyncCall.h"
#include "TextException.h"

/**
 \defgroup AsyncJobAPI Async-Jobs API
 \par
 * AsyncJob is an API and a base for a class that implements a stand-alone
 * "job", "task", or "logical processing thread" which receives asynchronous
 * calls.
 *
 * Implementations should wrap each method receiving an asynchronous call in
 * a pair of macros: AsyncCallEnter and AsyncCallExit. These macros:
 *   - provide call debugging
 *   - trap exceptions and terminate the task if an exception occurs
 *   - ensure that only one asynchronous call is active per object
 * Most of the work is done by AsyncJob class methods. Macros just provide
 * an enter/try/catch/exit framework.
 *
 * Eventually, the macros can and perhaps should be replaced with call/event
 * processing code so that individual job classes do not have to wrap all
 * asynchronous calls.
 */

/// \ingroup AsyncJobAPI
class AsyncJob
{

public:
    static AsyncJob *AsyncStart(AsyncJob *job); // use this to start jobs

    AsyncJob(const char *aTypeName);
    virtual ~AsyncJob();

    virtual void *toCbdata() = 0;
    void noteStart(); // calls virtual start

protected:
    // XXX: temporary method to replace "delete this" in jobs-in-transition.
    // Will be replaced with calls to mustStop() when transition is complete.
    void deleteThis(const char *aReason);

    void mustStop(const char *aReason); // force done() for a reason

    bool done() const; // the job is destroyed in callEnd() when done()

    virtual void start();
    virtual bool doneAll() const; // return true when done
    virtual void swanSong() {}; // perform internal cleanup
    virtual const char *status() const; // for debugging

public:
    // asynchronous call maintenance
    bool canBeCalled(AsyncCall &call) const;
    void callStart(AsyncCall &call);
    virtual void callException(const std::exception &e);
    virtual void callEnd();

protected:
    const char *stopReason; // reason for forcing done() to be true
    const char *typeName; // kid (leaf) class name, for debugging
    AsyncCall::Pointer inCall; // the asynchronous call being handled, if any
    const unsigned int id;

private:
    static unsigned int TheLastId;
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
