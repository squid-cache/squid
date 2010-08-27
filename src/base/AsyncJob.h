/*
 * $Id$
 */

#ifndef SQUID_ASYNC_JOB_H
#define SQUID_ASYNC_JOB_H

#include "base/AsyncCall.h"
#include "TextException.h"

template <class Cbc>
class CbcPointer;

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
/// Base class for all asynchronous jobs
class AsyncJob
{
public:
    typedef CbcPointer<AsyncJob> Pointer;

public:
    AsyncJob(const char *aTypeName);
    virtual ~AsyncJob();

    virtual void *toCbdata() = 0;

    /// starts a freshly created job (i.e., makes the job asynchronous)
    static Pointer Start(AsyncJob *job);

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

#endif /* SQUID_ASYNC_JOB_H */
