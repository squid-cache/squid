/*
 * DEBUG: section 93    ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "cbdata.h"
#include "MemBuf.h"
#include "TextException.h"
#include "base/AsyncJob.h"
#include "base/AsyncCall.h"


unsigned int AsyncJob::TheLastId = 0;

AsyncJob *AsyncJob::AsyncStart(AsyncJob *job)
{
    assert(job);
    CallJobHere(93, 5, job, AsyncJob::noteStart);
    return job;
}

AsyncJob::AsyncJob(const char *aTypeName): typeName(aTypeName), inCall(NULL), id(++TheLastId)
{
    debugs(93,3, "AsyncJob of type " << typeName << " constructed, this=" << this <<
           " [async" << id << ']');
}

AsyncJob::~AsyncJob()
{
}

void AsyncJob::noteStart()
{
    start();
}

void AsyncJob::start()
{
}

// XXX: temporary code to replace calls to "delete this" in jobs-in-transition.
// Will be replaced with calls to mustStop() when transition is complete.
void AsyncJob::deleteThis(const char *aReason)
{
    Must(aReason);
    stopReason = aReason;
    if (inCall != NULL) {
        // if we are in-call, then the call wrapper will delete us
        debugs(93, 4, typeName << " will NOT delete in-call job, reason: " << stopReason);
        return;
    }

    // there is no call wrapper waiting for our return, so we fake it
    debugs(93, 5, typeName << " will delete this, reason: " << stopReason);
    AsyncCall::Pointer fakeCall = asyncCall(93,4, "FAKE-deleteThis",
                                            MemFun(this, &AsyncJob::deleteThis, aReason));
    inCall = fakeCall;
    callEnd();
//    delete fakeCall;
}

void AsyncJob::mustStop(const char *aReason)
{
    // XXX: temporary code to catch cases where mustStop is called outside
    // of an async call context. Will be removed when that becomes impossible.
    // Until then, this will cause memory leaks and possibly other problems.
    if (!inCall) {
        stopReason = aReason;
        debugs(93, 5, typeName << " will STALL, reason: " << stopReason);
        return;
    }

    Must(inCall != NULL); // otherwise nobody will delete us if we are done()
    Must(aReason);
    if (!stopReason) {
        stopReason = aReason;
        debugs(93, 5, typeName << " will stop, reason: " << stopReason);
    } else {
        debugs(93, 5, typeName << " will stop, another reason: " << aReason);
    }
}

bool AsyncJob::done() const
{
    // stopReason, set in mustStop(), overwrites all other conditions
    return stopReason != NULL || doneAll();
}

bool AsyncJob::doneAll() const
{
    return true; // so that it is safe for kids to use
}

bool AsyncJob::canBeCalled(AsyncCall &call) const
{
    if (inCall != NULL) {
        // This may happen when we have bugs or some module is not calling
        // us asynchronously (comm used to do that).
        debugs(93, 5, HERE << inCall << " is in progress; " <<
               call << " canot reenter the job.");
        return call.cancel("reentrant job call");
    }

    return true;
}

void AsyncJob::callStart(AsyncCall &call)
{
    // we must be called asynchronously and hence, the caller must lock us
    Must(cbdataReferenceValid(toCbdata()));

    Must(!inCall); // see AsyncJob::canBeCalled

    inCall = &call; // XXX: ugly, but safe if callStart/callEnd,Ex are paired
    debugs(inCall->debugSection, inCall->debugLevel,
           typeName << " status in:" << status());
}

void AsyncJob::callException(const std::exception &e)
{
    // we must be called asynchronously and hence, the caller must lock us
    Must(cbdataReferenceValid(toCbdata()));

    mustStop("exception");
}

void AsyncJob::callEnd()
{
    if (done()) {
        debugs(93, 5, *inCall << " ends job" << status());

        AsyncCall::Pointer inCallSaved = inCall;
        void *thisSaved = this;

        swanSong();

        delete this; // this is the only place where the object is deleted

        // careful: this object does not exist any more
        debugs(93, 6, HERE << *inCallSaved << " ended " << thisSaved);
        return;
    }

    debugs(inCall->debugSection, inCall->debugLevel,
           typeName << " status out:" << status());
    inCall = NULL;
}

// returns a temporary string depicting transaction status, for debugging
const char *AsyncJob::status() const
{
    static MemBuf buf;
    buf.reset();

    buf.append(" [", 2);
    if (stopReason != NULL) {
        buf.Printf("Stopped, reason:");
        buf.Printf("%s",stopReason);
    }
    buf.Printf(" job%d]", id);
    buf.terminate();

    return buf.content();
}


/* JobDialer */

JobDialer::JobDialer(AsyncJob *aJob): job(NULL), lock(NULL)
{
    if (aJob) {
        lock = cbdataReference(aJob->toCbdata());
        job = aJob;
    }
}

JobDialer::JobDialer(const JobDialer &d): CallDialer(d),
        job(NULL), lock(NULL)
{
    if (d.lock && cbdataReferenceValid(d.lock)) {
        lock = cbdataReference(d.lock);
        Must(d.job);
        job = d.job;
    }
}

JobDialer::~JobDialer()
{
    cbdataReferenceDone(lock); // lock may be NULL
}


bool
JobDialer::canDial(AsyncCall &call)
{
    if (!lock)
        return call.cancel("job was gone before the call");

    if (!cbdataReferenceValid(lock))
        return call.cancel("job gone after the call");

    Must(job);
    return job->canBeCalled(call);
}

void
JobDialer::dial(AsyncCall &call)
{
    Must(lock && cbdataReferenceValid(lock)); // canDial() checks for this
    Must(job);

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
