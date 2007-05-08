/*
 * DEBUG: section 93  ICAP (RFC 3507) Client
 */

#include "squid.h"
#include "cbdata.h"
#include "TextException.h"
#include "AsyncJob.h"


AsyncJob *AsyncJob::AsyncStart(AsyncJob *job) {
    assert(job);
    job = cbdataReference(job); // unlocked when done() in callEnd()
    AsyncCall(93,5, job, AsyncJob::noteStart);
    return job;
}

AsyncJob::AsyncJob(const char *aTypeName): typeName(aTypeName), inCall(NULL)
{
}

AsyncJob::~AsyncJob()
{
}

void AsyncJob::noteStart()
{
    AsyncCallEnter(noteStart);

    start();

    AsyncCallExit();
}

void AsyncJob::start()
{
    Must(cbdataReferenceValid(this)); // locked in AsyncStart
}

void AsyncJob::mustStop(const char *aReason)
{
    Must(inCall); // otherwise nobody will delete us if we are done()
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

bool AsyncJob::callStart(const char *method)
{
    debugs(93, 5, typeName << "::" << method << " called" << status());

    if (inCall) {
        // this may happen when we have bugs or when arguably buggy
        // comm interface calls us while we are closing the connection
        debugs(93, 5, HERE << typeName << "::" << inCall <<
               " is in progress; " << typeName << "::" << method <<
               " cancels reentry.");
        return false;
    }

    inCall = method;
    return true;
}

void AsyncJob::callException(const TextException &e)
{
    debugs(93, 2, typeName << "::" << inCall << " caught an exception: " <<
           e.message << ' ' << status());

    mustStop("exception");
}

void AsyncJob::callEnd()
{
    if (done()) {
        debugs(93, 5, typeName << "::" << inCall << " ends job " <<
            status());

        const char *inCallSaved = inCall;
        const char *typeNameSaved = typeName;
        void *thisSaved = this;

        swanSong();

        void *cbdata = this;
        delete this; // this is the only place where the object is deleted
        cbdataReferenceDone(cbdata); // locked by AsyncStart

        // careful: this object does not exist any more
        debugs(93, 6, HERE << typeNameSaved << "::" << inCallSaved <<
            " ended " << thisSaved);
        return;
    }

    debugs(93, 6, typeName << "::" << inCall << " ended" << status());
    inCall = NULL;
}

