/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/AsyncJobCalls.h"
#include "base/JobWait.h"

#include <cassert>
#include <iostream>

JobWaitBase::JobWaitBase() = default;

JobWaitBase::~JobWaitBase()
{
    cancel("owner gone");
}

void
JobWaitBase::start_(const AsyncJob::Pointer aJob, const AsyncCall::Pointer aCall)
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

    AsyncJob::Start(job_.get());
}

void
JobWaitBase::finish()
{
    // Unexpected callbacks might result in disasters like secrets exposure,
    // data corruption, or expensive message routing mistakes when the callback
    // info is applied to the wrong message part or acted upon prematurely.
    assert(waiting());
    clear();
}

void
JobWaitBase::cancel(const char *reason)
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

void
JobWaitBase::print(std::ostream &os) const
{
    // use a backarrow to emphasize that this is a callback: call24<-job6
    if (callback_)
        os << callback_->id << "<-";
    if (const auto rawJob = job_.get())
        os << rawJob->id;
    else
        os << job_; // raw pointer of a gone job may still be useful for triage
}

