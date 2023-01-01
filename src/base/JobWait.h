/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_JOBWAIT_H
#define SQUID_BASE_JOBWAIT_H

#include "base/AsyncJob.h"
#include "base/CbcPointer.h"

#include <iosfwd>

/// Manages waiting for an AsyncJob callback. Use type-safe JobWait instead.
/// This base class does not contain code specific to the actual Job type.
class JobWaitBase
{
public:
    JobWaitBase();
    ~JobWaitBase();

    /// no copying of any kind: each waiting context needs a dedicated AsyncCall
    JobWaitBase(JobWaitBase &&) = delete;

    explicit operator bool() const { return waiting(); }

    /// whether we are currently waiting for the job to call us back
    /// the job itself may be gone even if this returns true
    bool waiting() const { return bool(callback_); }

    /// ends wait (after receiving the call back)
    /// forgets the job which is likely to be gone by now
    void finish();

    /// aborts wait (if any) before receiving the call back
    /// does nothing if we are not waiting
    void cancel(const char *reason);

    /// summarizes what we are waiting for (for debugging)
    void print(std::ostream &) const;

protected:
    /// starts waiting for the given job to call the given callback
    void start_(AsyncJob::Pointer, AsyncCall::Pointer);

private:
    /// the common part of finish() and cancel()
    void clear() { job_.clear(); callback_ = nullptr; }

    /// the job that we are waiting to call us back (or nil)
    AsyncJob::Pointer job_;

    /// the call we are waiting for the job_ to make (or nil)
    AsyncCall::Pointer callback_;
};

/// Manages waiting for an AsyncJob callback.
/// Completes JobWaitBase by providing Job type-specific members.
template <class Job>
class JobWait: public JobWaitBase
{
public:
    typedef CbcPointer<Job> JobPointer;

    /// starts waiting for the given job to call the given callback
    void start(const JobPointer &aJob, const AsyncCall::Pointer &aCallback) {
        start_(aJob, aCallback);
        typedJob_ = aJob;
    }

    /// \returns a cbdata pointer to the job we are waiting for (or nil)
    /// the returned pointer may be falsy, even if we are still waiting()
    JobPointer job() const { return waiting() ? typedJob_ : nullptr; }

private:
    /// nearly duplicates JobWaitBase::job_ but exposes the actual job type
    JobPointer typedJob_;
};

inline
std::ostream &operator <<(std::ostream &os, const JobWaitBase &wait)
{
    wait.print(os);
    return os;
}

#endif /* SQUID_BASE_JOBWAIT_H */

