/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_EVENT_H
#define SQUID_EVENT_H

#include "AsyncEngine.h"
#include "base/AsyncCall.h"
#include "base/Packable.h"
#include "mem/forward.h"

/* event scheduling facilities - run a callback after a given time period. */

typedef void EVH(void *);

/// an entry in the queue of waiting events
class ev_entry
{
    MEMPROXY_CLASS(ev_entry);

public:
    ev_entry(double when, int weight, const AsyncCall::Pointer &);
    // no copying or moving of any kind (for simplicity and to prevent accidental copies)
    ev_entry(ev_entry &&) = delete;

public:
    double when; ///< when this event is due to run
    int weight; ///< deprecated weight hack, avoids
    AsyncCall::Pointer call; ///< the AsyncCall which will perform this event

    ev_entry *next = nullptr;
};

/// Manages time-based events
class EventScheduler : public AsyncEngine
{

public:
    EventScheduler();
    ~EventScheduler();

    /// clean up the used memory in the scheduler
    void clean();

    /// either EVENT_IDLE or milliseconds remaining until the next event
    int timeRemaining() const;

    /// cache manager output for the event queue
    void dump(Packable *);

    /// schedule an AsyncCall run in when seconds
    void schedule(const AsyncCall::Pointer &, double when, int = 0);
    /// schedule an AsyncCall run in when +/-30% seconds
    void scheduleIsh(const AsyncCall::Pointer &, double when);
    /// \deprecated schedule a callback function to run in when seconds. Use AsyncCall instead.
    void schedule(const char *name, EVH * func, void *arg, double when, int weight, bool cbdata=true);

    /// \deprecated find a scheduled callback function. Use AsyncCall instead.
    bool find(EVH * func, void * arg);

    /// \deprecated cancel a scheduled but not dispatched event
    /// Use AsyncCall API to cancel() the Call instead.
    void cancel(EVH * func, void * arg);

    /// remove a scheduled but not dispatched event
    void remove(const AsyncCall::Pointer &);

    /* AsyncEngine API */
    int checkEvents(int) override;

private:
    ev_entry * tasks;
};

/// global queue of events waiting to happen
EventScheduler &Events();

/// perform any startup tasks needed by the EventScheduler
extern void eventInit();

/// \see EventScheduler::clean()
inline void
eventFreeMemory()
{
    Events().clean();
}

/// \see EventScheduler::schedule()
inline void
eventAdd(AsyncCall::Pointer &c, double when)
{
    Events().schedule(c, when);
}

/// \see EventScheduler::scheduleIsh()
inline void
eventAddIsh(AsyncCall::Pointer &c, double when)
{
    Events().scheduleIsh(c, when);
}

/// \see EventScheduler::remove()
inline void
eventDelete(AsyncCall::Pointer &c)
{
    Events().remove(c);
}

/* Legacy C API for event management. Use API with AsyncCall instead */

/// \see EventScheduler::schedule()
inline void
eventAdd(const char *name, EVH * func, void *arg, double when, int weight, bool cbdata = true)
{
    Events().schedule(name, func, arg, when, weight, cbdata);
}

/// \see EventScheduler::scheduleIsh()
void eventAddIsh(const char *name, EVH * func, void *arg, double delta_ish, int);

/// \see EventScheduler::find()
inline bool
eventFind(EVH * func, void *arg)
{
    return Events().find(func, arg);
}

/// \see EventScheduler::cancel()
inline void
eventDelete(EVH * func, void *arg)
{
    Events().cancel(func, arg);
}

#endif /* SQUID_EVENT_H */

