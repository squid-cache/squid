/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 41    Event Processing */

#include "squid.h"
#include "base/Random.h"
#include "event.h"
#include "mgr/Registration.h"
#include "Store.h"
#include "tools.h"

#include <cmath>

/* The list of event processes */

static OBJH eventDump;
static const char *last_event_ran = nullptr;

// This AsyncCall dialer can be configured to check that the event cbdata is
// valid before calling the event handler
class EventDialer: public CallDialer
{
public:
    typedef CallDialer Parent;

    EventDialer(EVH *aHandler, void *anArg, bool lockedArg);
    EventDialer(const EventDialer &d);
    ~EventDialer() override;

    void print(std::ostream &os) const override;
    virtual bool canDial(AsyncCall &call);

    void dial(AsyncCall &) { theHandler(theArg); }

private:
    EVH *theHandler;
    void *theArg;
    bool isLockedArg;
};

EventDialer::EventDialer(EVH *aHandler, void *anArg, bool lockedArg):
    theHandler(aHandler), theArg(anArg), isLockedArg(lockedArg)
{
    if (isLockedArg)
        (void)cbdataReference(theArg);
}

EventDialer::EventDialer(const EventDialer &d):
    theHandler(d.theHandler), theArg(d.theArg), isLockedArg(d.isLockedArg)
{
    if (isLockedArg)
        (void)cbdataReference(theArg);
}

EventDialer::~EventDialer()
{
    if (isLockedArg)
        cbdataReferenceDone(theArg);
}

bool
EventDialer::canDial(AsyncCall &call)
{
    // TODO: add Parent::canDial() that always returns true
    //if (!Parent::canDial())
    //    return false;

    if (isLockedArg && !cbdataReferenceValid(theArg))
        return call.cancel("stale handler data");

    return true;
}

void
EventDialer::print(std::ostream &os) const
{
    os << '(';
    if (theArg)
        os << theArg << (isLockedArg ? "*?" : "");
    os << ')';
}

ev_entry::ev_entry(char const * aName, EVH * aFunction, void * aArgument, double evWhen, int aWeight, bool haveArg) :
    name(aName),
    func(aFunction),
    arg(haveArg ? cbdataReference(aArgument) : aArgument),
    when(evWhen),
    weight(aWeight),
    cbdata(haveArg),
    next(nullptr)
{
}

ev_entry::~ev_entry()
{
    if (cbdata)
        cbdataReferenceDone(arg);
}

void
eventAdd(const char *name, EVH * func, void *arg, double when, int weight, bool cbdata)
{
    EventScheduler::GetInstance()->schedule(name, func, arg, when, weight, cbdata);
}

/* same as eventAdd but adds a random offset within +-1/3 of delta_ish */
void
eventAddIsh(const char *name, EVH * func, void *arg, double delta_ish, int weight)
{
    if (delta_ish >= 3.0) {
        static std::mt19937 rng(RandomSeed32());
        auto third = (delta_ish/3.0);
        std::uniform_real_distribution<> thirdIsh(delta_ish - third, delta_ish + third);
        delta_ish = thirdIsh(rng);
    }

    eventAdd(name, func, arg, delta_ish, weight);
}

void
eventDelete(EVH * func, void *arg)
{
    EventScheduler::GetInstance()->cancel(func, arg);
}

void
eventInit(void)
{
    Mgr::RegisterAction("events", "Event Queue", eventDump, 0, 1);
}

static void
eventDump(StoreEntry * sentry)
{
    EventScheduler::GetInstance()->dump(sentry);
}

int
eventFind(EVH * func, void *arg)
{
    return EventScheduler::GetInstance()->find(func, arg);
}

EventScheduler EventScheduler::_instance;

EventScheduler::EventScheduler(): tasks(nullptr)
{}

EventScheduler::~EventScheduler()
{
    clean();
}

void
EventScheduler::cancel(EVH * func, void *arg)
{
    ev_entry **E;
    ev_entry *event;

    for (E = &tasks; (event = *E) != nullptr; E = &(*E)->next) {
        if (event->func != func)
            continue;

        if (arg && event->arg != arg)
            continue;

        *E = event->next;

        delete event;

        if (arg)
            return;
        /*
         * DPW 2007-04-12
         * Since this method may now delete multiple events (when
         * arg is NULL) it no longer returns after a deletion and
         * we have a potential NULL pointer problem.  If we just
         * deleted the last event in the list then *E is now equal
         * to NULL.  We need to break here or else we'll get a NULL
         * pointer dereference in the last clause of the for loop.
         */
        if (nullptr == *E)
            break;
    }

    if (arg)
        debug_trap("eventDelete: event not found");
}

// The event API does not guarantee exact timing, but guarantees that no event
// is fired before it is due. We may delay firing, but never fire too early.
int
EventScheduler::timeRemaining() const
{
    if (!tasks)
        return EVENT_IDLE;

    if (tasks->when <= current_dtime) // we are on time or late
        return 0; // fire the event ASAP

    const double diff = tasks->when - current_dtime; // seconds
    // Round UP: If we come back a nanosecond earlier, we will wait again!
    const int timeLeft = static_cast<int>(ceil(1000*diff)); // milliseconds
    // Avoid hot idle: A series of rapid select() calls with zero timeout.
    const int minDelay = 1; // millisecond
    return max(minDelay, timeLeft);
}

int
EventScheduler::checkEvents(int)
{
    int result = timeRemaining();
    if (result != 0)
        return result;

    do {
        ev_entry *event = tasks;
        assert(event);

        /* XXX assumes event->name is static memory! */
        AsyncCall::Pointer call = asyncCall(41,5, event->name,
                                            EventDialer(event->func, event->arg, event->cbdata));
        ScheduleCallHere(call);

        last_event_ran = event->name; // XXX: move this to AsyncCallQueue
        const bool heavy = event->weight &&
                           (!event->cbdata || cbdataReferenceValid(event->arg));

        tasks = event->next;
        delete event;

        result = timeRemaining();

        // XXX: We may be called again during the same event loop iteration.
        // Is there a point in breaking now?
        if (heavy)
            break; // do not dequeue events following a heavy event
    } while (result == 0);

    return result;
}

void
EventScheduler::clean()
{
    while (ev_entry * event = tasks) {
        tasks = event->next;
        delete event;
    }

    tasks = nullptr;
}

void
EventScheduler::dump(Packable *out)
{
    if (last_event_ran)
        out->appendf("Last event to run: %s\n\n", last_event_ran);

    out->appendf("%-25s\t%-15s\t%s\t%s\n",
                 "Operation",
                 "Next Execution",
                 "Weight",
                 "Callback Valid?");

    for (auto *e = tasks; e; e = e->next) {
        out->appendf("%-25s\t%0.3f sec\t%5d\t %s\n",
                     e->name, (e->when ? e->when - current_dtime : 0), e->weight,
                     (e->arg && e->cbdata) ? cbdataReferenceValid(e->arg) ? "yes" : "no" : "N/A");
    }
}

bool
EventScheduler::find(EVH * func, void * arg)
{

    ev_entry *event;

    for (event = tasks; event != nullptr; event = event->next) {
        if (event->func == func && event->arg == arg)
            return true;
    }

    return false;
}

EventScheduler *
EventScheduler::GetInstance()
{
    return &_instance;
}

void
EventScheduler::schedule(const char *name, EVH * func, void *arg, double when, int weight, bool cbdata)
{
    // Use zero timestamp for when=0 events: Many of them are async calls that
    // must fire in the submission order. We cannot use current_dtime for them
    // because it may decrease if system clock is adjusted backwards.
    const double timestamp = when > 0.0 ? current_dtime + when : 0;
    ev_entry *event = new ev_entry(name, func, arg, timestamp, weight, cbdata);

    ev_entry **E;
    debugs(41, 7, "schedule: Adding '" << name << "', in " << when << " seconds");
    /* Insert after the last event with the same or earlier time */

    for (E = &tasks; *E; E = &(*E)->next) {
        if ((*E)->when > event->when)
            break;
    }

    event->next = *E;
    *E = event;
}

