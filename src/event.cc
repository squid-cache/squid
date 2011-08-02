/*
 * $Id$
 *
 * DEBUG: section 41    Event Processing
 * AUTHOR: Henrik Nordstrom
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "event.h"
#include "CacheManager.h"
#include "Store.h"
#include "SquidTime.h"

/* The list of event processes */


static OBJH eventDump;
static const char *last_event_ran = NULL;

// This AsyncCall dialer can be configured to check that the event cbdata is
// valid before calling the event handler
class EventDialer: public CallDialer
{
public:
    typedef CallDialer Parent;

    EventDialer(EVH *aHandler, void *anArg, bool lockedArg);
    EventDialer(const EventDialer &d);
    virtual ~EventDialer();

    virtual void print(std::ostream &os) const;
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


ev_entry::ev_entry(char const * aName, EVH * aFunction, void * aArgument, double evWhen,
                   int aWeight, bool haveArgument) : name(aName), func(aFunction),
        arg(haveArgument ? cbdataReference(aArgument) : aArgument), when(evWhen), weight(aWeight),
        cbdata(haveArgument)
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
        const double two_third = (2.0 * delta_ish) / 3.0;
        delta_ish = two_third + (drand48() * two_third);
        /*
         * I'm sure drand48() isn't portable.  Tell me what function
         * you have that returns a random double value in the range 0,1.
         */
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
    CacheManager::GetInstance()->
    registerAction("events", "Event Queue", eventDump, 0, 1);
}

static void
eventDump(StoreEntry * sentry)
{
    EventScheduler::GetInstance()->dump(sentry);
}

void
eventFreeMemory(void)
{
    EventScheduler::GetInstance()->clean();
}

int
eventFind(EVH * func, void *arg)
{
    return EventScheduler::GetInstance()->find(func, arg);
}

EventScheduler EventScheduler::_instance;

EventScheduler::EventScheduler(): tasks(NULL)
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

    for (E = &tasks; (event = *E) != NULL; E = &(*E)->next) {
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
        if (NULL == *E)
            break;
    }

    if (arg)
        debug_trap("eventDelete: event not found");
}

int
EventScheduler::checkDelay()
{
    if (!tasks)
        return EVENT_IDLE;

    int result = (int) ((tasks->when - current_dtime) * 1000);

    if (result < 0)
        return 0;

    return result;
}

int
EventScheduler::checkEvents(int timeout)
{

    ev_entry *event = NULL;

    if (NULL == tasks)
        return checkDelay();

    if (tasks->when > current_dtime)
        return checkDelay();

    PROF_start(eventRun);

    debugs(41, 5, HERE << "checkEvents");

    while ((event = tasks)) {
        if (event->when > current_dtime)
            break;

        /* XXX assumes event->name is static memory! */
        AsyncCall::Pointer call = asyncCall(41,5, event->name,
                                            EventDialer(event->func, event->arg, event->cbdata));
        ScheduleCallHere(call);

        last_event_ran = event->name; // XXX: move this to AsyncCallQueue
        const bool heavy = event->weight &&
                           (!event->cbdata || cbdataReferenceValid(event->arg));

        tasks = event->next;
        delete event;

        // XXX: We may be called again during the same event loop iteration.
        // Is there a point in breaking now?
        if (heavy)
            break; // do not dequeue events following a heavy event
    }

    PROF_stop(eventRun);
    return checkDelay();
}

void
EventScheduler::clean()
{
    while (ev_entry * event = tasks) {
        tasks = event->next;
        delete event;
    }

    tasks = NULL;
}

void
EventScheduler::dump(StoreEntry * sentry)
{

    ev_entry *e = tasks;

    if (last_event_ran)
        storeAppendPrintf(sentry, "Last event to run: %s\n\n", last_event_ran);

    storeAppendPrintf(sentry, "%-25s\t%-15s\t%s\t%s\n",
                      "Operation",
                      "Next Execution",
                      "Weight",
                      "Callback Valid?");

    while (e != NULL) {
        storeAppendPrintf(sentry, "%-25s\t%0.3f sec\t%5d\t %s\n",
                          e->name, e->when ? e->when - current_dtime : 0, e->weight,
                  (e->arg && e->cbdata) ? cbdataReferenceValid(e->arg) ? "yes" : "no" : "N/A");
        e = e->next;
    }
}

bool
EventScheduler::find(EVH * func, void * arg)
{

    ev_entry *event;

    for (event = tasks; event != NULL; event = event->next) {
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
    debugs(41, 7, HERE << "schedule: Adding '" << name << "', in " << when << " seconds");
    /* Insert after the last event with the same or earlier time */

    for (E = &tasks; *E; E = &(*E)->next) {
        if ((*E)->when > event->when)
            break;
    }

    event->next = *E;
    *E = event;
}
