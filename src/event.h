/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_EVENT_H
#define SQUID_EVENT_H

#include "AsyncEngine.h"
#include "base/CodeContext.h"
#include "mem/forward.h"

class StoreEntry;

/* event scheduling facilities - run a callback after a given time period. */

typedef void EVH(void *);

void eventAdd(const char *name, EVH * func, void *arg, double when, int, bool cbdata=true);
void eventAddIsh(const char *name, EVH * func, void *arg, double delta_ish, int);
void eventDelete(EVH * func, void *arg);
void eventInit(void);
void eventFreeMemory(void);
int eventFind(EVH *, void *);

class ev_entry
{
    MEMPROXY_CLASS(ev_entry);

public:
    ev_entry(char const * name, EVH * func, void *arg, double when, int weight, bool cbdata=true);
    ~ev_entry();
    const char *name;
    EVH *func;
    void *arg;
    double when;

    int weight;
    bool cbdata;

    CodeContext::Pointer codeContext; ///< event creator's context
    ev_entry *next;
};

// manages time-based events
class EventScheduler : public AsyncEngine
{

public:
    EventScheduler();
    ~EventScheduler();
    /* cancel a scheduled but not dispatched event */
    void cancel(EVH * func, void * arg);
    /* clean up the used memory in the scheduler */
    void clean();
    /* either EVENT_IDLE or milliseconds remaining until the next event */
    int timeRemaining() const;
    /* cache manager output for the event queue */
    void dump(StoreEntry *);
    /* find a scheduled event */
    bool find(EVH * func, void * arg);
    /* schedule a callback function to run in when seconds */
    void schedule(const char *name, EVH * func, void *arg, double when, int weight, bool cbdata=true);
    int checkEvents(int timeout);
    static EventScheduler *GetInstance();

private:
    static EventScheduler _instance;
    ev_entry * tasks;
};

#endif /* SQUID_EVENT_H */

