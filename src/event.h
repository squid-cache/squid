
/*
 * $Id: event.h,v 1.3 2006/09/02 12:20:53 serassio Exp $
 *
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

#ifndef SQUID_EVENT_H
#define SQUID_EVENT_H

#include "squid.h"
#include "Array.h"
#include "AsyncEngine.h"
#include "CompletionDispatcher.h"

/* forward decls */

class StoreEntry;

/* event scheduling facilities - run a callback after a given time period. */

typedef void EVH(void *);

extern void eventAdd(const char *name, EVH * func, void *arg, double when, int, bool cbdata=true);
SQUIDCEXTERN void eventAddIsh(const char *name, EVH * func, void *arg, double delta_ish, int);
SQUIDCEXTERN void eventDelete(EVH * func, void *arg);
SQUIDCEXTERN void eventInit(CacheManager &);
SQUIDCEXTERN void eventFreeMemory(void);
SQUIDCEXTERN int eventFind(EVH *, void *);

class ev_entry
{

public:
    ev_entry(char const * name, EVH * func, void *arg, double when, int weight, bool cbdata=true);
    MEMPROXY_CLASS(ev_entry);
    const char *name;
    EVH *func;
    void *arg;
    double when;

    int weight;
    bool cbdata;

    ev_entry *next;
};

MEMPROXY_CLASS_INLINE(ev_entry);

class EventDispatcher : public CompletionDispatcher
{

public:
    EventDispatcher();
    /* add an event to dequeue when dispatch is called */

    void add
        (ev_entry *);

    /* add an event to be dispatched in the future */
    void add
        (const char *name, EVH * func, void *arg, double when, int, bool cbdata=true);

    bool dispatch();

    static EventDispatcher *GetInstance();

private:
    Vector<ev_entry *> queue;

    static EventDispatcher _instance;
};

class EventScheduler : public AsyncEngine
{

public:
    /* Create an event scheduler that will hand its ready to run callbacks to
     * an EventDispatcher 
     *
     * TODO: add should include a dispatcher to use perhaps? then it would be
     * more decoupled..
     */
    EventScheduler(EventDispatcher *);
    ~EventScheduler();
    /* cancel a scheduled but not dispatched event */
    void cancel(EVH * func, void * arg);
    /* clean up the used memory in the scheduler */
    void clean();
    /* how long until the next event ? */
    int checkDelay();
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
    EventDispatcher * dispatcher;
    ev_entry * tasks;
};

#endif /* SQUID_EVENT_H */
