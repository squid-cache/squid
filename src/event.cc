
/*
 * $Id: event.cc,v 1.2 1996/11/14 19:02:15 wessels Exp $
 *
 * DEBUG: Section 41    Event Processing
 * AUTHOR: Henrik Nordstrom
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

/* The list of event processes */
struct ev_entry {
    EVH func;
    void *arg;
    const char *name;
    time_t when;
    struct ev_entry *next;
};

static struct ev_entry *tasks = NULL;

void
eventAdd(const char *name, EVH func, void *arg, time_t when)
{
    struct ev_entry *event = xcalloc(1, sizeof(struct ev_entry));
    struct ev_entry **E;
    event->func = func;
    event->arg = arg;
    event->name = name;
    event->when = squid_curtime + when;
    debug(41, 3, "eventAdd: Adding '%s', in %d seconds\n", name, when);
    /* Insert after the last event with the same or earlier time */
    for (E = &tasks; *E; E = &(*E)->next) {
	if ((*E)->when > event->when)
	    break;
    }
    event->next = *E;
    *E = event;
}

void
eventRun(void)
{
    struct ev_entry *event = NULL;
    EVH func;
    void *arg;
    if ((event = tasks) == NULL)
	return;
    if (event->when > squid_curtime)
	return;
    debug(41, 3, "eventRun: Running '%s'\n", event->name);
    func = event->func;
    arg = event->arg;
    event->func = NULL;
    event->arg = NULL;
    tasks = event->next;
    safe_free(event);
    func(arg);
}

time_t
eventNextTime(void)
{
    if (!tasks)
	return (time_t) 10;
    return tasks->when > squid_curtime;
}
