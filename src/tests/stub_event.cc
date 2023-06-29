/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "event.h"

#define STUB_API "event.cc"
#include "tests/STUB.h"

void eventAdd(const char *, EVH *, void *, double, int, bool) STUB_NOP
void eventAddIsh(const char *, EVH *, void *, double, int) STUB
void eventDelete(EVH *, void *) STUB
void eventInit(void) STUB
int eventFind(EVH *, void *) STUB_RETVAL(-1)

// ev_entry::ev_entry(char const * name, EVH * func, void *arg, double when, int weight, bool cbdata) STUB
// ev_entry::~ev_entry() STUB
//    EVH *func;

EventScheduler::EventScheduler() STUB
EventScheduler::~EventScheduler() STUB
void EventScheduler::cancel(EVH *, void *) STUB
int EventScheduler::timeRemaining() const STUB_RETVAL(1)
void EventScheduler::clean() STUB
void EventScheduler::dump(Packable *) STUB
bool EventScheduler::find(EVH *, void *) STUB_RETVAL(false)
void EventScheduler::schedule(const char *, EVH *, void *, double, int, bool) STUB
int EventScheduler::checkEvents(int) STUB_RETVAL(-1)
EventScheduler *EventScheduler::GetInstance() STUB_RETVAL(nullptr)

