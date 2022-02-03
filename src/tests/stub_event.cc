/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "event.cc"
#include "tests/STUB.h"

#include "event.h"
EventScheduler::EventScheduler() STUB
EventScheduler::~EventScheduler() STUB
void EventScheduler::cancel(EVH *, void *) STUB
int EventScheduler::timeRemaining() const STUB_RETVAL(1)
void EventScheduler::clean() STUB
void EventScheduler::dump(Packable *) STUB
bool EventScheduler::find(EVH *, void *) STUB_RETVAL(false)
void EventScheduler::schedule(const AsyncCall::Pointer &, double, int) STUB
void EventScheduler::schedule(const char *, EVH *, void *, double, int, bool) STUB
void EventScheduler::scheduleIsh(const AsyncCall::Pointer &, double) STUB
void EventScheduler::remove(const AsyncCall::Pointer &) STUB
int EventScheduler::checkEvents(int) STUB_RETVAL(-1)
EventScheduler &Events() STUB_RETREF(EventScheduler)
void eventAddIsh(const char *, EVH *, void *, double, int) STUB
void eventInit(void) STUB

