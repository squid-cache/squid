/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "EventLoop.h"

#define STUB_API "EventLoop.cc"
#include "tests/STUB.h"

EventLoop *EventLoop::Running = NULL;

EventLoop::EventLoop(): errcount(0), last_loop(false), timeService(NULL),
    primaryEngine(NULL), loop_delay(0), error(false), runOnceResult(false)
    STUB_NOP

    void EventLoop::registerEngine(AsyncEngine *engine) STUB

