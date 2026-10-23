/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "engines/libengines.la"
#include "tests/STUB.h"

#include "engines/AsyncEngine.h"

#include "engines/EventLoop.h"
EventLoop *EventLoop::Running = nullptr;
void EventLoop::run() STUB
bool EventLoop::runOnce() STUB
void EventLoop::setPrimaryEngine(AsyncEngine * const) STUB
