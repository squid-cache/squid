/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "event.h"
#include "EventLoop.h"
#include "SquidTime.h"
#include "testStoreSupport.h"

/* construct a stock loop with event dispatching, a time service that advances
 * 1 second a tick
 */
StockEventLoop::StockEventLoop() : default_time_engine(TimeEngine())
{
    registerEngine(EventScheduler::GetInstance());
    setTimeService(&default_time_engine);
}

