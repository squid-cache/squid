/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_TESTS_TESTSTORESUPPORT_H
#define SQUID_SRC_TESTS_TESTSTORESUPPORT_H

#include "EventLoop.h"
#include "time/Engine.h"

/* construct a stock loop with event dispatching, a time service that advances
 * 1 second a tick
 */

class StockEventLoop : public EventLoop
{

public:
    StockEventLoop();
    Time::Engine default_time_engine;
};

#endif /* SQUID_SRC_TESTS_TESTSTORESUPPORT_H */

