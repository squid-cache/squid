#include "squid.h"
#include "EventLoop.h"

#define STUB_API "EventLoop.cc"
#include "tests/STUB.h"

EventLoop *EventLoop::Running = NULL;

EventLoop::EventLoop(): errcount(0), last_loop(false), timeService(NULL),
        primaryEngine(NULL), loop_delay(0), error(false), runOnceResult(false)
        STUB_NOP

        void EventLoop::registerEngine(AsyncEngine *engine) STUB
