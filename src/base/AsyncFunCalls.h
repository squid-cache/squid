/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_ASYNCFUNCALLS_H
#define SQUID_BASE_ASYNCFUNCALLS_H

#include "base/AsyncCall.h"

// dialer to run a callback function with no arguments
class NullaryFunDialer : public CallDialer
{
public:
    typedef void Handler();

    NullaryFunDialer(Handler *aHandler) :
        handler(aHandler) {}

    virtual bool canDial(AsyncCall &) { return true; }
    void dial(AsyncCall &) { handler(); }
    virtual void print(std::ostream &os) const {  os << '(' << handler << ')'; }

public:
    Handler *handler;
};

inline NullaryFunDialer
funDialer(NullaryFunDialer::Handler *handler)
{
    return NullaryFunDialer(handler);
}

#endif

