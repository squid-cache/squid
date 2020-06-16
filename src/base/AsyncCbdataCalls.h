/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_ASYNCCBDATACALLS_H
#define SQUID_BASE_ASYNCCBDATACALLS_H

#include "base/AsyncCall.h"
#include "base/CbcPointer.h"

// dialer to run cbdata callback functions as Async Calls
// to ease the transition of these cbdata objects to full Jobs
template<class Argument1>
class UnaryCbdataDialer : public CallDialer
{
public:
    typedef void Handler(Argument1 *);

    UnaryCbdataDialer(Handler *aHandler, Argument1 *aArg) :
        arg1(aArg),
        handler(aHandler)
    {}

    virtual bool canDial(AsyncCall &) { return arg1.valid(); }
    void dial(AsyncCall &) { handler(arg1.get()); }
    virtual void print(std::ostream &os) const {  os << '(' << arg1 << ')'; }

public:
    CbcPointer<Argument1> arg1;
    Handler *handler;
};

// helper function to simplify Dialer creation.
template <class Argument1>
UnaryCbdataDialer<Argument1>
cbdataDialer(typename UnaryCbdataDialer<Argument1>::Handler *handler, Argument1 *arg1)
{
    return UnaryCbdataDialer<Argument1>(handler, arg1);
}

#endif

