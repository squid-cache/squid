/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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

/// CallDialer for single-parameter callback methods of cbdata-protected classes
template <class Destination, typename Argument1>
class UnaryCbcCallbackDialer:
    public CallDialer,
    public WithAnswer<Argument1>
{
public:
    // class member function that receives our answer
    typedef void (Destination::*Method)(Argument1 &);

    UnaryCbcCallbackDialer(Method method, Destination *destination): destination_(destination), method_(method) {}
    virtual ~UnaryCbcCallbackDialer() = default;

    /* CallDialer API */
    bool canDial(AsyncCall &) { return destination_.valid(); }
    void dial(AsyncCall &) {((*destination_).*method_)(arg1_); }
    virtual void print(std::ostream &os) const override { os << '(' << arg1_ << ')'; }

    /* WithArgument1 API */
    virtual Argument1 &answer() { return arg1_; }

private:
    CbcPointer<Destination> destination_; ///< object to deliver the answer to
    Method method_; ///< Destination method to call with the answer
    Argument1 arg1_;
};

// helper function to simplify UnaryCbcCallbackDialer creation
template <class Destination, typename Argument1>
UnaryCbcCallbackDialer<Destination, Argument1>
cbcCallbackDialer(Destination *destination, void (Destination::*method)(Argument1 &))
{
    return UnaryCbcCallbackDialer<Destination, Argument1>(method, destination);
}

#endif

