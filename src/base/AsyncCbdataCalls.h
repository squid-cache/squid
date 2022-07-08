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

// TODO: Misplaced. This header is about cbdata-protected calls
/// CallDialer for single-parameter callback functions
template <typename Argument1>
class UnaryFunCallbackDialer:
    public CallDialer,
    public WithAnswer<Argument1>
{
public:
    // stand-alone function that receives our answer
    using Handler = void (Argument1 &);

    explicit UnaryFunCallbackDialer(Handler * const aHandler): handler(aHandler) {}
    virtual ~UnaryFunCallbackDialer() = default;

    /* CallDialer API */
    bool canDial(AsyncCall &) { return bool(handler); }
    void dial(AsyncCall &) { handler(arg1); }
    virtual void print(std::ostream &os) const final { os << '(' << arg1 << ')'; }

    /* WithAnswer API */
    virtual Argument1 &answer() final { return arg1; }

private:
    Handler *handler; ///< the function to call
    Argument1 arg1; ///< actual call parameter
};

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
    virtual void print(std::ostream &os) const final { os << '(' << arg1_ << ')'; }

    /* WithAnswer API */
    virtual Argument1 &answer() final { return arg1_; }

private:
    CbcPointer<Destination> destination_; ///< object to deliver the answer to
    Method method_; ///< Destination method to call with the answer
    Argument1 arg1_;
};

#include "base/AsyncJobCalls.h" // XXX

/// XXX:
template <class Job, typename Argument1>
class UnaryJobCallbackDialer:
    public UnaryMemFunT<Job, Argument1, Argument1&>,
    public WithAnswer<Argument1>
{
public:
    using Base = UnaryMemFunT<Job, Argument1, Argument1&>;

    UnaryJobCallbackDialer(const CbcPointer<Job> &aJob, typename Base::Method aMethod):
        Base(aJob, aMethod, {}) {}

    /* WithAnswer API */
    virtual Argument1 &answer() final { return this->arg1; }
};

// XXX: Duplicates SquidMath.h!
/// std::enable_if_t replacement until C++14
/// simplifies declarations further below
template <bool B, class T = void>
using EnableIf = typename std::enable_if<B,T>::type;

/// whether the given type is an AsyncJob
/// reduces code duplication in declarations further below
template <typename T>
using IsAsyncJob = typename std::conditional<
                   std::is_base_of<AsyncJob, T>::value,
                   std::true_type,
                   std::false_type
                   >::type;

// TODO: rename to callbackDialer()
/// helper function to simplify UnaryCbcCallbackDialer creation
template <class Destination, typename Argument1, EnableIf<!IsAsyncJob<Destination>::value, int> = 0>
UnaryCbcCallbackDialer<Destination, Argument1>
cbcCallbackDialer(Destination *destination, void (Destination::*method)(Argument1 &))
{
    static_assert(!std::is_base_of<AsyncJob, Destination>::value, "wrong wrapper");
    return UnaryCbcCallbackDialer<Destination, Argument1>(method, destination);
}

/// helper function to simplify UnaryCbcCallbackDialer creation
template <class Destination, typename Argument1, EnableIf<IsAsyncJob<Destination>::value, int> = 0>
UnaryJobCallbackDialer<Destination, Argument1>
cbcCallbackDialer(Destination *destination, void (Destination::*method)(Argument1 &))
{
    static_assert(std::is_base_of<AsyncJob, Destination>::value, "wrong wrapper");
    return UnaryJobCallbackDialer<Destination, Argument1>(destination, method);
}

/// helper function to simplify UnaryCbcCallbackDialer creation
template <typename Argument1>
UnaryFunCallbackDialer<Argument1>
cbcCallbackDialer(void (*destination)(Argument1 &))
{
    return UnaryFunCallbackDialer<Argument1>(destination);
}

#endif

