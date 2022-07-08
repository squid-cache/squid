/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_ASYNCFUNCALLS_H
#define SQUID_BASE_ASYNCFUNCALLS_H

#include "base/AsyncCall.h"

#include <iostream>

/// Calls a function without arguments. See also: NullaryMemFunT.
class NullaryFunDialer: public CallDialer
{
public:
    using Handler = void ();

    explicit NullaryFunDialer(Handler * const aHandler): handler(aHandler) {}

    /* CallDialer API */
    bool canDial(AsyncCall &) { return bool(handler); }
    void dial(AsyncCall &) { handler(); }
    virtual void print(std::ostream &os) const override { os << "()"; }

private:
    Handler *handler; ///< the function to call (or nil)
};

/// CallDialer for single-parameter stand-alone functions
template <typename Argument1>
class UnaryFunDialer: public CallDialer
{
public:
    // stand-alone function that receives our answer
    using Handler = void (const Argument1 &);

    UnaryFunDialer(Handler * const aHandler, const Argument1 &anArg1):
        handler(aHandler),
        arg1(anArg1)
    {}
    virtual ~UnaryFunDialer() = default;

    /* CallDialer API */
    bool canDial(AsyncCall &) { return bool(handler); }
    void dial(AsyncCall &) { handler(arg1); }
    virtual void print(std::ostream &os) const final { os << '(' << arg1 << ')'; }

private:
    Handler *handler; ///< the function to call
    Argument1 arg1; ///< actual call parameter
};

/// helper function to simplify UnaryFunDialer creation
template <typename Argument1>
UnaryFunDialer<Argument1>
callDialer(void (*handler)(const Argument1 &), const Argument1 &arg1)
{
    return UnaryFunDialer<Argument1>(handler, arg1);
}

#endif /* SQUID_BASE_ASYNCFUNCALLS_H */

