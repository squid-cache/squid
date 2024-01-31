/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_ASYNCFUNCALLS_H
#define SQUID_SRC_BASE_ASYNCFUNCALLS_H

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
    void print(std::ostream &os) const override { os << "()"; }

private:
    Handler *handler; ///< the function to call (or nil)
};

/// CallDialer for single-parameter stand-alone functions
template <typename Argument1>
class UnaryFunDialer: public CallDialer
{
public:
    /// a stand-alone function that receives the parameter given to us
    using Handler = void (Argument1);

    UnaryFunDialer(Handler * const aHandler, Argument1 anArg1):
        handler(aHandler),
        arg1(anArg1)
    {}
    ~UnaryFunDialer() override = default;

    /* CallDialer API */
    bool canDial(AsyncCall &) { return bool(handler); }
    void dial(AsyncCall &) { handler(std::move(arg1)); }
    void print(std::ostream &os) const final { os << '(' << arg1 << ')'; }

private:
    Handler *handler; ///< the function to call
    Argument1 arg1; ///< actual call parameter
};

/// helper function to simplify UnaryFunDialer creation
template <typename Argument1>
UnaryFunDialer<Argument1>
callDialer(void (*handler)(Argument1), Argument1 arg1)
{
    return UnaryFunDialer<Argument1>(handler, arg1);
}

#endif /* SQUID_SRC_BASE_ASYNCFUNCALLS_H */

