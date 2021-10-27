/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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

#endif /* SQUID_BASE_ASYNCFUNCALLS_H */

