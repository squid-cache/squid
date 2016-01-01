/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "YesNoNone.h"

YesNoNone::operator void*() const
{
    assert(option != 0); // must call configure() first
    return option > 0 ? (void*)this : NULL;
}

void
YesNoNone::configure(bool beSet)
{
    option = beSet ? +1 : -1;
}

