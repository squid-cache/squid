/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "store/AccumulationConstraints.h"

#include <iostream>

void
Store::AccumulationConstraints::noteHardMaximum(const uint64_t n, const char * const restrictionDescription)
{
    if (n < hardMaximum_) {
        debugs(19, 5, n << " for " << restrictionDescription << "; was: " << hardMaximum_);
        hardMaximum_ = n;
    } else {
        debugs(19, 7, "ignoring " << n << " for " << restrictionDescription << "; keeping: " << hardMaximum_);
    }
}

// TODO: Consider moving MemObject::mostBytesWanted() code here.
uint64_t Store::AccumulationConstraints::applyHardMaximum(const uint64_t raw) const
{
    return std::min(raw, hardMaximum_);
}


std::ostream &operator <<(std::ostream &os, const Store::AccumulationConstraints &)
{
    // XXX: implement
    return os;
}
