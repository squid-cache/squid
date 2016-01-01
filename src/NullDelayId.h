/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#ifndef NULLDELAYID_H
#define NULLDELAYID_H

#if USE_DELAY_POOLS
#include "base/RefCount.h"
#include "DelayIdComposite.h"

class NullDelayId : public DelayIdComposite
{

public:
    void *operator new(size_t);
    void operator delete (void *);
    virtual int bytesWanted (int minimum, int maximum) const {return max(minimum,maximum);}

    virtual void bytesIn(int qty) {}
};
#endif
#endif /* NULLDELAYID_H */

