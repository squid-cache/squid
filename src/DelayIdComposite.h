/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#ifndef DELAYIDCOMPOSITE_H
#define DELAYIDCOMPOSITE_H

#if USE_DELAY_POOLS
#include "base/RefCount.h"
#include "fatal.h"

class DeferredRead;

class DelayIdComposite : public RefCountable
{

public:
    typedef RefCount<DelayIdComposite> Pointer;
    virtual inline ~DelayIdComposite() {}

    virtual int bytesWanted (int min, int max) const =0;
    virtual void bytesIn(int qty) = 0;
    /* only aggregate and vector need this today */
    virtual void delayRead(DeferredRead const &) {fatal("Not implemented");}
};

#endif /* USE_DELAY_POOLS */
#endif /* DELAYIDCOMPOSITE_H */

