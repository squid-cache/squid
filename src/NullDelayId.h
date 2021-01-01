/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#ifndef NULLDELAYID_H
#define NULLDELAYID_H

#if USE_DELAY_POOLS
#include "DelayIdComposite.h"

class NullDelayId : public DelayIdComposite
{
    MEMPROXY_CLASS(NullDelayId);

public:
    virtual int bytesWanted (int minimum, int maximum) const {return max(minimum,maximum);}

    virtual void bytesIn(int qty) {}
};
#endif
#endif /* NULLDELAYID_H */

