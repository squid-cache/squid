/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#ifndef SQUID_SRC_NULLDELAYID_H
#define SQUID_SRC_NULLDELAYID_H

#if USE_DELAY_POOLS
#include "DelayIdComposite.h"

class NullDelayId : public DelayIdComposite
{
    MEMPROXY_CLASS(NullDelayId);

public:
    int bytesWanted (int minimum, int maximum) const override {return max(minimum,maximum);}

    void bytesIn(int) override {}
};
#endif
#endif /* SQUID_SRC_NULLDELAYID_H */

