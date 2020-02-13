/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#include "squid.h"

#if USE_DELAY_POOLS
#include "comm/Connection.h"
#include "CommRead.h"
#include "DelayVector.h"

DelayVector::DelayVector()
{
    DelayPools::registerForUpdates (this);
}

DelayVector::~DelayVector()
{
    DelayPools::deregisterForUpdates (this);
}

void
DelayVector::stats(StoreEntry * sentry)
{
    iterator pos = pools.begin();

    while (pos != pools.end()) {
        (*pos)->stats(sentry);
        ++pos;
    }
}

void
DelayVector::dump(StoreEntry *entry) const
{
    const_iterator pos = pools.begin();

    while (pos != pools.end()) {
        (*pos)->dump(entry);
        ++pos;
    }
}

void
DelayVector::update(int incr)
{
    /*
     * Each pool updates itself,
     * but we may have deferred reads waiting on the pool as a whole.
     */

    kickReads();
}

void
DelayVector::parse()
{
    iterator pos = pools.begin();

    while (pos != pools.end()) {
        (*pos)->parse();
        ++pos;
    }
}

DelayIdComposite::Pointer
DelayVector::id(CompositeSelectionDetails &details)
{
    return new Id(this, details);
}

void
DelayVector::push_back(CompositePoolNode::Pointer aNode)
{
    pools.push_back(aNode);
}

DelayVector::Id::Id(DelayVector::Pointer aDelayVector, CompositeSelectionDetails &details) : theVector(aDelayVector)
{
    debugs(77, 3, "DelayVector::Id::Id");
    DelayVector::iterator pos = theVector->pools.begin();

    while (pos != theVector->pools.end()) {
        ids.push_back ((*pos)->id (details));
        ++pos;
    }
}

DelayVector::Id::~Id()
{
    debugs(77, 3, "DelayVector::Id::~Id");
}

int
DelayVector::Id::bytesWanted (int minimum, int maximum) const
{
    int nbytes = maximum;
    const_iterator pos = ids.begin();

    while (pos != ids.end()) {
        nbytes = min (nbytes, (*pos)->bytesWanted(minimum, nbytes));
        ++pos;
    }

    nbytes = max(minimum, nbytes);
    return nbytes;
}

void
DelayVector::Id::bytesIn(int qty)
{
    iterator pos = ids.begin();

    while (pos != ids.end()) {
        (*pos)->bytesIn(qty);
        ++pos;
    }

    theVector->kickReads();
}

void
DelayVector::Id::delayRead(DeferredRead const &aRead)
{
    theVector->delayRead(aRead);
}

#endif

