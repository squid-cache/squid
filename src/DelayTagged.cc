
/*
 * $Id$
 *
 * DEBUG: section 77    Delay Pools
 * AUTHOR: Robert Collins <robertc@squid-cache.org>
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "config.h"

#if DELAY_POOLS
#include "squid.h"
#include "DelayTagged.h"
#include "NullDelayId.h"
#include "Store.h"

void *
DelayTagged::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (DelayTagged);
    return ::operator new (size);
}

void
DelayTagged::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (DelayTagged);
    ::operator delete (address);
}

DelayTagged::DelayTagged()
{
    DelayPools::registerForUpdates (this);
}

static SplayNode<DelayTaggedBucket::Pointer>::SPLAYFREE DelayTaggedFree;

DelayTagged::~DelayTagged()
{
    DelayPools::deregisterForUpdates (this);
    buckets.head->destroy (DelayTaggedFree);
}

static SplayNode<DelayTaggedBucket::Pointer>::SPLAYCMP DelayTaggedCmp;

int
DelayTaggedCmp(DelayTaggedBucket::Pointer const &left, DelayTaggedBucket::Pointer const &right)
{
    /* for rate limiting, case insensitive */
    return left->tag.caseCmp(right->tag);
}

void
DelayTaggedFree(DelayTaggedBucket::Pointer &)
{}

void
DelayTaggedStatsWalkee(DelayTaggedBucket::Pointer const &current, void *state)
{
    current->stats ((StoreEntry *)state);
}

void
DelayTagged::stats(StoreEntry * sentry)
{
    spec.stats (sentry, "Per Tag");

    if (spec.restore_bps == -1)
        return;

    storeAppendPrintf(sentry, "\t\tCurrent: ");

    if (!buckets.head) {
        storeAppendPrintf (sentry, "Not used yet.\n\n");
        return;
    }

    buckets.head->walk(DelayTaggedStatsWalkee, sentry);
    storeAppendPrintf(sentry, "\n\n");
}

void
DelayTagged::dump(StoreEntry *entry) const
{
    spec.dump(entry);
}

struct DelayTaggedUpdater {
    DelayTaggedUpdater (DelaySpec &_spec, int _incr):spec(_spec),incr(_incr) {};

    DelaySpec spec;
    int incr;
};

void
DelayTaggedUpdateWalkee(DelayTaggedBucket::Pointer const &current, void *state)
{
    DelayTaggedUpdater *t = (DelayTaggedUpdater *)state;
    /* This doesn't change the value of the DelayTaggedBucket, so is safe */
    const_cast<DelayTaggedBucket *>(current.getRaw())->theBucket.update(t->spec, t->incr);
}

void
DelayTagged::update(int incr)
{
    DelayTaggedUpdater updater(spec, incr);
    buckets.head->walk (DelayTaggedUpdateWalkee, &updater);
    kickReads();
}

void
DelayTagged::parse()
{
    spec.parse();
}

DelayIdComposite::Pointer

DelayTagged::id(CompositePoolNode::CompositeSelectionDetails &details)
{
    if (!details.tag.size())
        return new NullDelayId;

    return new Id(this, details.tag);
}

void *
DelayTagged::Id::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (Id);
    return ::operator new (size);
}

void
DelayTagged::Id::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (Id);
    ::operator delete (address);
}

void *
DelayTaggedBucket::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (DelayTaggedBucket);
    return ::operator new (size);
}

void
DelayTaggedBucket::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (DelayTaggedBucket);
    ::operator delete (address);
}

DelayTaggedBucket::DelayTaggedBucket(String &aTag) : tag (aTag)
{
    debugs(77, 3, "DelayTaggedBucket::DelayTaggedBucket");
}

DelayTaggedBucket::~DelayTaggedBucket()
{
    debugs(77, 3, "DelayTaggedBucket::~DelayTaggedBucket");
}

void
DelayTaggedBucket::stats (StoreEntry *entry) const
{
    storeAppendPrintf(entry, " :" SQUIDSTRINGPH , SQUIDSTRINGPRINT(tag));
    theBucket.stats (entry);
}

DelayTagged::Id::Id(DelayTagged::Pointer aDelayTagged, String &aTag) : theTagged(aDelayTagged)
{
    theBucket = new DelayTaggedBucket(aTag);
    DelayTaggedBucket::Pointer const *existing = theTagged->buckets.find(theBucket, DelayTaggedCmp);

    if (existing) {
        theBucket = *existing;
        return;
    }

    theBucket->theBucket.init(theTagged->spec);
    theTagged->buckets.head = theTagged->buckets.head->insert (theBucket, DelayTaggedCmp);
}

DelayTagged::Id::~Id()
{
    debugs(77, 3, "DelayTagged::Id::~Id");
}

int
DelayTagged::Id::bytesWanted (int min, int max) const
{
    return theBucket->theBucket.bytesWanted(min,max);
}

void
DelayTagged::Id::bytesIn(int qty)
{
    theBucket->theBucket.bytesIn(qty);
}

void
DelayTagged::Id::delayRead(DeferredRead const &aRead)
{
    theTagged->delayRead(aRead);
}

#endif
