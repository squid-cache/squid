/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#include "squid.h"

#if USE_DELAY_POOLS
#include "comm/Connection.h"
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

static Splay<DelayTaggedBucket::Pointer>::SPLAYFREE DelayTaggedFree;

DelayTagged::~DelayTagged()
{
    DelayPools::deregisterForUpdates (this);
    buckets.destroy(DelayTaggedFree);
}

static Splay<DelayTaggedBucket::Pointer>::SPLAYCMP DelayTaggedCmp;

int
DelayTaggedCmp(DelayTaggedBucket::Pointer const &left, DelayTaggedBucket::Pointer const &right)
{
    /* for rate limiting, case insensitive */
    return left->tag.caseCmp(right->tag);
}

void
DelayTaggedFree(DelayTaggedBucket::Pointer &)
{}

struct DelayTaggedStatsVisitor {
    StoreEntry *sentry;
    explicit DelayTaggedStatsVisitor(StoreEntry *se): sentry(se) {}
    void operator() (DelayTaggedBucket::Pointer const &current) {
        current->stats(sentry);
    }
};

void
DelayTagged::stats(StoreEntry * sentry)
{
    spec.stats (sentry, "Per Tag");

    if (spec.restore_bps == -1)
        return;

    storeAppendPrintf(sentry, "\t\tCurrent: ");

    if (buckets.empty()) {
        storeAppendPrintf (sentry, "Not used yet.\n\n");
        return;
    }

    DelayTaggedStatsVisitor visitor(sentry);
    buckets.visit(visitor);
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

struct DelayTaggedUpdateVisitor {
    DelayTaggedUpdater *updater;
    explicit DelayTaggedUpdateVisitor(DelayTaggedUpdater *u) : updater(u) {}
    void operator() (DelayTaggedBucket::Pointer const &current) {
        const_cast<DelayTaggedBucket *>(current.getRaw())->theBucket.update(updater->spec, updater->incr);
    }
};

void
DelayTagged::update(int incr)
{
    DelayTaggedUpdater updater(spec, incr);
    DelayTaggedUpdateVisitor visitor(&updater);
    buckets.visit(visitor);
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
DelayTaggedBucket::stats(StoreEntry *entry) const
{
    storeAppendPrintf(entry, " " SQUIDSTRINGPH ":", SQUIDSTRINGPRINT(tag));
    theBucket.stats(entry);
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
    theTagged->buckets.insert (theBucket, DelayTaggedCmp);
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

