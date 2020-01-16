/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#ifndef DELAYTAGGED_H
#define DELAYTAGGED_H

#if USE_DELAY_POOLS

#include "auth/Gadgets.h"
#include "CompositePoolNode.h"
#include "DelayBucket.h"
#include "DelayIdComposite.h"
#include "DelaySpec.h"
#include "splay.h"

/// \ingroup DelayPoolsAPI
class DelayTaggedBucket : public RefCountable
{
    MEMPROXY_CLASS(DelayTaggedBucket);

public:
    typedef RefCount<DelayTaggedBucket> Pointer;

    void stats(StoreEntry *)const;
    DelayTaggedBucket(String &aTag);
    ~DelayTaggedBucket();
    DelayBucket theBucket;
    String tag;
};

/// \ingroup DelayPoolsAPI
class DelayTagged : public CompositePoolNode
{
    MEMPROXY_CLASS(DelayTagged);

public:
    typedef RefCount<DelayTagged> Pointer;

    DelayTagged();
    virtual ~DelayTagged();
    virtual void stats(StoreEntry * sentry);
    virtual void dump(StoreEntry *entry) const;
    virtual void update(int incr);
    virtual void parse();

    virtual DelayIdComposite::Pointer id(CompositeSelectionDetails &);

private:

    /// \ingroup DelayPoolsInternal
    class Id:public DelayIdComposite
    {
        MEMPROXY_CLASS(DelayTagged::Id);

    public:
        Id (RefCount<DelayTagged>, String &);
        ~Id();
        virtual int bytesWanted (int min, int max) const;
        virtual void bytesIn(int qty);
        virtual void delayRead(DeferredRead const &);

    private:
        RefCount<DelayTagged> theTagged;
        DelayTaggedBucket::Pointer theBucket;
    };

    friend class Id;

    DelaySpec spec;
    Splay<DelayTaggedBucket::Pointer> buckets;
};

#endif /* USE_DELAY_POOLS */
#endif /* DELAYTAGGED_H */

