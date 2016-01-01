/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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

public:
    typedef RefCount<DelayTaggedBucket> Pointer;
    void *operator new(size_t);
    void operator delete (void *);

    void stats(StoreEntry *)const;
    DelayTaggedBucket(String &aTag);
    ~DelayTaggedBucket();
    DelayBucket theBucket;
    String tag;
};

/// \ingroup DelayPoolsAPI
class DelayTagged : public CompositePoolNode
{

public:
    typedef RefCount<DelayTagged> Pointer;
    void *operator new(size_t);
    void operator delete (void *);
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

    public:
        void *operator new(size_t);
        void operator delete (void *);
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

