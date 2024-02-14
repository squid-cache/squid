/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#ifndef SQUID_SRC_DELAYTAGGED_H
#define SQUID_SRC_DELAYTAGGED_H

#if USE_DELAY_POOLS

#include "auth/Gadgets.h"
#include "base/forward.h"
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
    ~DelayTaggedBucket() override;
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
    ~DelayTagged() override;
    void stats(StoreEntry * sentry) override;
    void dump(StoreEntry *entry) const override;
    void update(int incr) override;
    void parse() override;

    DelayIdComposite::Pointer id(CompositeSelectionDetails &) override;

private:

    /// \ingroup DelayPoolsInternal
    class Id:public DelayIdComposite
    {
        MEMPROXY_CLASS(DelayTagged::Id);

    public:
        Id (RefCount<DelayTagged>, String &);
        ~Id() override;
        int bytesWanted (int min, int max) const override;
        void bytesIn(int qty) override;
        void delayRead(const AsyncCallPointer &) override;

    private:
        RefCount<DelayTagged> theTagged;
        DelayTaggedBucket::Pointer theBucket;
    };

    friend class Id;

    DelaySpec spec;
    Splay<DelayTaggedBucket::Pointer> buckets;
};

#endif /* USE_DELAY_POOLS */
#endif /* SQUID_SRC_DELAYTAGGED_H */

