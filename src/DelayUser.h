/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#ifndef DELAYUSER_H
#define DELAYUSER_H

#if USE_DELAY_POOLS && USE_AUTH

#include "auth/Gadgets.h"
#include "auth/User.h"
#include "CompositePoolNode.h"
#include "DelayBucket.h"
#include "DelayIdComposite.h"
#include "DelaySpec.h"
#include "splay.h"

/// \ingroup DelayPoolsAPI
class DelayUserBucket : public RefCountable
{
    MEMPROXY_CLASS(DelayUserBucket);

public:
    typedef RefCount<DelayUserBucket> Pointer;

    void stats(StoreEntry *)const;
    DelayUserBucket(Auth::User::Pointer);
    ~DelayUserBucket() override;
    DelayBucket theBucket;
    Auth::User::Pointer authUser;
};

/// \ingroup DelayPoolsAPI
class DelayUser : public CompositePoolNode
{
    MEMPROXY_CLASS(DelayUser);

public:
    typedef RefCount<DelayUser> Pointer;
    DelayUser();
    ~DelayUser() override;
    void stats(StoreEntry * sentry) override;
    void dump(StoreEntry *entry) const override;
    void update(int incr) override;
    void parse() override;

    DelayIdComposite::Pointer id(CompositeSelectionDetails &) override;

private:

    /// \ingroup DelayPoolsInternal
    class Id:public DelayIdComposite
    {
        MEMPROXY_CLASS(DelayUser::Id);

    public:
        Id(RefCount<DelayUser>, Auth::User::Pointer);
        ~Id() override;
        int bytesWanted (int min, int max) const override;
        void bytesIn(int qty) override;

    private:
        RefCount<DelayUser> theUser;
        DelayUserBucket::Pointer theBucket;
    };

    friend class Id;

    DelaySpec spec;
    Splay<DelayUserBucket::Pointer> buckets;
};

#endif /* USE_DELAY_POOLS && USE_AUTH */
#endif /* DELAYUSER_H */

