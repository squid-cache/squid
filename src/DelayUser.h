/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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

public:
    typedef RefCount<DelayUserBucket> Pointer;
    void *operator new(size_t);
    void operator delete (void *);

    void stats(StoreEntry *)const;
    DelayUserBucket(Auth::User::Pointer);
    ~DelayUserBucket();
    DelayBucket theBucket;
    Auth::User::Pointer authUser;
};

/// \ingroup DelayPoolsAPI
class DelayUser : public CompositePoolNode
{

public:
    typedef RefCount<DelayUser> Pointer;
    void *operator new(size_t);
    void operator delete (void *);
    DelayUser();
    virtual ~DelayUser();
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
        Id(RefCount<DelayUser>, Auth::User::Pointer);
        ~Id();
        virtual int bytesWanted (int min, int max) const;
        virtual void bytesIn(int qty);

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

