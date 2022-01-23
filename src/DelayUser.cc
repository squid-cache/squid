/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

#include "squid.h"

#if USE_DELAY_POOLS && USE_AUTH
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "comm/Connection.h"
#include "DelayUser.h"
#include "NullDelayId.h"
#include "Store.h"

DelayUser::DelayUser()
{
    DelayPools::registerForUpdates (this);
}

static Splay<DelayUserBucket::Pointer>::SPLAYFREE DelayUserFree;

DelayUser::~DelayUser()
{
    DelayPools::deregisterForUpdates (this);
    buckets.destroy(DelayUserFree);
}

static Splay<DelayUserBucket::Pointer>::SPLAYCMP DelayUserCmp;

int
DelayUserCmp(DelayUserBucket::Pointer const &left, DelayUserBucket::Pointer const &right)
{
    /* Verify for re-currance of Bug 2127. either of these missing will crash strcasecmp() */
    assert(left->authUser->username() != NULL);
    assert(right->authUser->username() != NULL);

    /* for rate limiting, case insensitive */
    return strcasecmp(left->authUser->username(), right->authUser->username());
}

void
DelayUserFree(DelayUserBucket::Pointer &)
{}

void
DelayUserStatsWalkee(DelayUserBucket::Pointer const &current, void *state)
{
    current->stats ((StoreEntry *)state);
}

struct DelayUserStatsVisitor {
    StoreEntry *se;
    explicit DelayUserStatsVisitor(StoreEntry *s) : se(s) {}
    void operator() (DelayUserBucket::Pointer const &current) {
        current->stats(se);
    }
};

void
DelayUser::stats(StoreEntry * sentry)
{
    spec.stats (sentry, "Per User");

    if (spec.restore_bps == -1)
        return;

    storeAppendPrintf(sentry, "\t\tCurrent: ");

    if (buckets.empty()) {
        storeAppendPrintf (sentry, "Not used yet.\n\n");
        return;
    }

    DelayUserStatsVisitor visitor(sentry);
    buckets.visit(visitor);
    storeAppendPrintf(sentry, "\n\n");
}

void
DelayUser::dump(StoreEntry *entry) const
{
    spec.dump(entry);
}

struct DelayUserUpdater {
    DelayUserUpdater (DelaySpec &_spec, int _incr):spec(_spec),incr(_incr) {};

    DelaySpec spec;
    int incr;
};

void
DelayUserUpdateWalkee(DelayUserBucket::Pointer const &current, void *state)
{
    DelayUserUpdater *t = (DelayUserUpdater *)state;
    /* This doesn't change the value of the DelayUserBucket, so is safe */
    const_cast<DelayUserBucket *>(current.getRaw())->theBucket.update(t->spec, t->incr);
}

struct DelayUserUpdateVisitor {
    DelayUserUpdater *t;
    DelayUserUpdateVisitor(DelayUserUpdater *updater) : t(updater) {}
    void operator() (DelayUserBucket::Pointer const &current) {
        const_cast<DelayUserBucket *>(current.getRaw())->theBucket.update(t->spec, t->incr);
    }
};

void
DelayUser::update(int incr)
{
    DelayUserUpdater updater(spec, incr);
    DelayUserUpdateVisitor visitor(&updater);
    buckets.visit(visitor);
}

void
DelayUser::parse()
{
    spec.parse();
}

DelayIdComposite::Pointer
DelayUser::id(CompositePoolNode::CompositeSelectionDetails &details)
{
    if (!details.user || !details.user->user() || !details.user->user()->username())
        return new NullDelayId;

    debugs(77, 3, HERE << "Adding a slow-down for User '" << details.user->user()->username() << "'");
    return new Id(this, details.user->user());
}

DelayUserBucket::DelayUserBucket(Auth::User::Pointer aUser) : authUser(aUser)
{
    debugs(77, 3, "DelayUserBucket::DelayUserBucket");
}

DelayUserBucket::~DelayUserBucket()
{
    authUser = NULL;
    debugs(77, 3, "DelayUserBucket::~DelayUserBucket");
}

void
DelayUserBucket::stats (StoreEntry *entry) const
{
    storeAppendPrintf(entry, " %s:", authUser->username());
    theBucket.stats(entry);
}

DelayUser::Id::Id(DelayUser::Pointer aDelayUser, Auth::User::Pointer aUser) : theUser(aDelayUser)
{
    theBucket = new DelayUserBucket(aUser);
    DelayUserBucket::Pointer const *existing = theUser->buckets.find(theBucket, DelayUserCmp);

    if (existing) {
        theBucket = *existing;
        return;
    }

    theBucket->theBucket.init(theUser->spec);
    theUser->buckets.insert (theBucket, DelayUserCmp);
}

DelayUser::Id::~Id()
{
    debugs(77, 3, "DelayUser::Id::~Id");
}

int
DelayUser::Id::bytesWanted (int min, int max) const
{
    return theBucket->theBucket.bytesWanted(min,max);
}

void
DelayUser::Id::bytesIn(int qty)
{
    theBucket->theBucket.bytesIn(qty);
}

#endif /* USE_DELAY_POOLS && USE_AUTH */

