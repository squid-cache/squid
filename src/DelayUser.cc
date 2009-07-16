
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
#include "DelayUser.h"
#include "auth/UserRequest.h"
#include "auth/User.h"
#include "NullDelayId.h"
#include "Store.h"

void *
DelayUser::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (DelayUser);
    return ::operator new (size);
}

void
DelayUser::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (DelayUser);
    ::operator delete (address);
}

DelayUser::DelayUser()
{
    DelayPools::registerForUpdates (this);
}

static SplayNode<DelayUserBucket::Pointer>::SPLAYFREE DelayUserFree;

DelayUser::~DelayUser()
{
    DelayPools::deregisterForUpdates (this);
    buckets.head->destroy (DelayUserFree);
}

static SplayNode<DelayUserBucket::Pointer>::SPLAYCMP DelayUserCmp;

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

void
DelayUser::stats(StoreEntry * sentry)
{
    spec.stats (sentry, "Per User");

    if (spec.restore_bps == -1)
        return;

    storeAppendPrintf(sentry, "\t\tCurrent: ");

    if (!buckets.head) {
        storeAppendPrintf (sentry, "Not used yet.\n\n");
        return;
    }

    buckets.head->walk(DelayUserStatsWalkee, sentry);
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

void
DelayUser::update(int incr)
{
    DelayUserUpdater updater(spec, incr);
    buckets.head->walk (DelayUserUpdateWalkee, &updater);
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

void *
DelayUser::Id::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (Id);
    return ::operator new (size);
}

void
DelayUser::Id::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (Id);
    ::operator delete (address);
}

void *
DelayUserBucket::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (DelayUserBucket);
    return ::operator new (size);
}

void
DelayUserBucket::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (DelayUserBucket);
    ::operator delete (address);
}

DelayUserBucket::DelayUserBucket(AuthUser *aUser) : authUser (aUser)
{
    debugs(77, 3, "DelayUserBucket::DelayUserBucket");

    authUser->lock();
}

DelayUserBucket::~DelayUserBucket()
{
    authUser->unlock();
    debugs(77, 3, "DelayUserBucket::~DelayUserBucket");
}

void
DelayUserBucket::stats (StoreEntry *entry) const
{
    storeAppendPrintf(entry, " %s:", authUser->username());
    theBucket.stats (entry);
}

DelayUser::Id::Id(DelayUser::Pointer aDelayUser,AuthUser *aUser) : theUser(aDelayUser)
{
    theBucket = new DelayUserBucket(aUser);
    DelayUserBucket::Pointer const *existing = theUser->buckets.find(theBucket, DelayUserCmp);

    if (existing) {
        theBucket = *existing;
        return;
    }

    theBucket->theBucket.init(theUser->spec);
    theUser->buckets.head = theUser->buckets.head->insert (theBucket, DelayUserCmp);
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

#endif
