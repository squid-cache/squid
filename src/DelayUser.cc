
/*
 * $Id: DelayUser.cc,v 1.1 2003/02/05 21:06:30 robertc Exp $
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
#include "authenticate.h"
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

void
DelayUser::deleteSelf() const
{
    delete this;
}

DelayUser::DelayUser()
{
    DelayPools::registerForUpdates (this);
}

DelayUser::~DelayUser()
{
    DelayPools::deregisterForUpdates (this);
}

void
DelayUser::stats(StoreEntry * sentry)
{
    spec.stats (sentry, "Per User");
    if (spec.restore_bps == -1)
	return;
    storeAppendPrintf(sentry, "\t\tCurrent: ");
    if (!buckets.size()) {
	storeAppendPrintf (sentry, "Not used yet.\n\n");
	return;
    }
    iterator pos = buckets.begin();
    while (pos != buckets.end()) {
	(*pos)->stats(sentry);
	++pos;
    }
    storeAppendPrintf(sentry, "\n\n");
}

void
DelayUser::dump(StoreEntry *entry) const
{
    spec.dump(entry);
}

void
DelayUser::update(int incr)
{
    iterator pos = buckets.begin();
    while (pos != buckets.end()) {
	(*pos)->theBucket.update(spec, incr);
	++pos;
    }
}

void
DelayUser::parse()
{
    spec.parse();
}

DelayIdComposite::Pointer
DelayUser::id(struct in_addr &src_addr, AuthUserRequest *authRequest)
{
    if (!authRequest)
	return new NullDelayId;
    return new Id(this, authRequest->auth_user);
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

void
DelayUser::Id::deleteSelf() const
{
    delete this;
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
    authenticateAuthUserLock (authUser);
}

DelayUserBucket::~DelayUserBucket()
{
    authenticateAuthUserUnlock(authUser);
}

void
DelayUserBucket::stats (StoreEntry *entry) const
{
    storeAppendPrintf(entry, " %s:", authUser->username());
    theBucket.stats (entry);
}

DelayUser::Id::Id(DelayUser::Pointer aDelayUser,AuthUser *aUser) : theUser(aDelayUser)
{
    DelayUser::iterator pos = theUser->buckets.begin();
    while (pos != theUser->buckets.end()) {
	if ((*pos)->authUser == aUser) {
	    theBucket = (*pos);
	    return;
	}
	++pos;
    }
    
    theBucket = new DelayUserBucket(aUser);
    theBucket->theBucket.init(theUser->spec);
    theUser->buckets.push_back (theBucket);
}

DelayUser::Id::~Id()
{
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
