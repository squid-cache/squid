/*
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
#ifndef DELAYUSER_H
#define DELAYUSER_H

#if USE_DELAY_POOLS && USE_AUTH

#include "auth/Gadgets.h"
#include "auth/User.h"
#include "CompositePoolNode.h"
#include "DelayIdComposite.h"
#include "DelayBucket.h"
#include "DelaySpec.h"
#include "Array.h"
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
