
/*
 * $Id: DelayTagged.h,v 1.4 2003/08/04 22:14:40 robertc Exp $
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

#ifndef DELAYTAGGED_H
#define DELAYTAGGED_H

#include "squid.h"
#include "authenticate.h"
#include "CompositePoolNode.h"
#include "DelayIdComposite.h"
#include "DelayBucket.h"
#include "DelaySpec.h"
#include "Array.h"
#include "splay.h"

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

#endif /* DELAYTAGGED_H */
