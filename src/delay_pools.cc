
/*
 * $Id: delay_pools.cc,v 1.49 2007/11/13 23:25:34 rousskov Exp $
 *
 * DEBUG: section 77    Delay Pools
 * AUTHOR: Robert Collins <robertc@squid-cache.org>
 * Based upon original delay pools code by
 *   David Luyer <david@luyer.net>
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
#include "CacheManager.h"
#include "DelaySpec.h"
#include "DelayPools.h"
#include "event.h"
#include "StoreClient.h"
#include "Store.h"
#include "MemObject.h"
#include "client_side_request.h"
#include "ConfigParser.h"
#include "DelayId.h"
#include "Array.h"
#include "SquidString.h"
#include "SquidTime.h"
#include "CommonPool.h"
#include "CompositePoolNode.h"
#include "DelayPool.h"
#include "DelayVector.h"
#include "NullDelayId.h"
#include "DelayBucket.h"
#include "DelayUser.h"
#include "DelayTagged.h"

long DelayPools::MemoryUsed = 0;

class Aggregate : public CompositePoolNode
{

public:
    typedef RefCount<Aggregate> Pointer;
    void *operator new(size_t);
    void operator delete (void *);
    Aggregate();
    ~Aggregate();
    virtual DelaySpec *rate() {return &spec;}

    virtual DelaySpec const *rate() const {return &spec;}

    virtual void stats(StoreEntry * sentry);
    virtual void dump(StoreEntry *entry) const;
    virtual void update(int incr);
    virtual void parse();

    virtual DelayIdComposite::Pointer id(CompositeSelectionDetails &);

private:

class AggregateId:public DelayIdComposite
    {

    public:
        void *operator new(size_t);
        void operator delete (void *);
        AggregateId (RefCount<Aggregate>);
        virtual int bytesWanted (int min, int max) const;
        virtual void bytesIn(int qty);
        virtual void delayRead(DeferredRead const &);

    private:
        RefCount<Aggregate> theAggregate;
    };

    friend class AggregateId;

    DelayBucket theBucket;
    DelaySpec spec;
};

template <class Key, class Value>

class VectorMap
{

public:
    VectorMap();
    unsigned int size() const;
    unsigned char findKeyIndex (Key const key) const;
    bool indexUsed (unsigned char const index) const;
    unsigned int insert (Key const key);

#define IND_MAP_SZ 256

    Key key_map[IND_MAP_SZ];
    Value values[IND_MAP_SZ];

private:
    unsigned int nextMapPosition;
};

class VectorPool : public CompositePoolNode
{

public:
    typedef RefCount<VectorPool> Pointer;
    virtual void dump(StoreEntry *entry) const;
    virtual void parse();
    virtual void update(int incr);
    virtual void stats(StoreEntry * sentry);

    virtual DelayIdComposite::Pointer id(CompositeSelectionDetails &);
    VectorMap<unsigned char, DelayBucket> buckets;
    VectorPool();
    ~VectorPool();

protected:
    bool keyAllocated (unsigned char const key) const;
    virtual DelaySpec *rate() {return &spec;}

    virtual DelaySpec const *rate() const {return &spec;}

    virtual char const *label() const = 0;

    virtual unsigned int makeKey (struct IN_ADDR &src_addr) const = 0;

    DelaySpec spec;

class Id:public DelayIdComposite
    {

    public:
        void *operator new(size_t);
        void operator delete (void *);
        Id (RefCount<VectorPool>, int);
        virtual int bytesWanted (int min, int max) const;
        virtual void bytesIn(int qty);

    private:
        RefCount<VectorPool> theVector;
        int theIndex;
    };
};

class IndividualPool : public VectorPool
{

public:
    void *operator new(size_t);
    void operator delete (void *);

protected:
    virtual char const *label() const {return "Individual";}

    virtual unsigned int makeKey (struct IN_ADDR &src_addr) const;

};

class ClassCNetPool : public VectorPool
{

public:
    void *operator new(size_t);
    void operator delete (void *);

protected:
    virtual char const *label() const {return "Network";}

    virtual unsigned int makeKey (struct IN_ADDR &src_addr) const;
};

/* don't use remote storage for these */

class ClassCBucket
{

public:
    bool individualUsed (unsigned int index)const;
    unsigned char findHostMapPosition (unsigned char const host) const;
    bool individualAllocated (unsigned char host) const;
    unsigned char hostPosition (DelaySpec &rate, unsigned char const host);
    void initHostIndex (DelaySpec &rate, unsigned char index, unsigned char host);
    void update (DelaySpec const &, int incr);
    void stats(StoreEntry *)const;

    DelayBucket net;
    VectorMap<unsigned char, DelayBucket> individuals;
};

class ClassCHostPool : public CompositePoolNode
{

public:
    typedef RefCount<ClassCHostPool> Pointer;
    virtual void dump(StoreEntry *entry) const;
    virtual void parse();
    virtual void update(int incr);
    virtual void stats(StoreEntry * sentry);

    virtual DelayIdComposite::Pointer id(CompositeSelectionDetails &);
    ClassCHostPool();
    ~ClassCHostPool();

protected:
    bool keyAllocated (unsigned char const key) const;
    virtual DelaySpec *rate() {return &spec;}

    virtual DelaySpec const *rate() const {return &spec;}

    virtual char const *label() const {return "Individual";}

    virtual unsigned int makeKey (struct IN_ADDR &src_addr) const;

    unsigned char makeHostKey (struct IN_ADDR &src_addr) const;

    DelaySpec spec;
    VectorMap<unsigned char, ClassCBucket> buckets;

    class Id;

    friend class ClassCHostPool::Id;

class Id:public DelayIdComposite
    {

    public:
        void *operator new(size_t);
        void operator delete (void *);
        Id (RefCount<ClassCHostPool>, unsigned char, unsigned char);
        virtual int bytesWanted (int min, int max) const;
        virtual void bytesIn(int qty);

    private:
        RefCount<ClassCHostPool> theClassCHost;
        unsigned char theNet;
        unsigned char theHost;
    };
};

void
Aggregate::AggregateId::delayRead(DeferredRead const &aRead)
{
    theAggregate->delayRead(aRead);
}

void *
CommonPool::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (CommonPool);
    return ::operator new (size);
}

void
CommonPool::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (CommonPool);
    ::operator delete (address);
}

CommonPool *
CommonPool::Factory(unsigned char _class, CompositePoolNode::Pointer& compositeCopy)
{
    CommonPool *result = new CommonPool;

    switch (_class) {

    case 0:
        break;

    case 1:
        compositeCopy = new Aggregate;
        result->typeLabel = "1";
        break;

    case 2:
        result->typeLabel = "2";
        {
            DelayVector::Pointer temp = new DelayVector;
            compositeCopy = temp.getRaw();
            temp->push_back (new Aggregate);
            temp->push_back(new IndividualPool);
        }

        break;

    case 3:
        result->typeLabel = "3";
        {
            DelayVector::Pointer temp = new DelayVector;
            compositeCopy = temp.getRaw();
            temp->push_back (new Aggregate);
            temp->push_back (new ClassCNetPool);
            temp->push_back (new ClassCHostPool);
        }

        break;

    case 4:
        result->typeLabel = "4";
        {
            DelayVector::Pointer temp = new DelayVector;
            compositeCopy = temp.getRaw();
            temp->push_back (new Aggregate);
            temp->push_back (new ClassCNetPool);
            temp->push_back (new ClassCHostPool);
            temp->push_back (new DelayUser);
        }

        break;

    case 5:
        result->typeLabel = "5";
        compositeCopy = new DelayTagged;
        break;

    default:
        fatal ("unknown delay pool class");
        return NULL;
    };

    return result;
}

CommonPool::CommonPool()
{}

void
ClassCBucket::update (DelaySpec const &rate, int incr)
{
    /* If we aren't active, don't try to update us ! */
    assert (rate.restore_bps != -1);

    for (unsigned char j = 0; j < individuals.size(); ++j)
        individuals.values[j].update (rate, incr);
}

void
ClassCBucket::stats(StoreEntry *sentry)const
{
    for (unsigned int j = 0; j < individuals.size(); ++j) {
        assert (individualUsed (j));
        storeAppendPrintf(sentry, " %d:",individuals.key_map[j]);
        individuals.values[j].stats (sentry);
    }
}

unsigned char
ClassCBucket::findHostMapPosition (unsigned char const host) const
{
    return individuals.findKeyIndex(host);
}

bool
ClassCBucket::individualUsed (unsigned int index)const
{
    return individuals.indexUsed(index);
}

bool
ClassCBucket::individualAllocated (unsigned char host) const
{
    return individualUsed(findHostMapPosition (host));
}

unsigned char
ClassCBucket::hostPosition (DelaySpec &rate, unsigned char const host)
{
    if (individualAllocated (host))
        return findHostMapPosition(host);

    assert (!individualUsed (findHostMapPosition(host)));

    unsigned char result = findHostMapPosition(host);

    initHostIndex (rate, result, host);

    return result;
}

void
ClassCBucket::initHostIndex (DelaySpec &rate, unsigned char index, unsigned char host)
{
    assert (!individualUsed(index));

    unsigned char const newIndex = individuals.insert (host);

    /* give the bucket a default value */
    individuals.values[newIndex].init (rate);
}

void *
CompositePoolNode::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (CompositePoolNode);
    return ::operator new (size);
}

void
CompositePoolNode::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (CompositePoolNode);
    ::operator delete (address);
}

void *
Aggregate::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (Aggregate);
    return ::operator new (size);
}

void
Aggregate::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (Aggregate);
    ::operator delete (address);
}

Aggregate::Aggregate()
{
    theBucket.init (*rate());
    DelayPools::registerForUpdates (this);
}

Aggregate::~Aggregate()
{
    DelayPools::deregisterForUpdates (this);
}

void
Aggregate::stats(StoreEntry * sentry)
{
    rate()->stats (sentry, "Aggregate");

    if (rate()->restore_bps == -1)
        return;

    storeAppendPrintf(sentry, "\t\tCurrent: ");

    theBucket.stats(sentry);

    storeAppendPrintf(sentry, "\n\n");
}

void
Aggregate::dump(StoreEntry *entry) const
{
    rate()->dump (entry);
}

void
Aggregate::update(int incr)
{
    theBucket.update(*rate(), incr);
    kickReads();
}

void
Aggregate::parse()
{
    rate()->parse();
}

DelayIdComposite::Pointer

Aggregate::id(CompositeSelectionDetails &details)
{
    if (rate()->restore_bps != -1)
        return new AggregateId (this);
    else
        return new NullDelayId;
}

void *
Aggregate::AggregateId::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (AggregateId);
    return ::operator new (size);
}

void
Aggregate::AggregateId::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (AggregateId);
    ::operator delete (address);
}

Aggregate::AggregateId::AggregateId(RefCount<Aggregate> anAggregate) : theAggregate(anAggregate)
{}

int
Aggregate::AggregateId::bytesWanted (int min, int max) const
{
    return theAggregate->theBucket.bytesWanted(min, max);
}

void
Aggregate::AggregateId::bytesIn(int qty)
{
    theAggregate->theBucket.bytesIn(qty);
    theAggregate->kickReads();
}

DelayPool *DelayPools::delay_data = NULL;
time_t DelayPools::LastUpdate = 0;
unsigned short DelayPools::pools_ (0);

void
DelayPools::Init()
{
    LastUpdate = getCurrentTime();
}

void
DelayPools::RegisterWithCacheManager(CacheManager & manager)
{
    manager.registerAction("delay", "Delay Pool Levels", Stats, 0, 1);
}

void
DelayPools::InitDelayData()
{
    if (!pools())
        return;

    DelayPools::delay_data = new DelayPool[pools()];

    DelayPools::MemoryUsed += pools() * sizeof(DelayPool);

    eventAdd("DelayPools::Update", DelayPools::Update, NULL, 1.0, 1);
}

void
DelayPools::FreeDelayData()
{
    eventDelete(DelayPools::Update, NULL);
    delete[] DelayPools::delay_data;
    DelayPools::MemoryUsed -= pools() * sizeof(*DelayPools::delay_data);
    pools_ = 0;
}

void
DelayPools::Update(void *unused)
{
    if (!pools())
        return;

    eventAdd("DelayPools::Update", Update, NULL, 1.0, 1);

    int incr = squid_curtime - LastUpdate;

    if (incr < 1)
        return;

    LastUpdate = squid_curtime;

    Vector<Updateable *>::iterator pos = toUpdate.begin();

    while (pos != toUpdate.end()) {
        (*pos)->update(incr);
        ++pos;
    }
}

void
DelayPools::registerForUpdates(Updateable *anObject)
{
    /* Assume no doubles */
    toUpdate.push_back(anObject);
}

void
DelayPools::deregisterForUpdates (Updateable *anObject)
{
    Vector<Updateable *>::iterator pos = toUpdate.begin();

    while (pos != toUpdate.end() && *pos != anObject) {
        ++pos;
    }

    if (pos != toUpdate.end()) {
        /* move all objects down one */
        Vector<Updateable *>::iterator temp = pos;
        ++pos;

        while (pos != toUpdate.end()) {
            *temp = *pos;
            ++temp;
            ++pos;
        }

        toUpdate.pop_back();
    }
}

Vector<Updateable *> DelayPools::toUpdate;

void
DelayPools::Stats(StoreEntry * sentry)
{
    unsigned short i;

    storeAppendPrintf(sentry, "Delay pools configured: %d\n\n", DelayPools::pools());

    for (i = 0; i < DelayPools::pools(); ++i) {
        if (DelayPools::delay_data[i].theComposite().getRaw()) {
            storeAppendPrintf(sentry, "Pool: %d\n\tClass: %s\n\n", i + 1, DelayPools::delay_data[i].pool->theClassTypeLabel());
            DelayPools::delay_data[i].theComposite()->stats (sentry);
        } else
            storeAppendPrintf(sentry, "\tMisconfigured pool.\n\n");
    }

    storeAppendPrintf(sentry, "Memory Used: %d bytes\n", (int) DelayPools::MemoryUsed);
}

void
DelayPools::FreePools()
{
    if (!DelayPools::pools())
        return;

    FreeDelayData();
}

unsigned short
DelayPools::pools()
{
    return pools_;
}

void
DelayPools::pools (u_short newPools)
{
    if (pools()) {
        debugs(3, 0, "parse_delay_pool_count: multiple delay_pools lines, aborting all previous delay_pools config");
        FreePools();
    }

    pools_ = newPools;

    if (pools())
        InitDelayData();
}

template <class Key, class Value>
VectorMap<Key,Value>::VectorMap() : nextMapPosition(0)
{}

template <class Key, class Value>
unsigned int
VectorMap<Key,Value>::size() const
{
    return nextMapPosition;
}

template <class Key, class Value>
unsigned int
VectorMap<Key,Value>::insert (Key const key)
{
    unsigned char index = findKeyIndex (key);
    assert (!indexUsed(index));

    key_map[index] = key;

    ++nextMapPosition;

    return index;
}

void *
IndividualPool::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (IndividualPool);
    return ::operator new (size);
}

void
IndividualPool::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (IndividualPool);
    ::operator delete (address);
}

VectorPool::VectorPool()
{
    DelayPools::registerForUpdates (this);
}

VectorPool::~VectorPool()
{
    DelayPools::deregisterForUpdates (this);
}

void
VectorPool::stats(StoreEntry * sentry)
{
    rate()->stats (sentry, label());

    if (rate()->restore_bps == -1) {
        storeAppendPrintf(sentry, "\n\n");
        return;
    }

    storeAppendPrintf(sentry, "\t\tCurrent:");

    for (unsigned int i = 0; i < buckets.size(); i++) {
        storeAppendPrintf(sentry, " %d:", buckets.key_map[i]);
        buckets.values[i].stats(sentry);
    }

    if (!buckets.size())
        storeAppendPrintf(sentry, " Not used yet.");

    storeAppendPrintf(sentry, "\n\n");
}

void
VectorPool::dump(StoreEntry *entry) const
{
    rate()->dump (entry);
}

void
VectorPool::update(int incr)
{
    if (rate()->restore_bps == -1)
        return;

    for (unsigned int i = 0; i< buckets.size(); ++i)
        buckets.values[i].update (*rate(), incr);
}

void
VectorPool::parse()
{
    rate()->parse();
}

bool
VectorPool::keyAllocated (unsigned char const key) const
{
    return buckets.indexUsed(buckets.findKeyIndex (key));
}

template <class Key, class Value>
bool
VectorMap<Key,Value>::indexUsed (unsigned char const index) const
{
    return index < size();
}

/* returns the used position, or the position to allocate */
template <class Key, class Value>
unsigned char
VectorMap<Key,Value>::findKeyIndex (Key const key) const
{
    for (unsigned int index = 0; index < size(); ++index) {
        assert (indexUsed (index));

        if (key_map[index] == key)
            return index;
    }

    /* not in map */
    return size();
}

DelayIdComposite::Pointer

VectorPool::id(CompositeSelectionDetails &details)
{
    if (rate()->restore_bps == -1)
        return new NullDelayId;

    unsigned int key = makeKey (details.src_addr);

    if (keyAllocated (key))
        return new Id (this, buckets.findKeyIndex(key));

    unsigned char const resultIndex = buckets.insert(key);

    buckets.values[resultIndex].init (*rate());

    return new Id(this, resultIndex);
}

void *
VectorPool::Id::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (Id);
    return ::operator new (size);
}

void
VectorPool::Id::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (Id);
    ::operator delete (address);
}

VectorPool::Id::Id (VectorPool::Pointer aPool, int anIndex) : theVector (aPool), theIndex (anIndex)
{}

int
VectorPool::Id::bytesWanted (int min, int max) const
{
    return theVector->buckets.values[theIndex].bytesWanted (min, max);
}

void
VectorPool::Id::bytesIn(int qty)
{
    theVector->buckets.values[theIndex].bytesIn (qty);
}


unsigned int
IndividualPool::makeKey (struct IN_ADDR &src_addr) const
{
    unsigned int host;
    host = ntohl(src_addr.s_addr) & 0xff;
    return host;
}

void *
ClassCNetPool::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (ClassCNetPool);
    return ::operator new (size);
}

void
ClassCNetPool::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (ClassCNetPool);
    ::operator delete (address);
}

unsigned int
ClassCNetPool::makeKey (struct IN_ADDR &src_addr) const
{
    unsigned int net;
    net = (ntohl(src_addr.s_addr) >> 8) & 0xff;
    return net;
}


ClassCHostPool::ClassCHostPool()
{
    DelayPools::registerForUpdates (this);
}

ClassCHostPool::~ClassCHostPool()
{
    DelayPools::deregisterForUpdates (this);
}

void
ClassCHostPool::stats(StoreEntry * sentry)
{
    rate()->stats (sentry, label());

    if (rate()->restore_bps == -1) {
        storeAppendPrintf(sentry, "\n\n");
        return;
    }

    for (unsigned int index = 0; index < buckets.size(); ++index) {
        storeAppendPrintf(sentry, "\t\tCurrent [Network %d]:", buckets.key_map[index]);
        buckets.values[index].stats (sentry);
        storeAppendPrintf(sentry, "\n");
    }

    if (!buckets.size())
        storeAppendPrintf(sentry, "\t\tCurrent [All networks]: Not used yet.\n");

    storeAppendPrintf(sentry, "\n\n");
}

void
ClassCHostPool::dump(StoreEntry *entry) const
{
    rate()->dump (entry);
}

void
ClassCHostPool::update(int incr)
{
    if (rate()->restore_bps == -1)
        return;

    for (unsigned int i = 0; i< buckets.size(); ++i)
        buckets.values[i].update (*rate(), incr);
}

void
ClassCHostPool::parse()
{
    rate()->parse();
}

bool
ClassCHostPool::keyAllocated (unsigned char const key) const
{
    return buckets.indexUsed(buckets.findKeyIndex (key));
}

unsigned char
ClassCHostPool::makeHostKey (struct IN_ADDR &src_addr) const
{
    unsigned int host;
    host = ntohl(src_addr.s_addr) & 0xff;
    return host;
}

unsigned int
ClassCHostPool::makeKey (struct IN_ADDR &src_addr) const
{
    unsigned int net;
    net = (ntohl(src_addr.s_addr) >> 8) & 0xff;
    return net;
}

DelayIdComposite::Pointer

ClassCHostPool::id(CompositeSelectionDetails &details)
{
    if (rate()->restore_bps == -1)
        return new NullDelayId;

    unsigned int key = makeKey (details.src_addr);

    unsigned char host = makeHostKey (details.src_addr);

    unsigned char hostIndex;

    unsigned char netIndex;

    if (keyAllocated (key))
        netIndex = buckets.findKeyIndex(key);
    else
        netIndex = buckets.insert (key);

    hostIndex = buckets.values[netIndex].hostPosition (*rate(), host);

    return new Id (this, netIndex, hostIndex);
}

void *
ClassCHostPool::Id::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (Id);
    return ::operator new (size);
}

void
ClassCHostPool::Id::operator delete (void *address)
{
    DelayPools::MemoryUsed -= sizeof (Id);
    ::operator delete (address);
}

ClassCHostPool::Id::Id (ClassCHostPool::Pointer aPool, unsigned char aNet, unsigned char aHost) : theClassCHost (aPool), theNet (aNet), theHost (aHost)
{}

int
ClassCHostPool::Id::bytesWanted (int min, int max) const
{
    return theClassCHost->buckets.values[theNet].individuals.values[theHost].bytesWanted (min, max);
}

void
ClassCHostPool::Id::bytesIn(int qty)
{
    theClassCHost->buckets.values[theNet].individuals.values[theHost].bytesIn (qty);
}

#endif

