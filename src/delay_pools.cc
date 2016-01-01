/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Delay Pools */

/**
 \defgroup DelayPoolsInternal Delay Pools Internal
 \ingroup DelayPoolsAPI
 */

#include "squid.h"

#if USE_DELAY_POOLS
#include "client_side_request.h"
#include "comm/Connection.h"
#include "CommonPool.h"
#include "CompositePoolNode.h"
#include "ConfigParser.h"
#include "DelayBucket.h"
#include "DelayId.h"
#include "DelayPool.h"
#include "DelayPools.h"
#include "DelaySpec.h"
#include "DelayTagged.h"
#include "DelayUser.h"
#include "DelayVector.h"
#include "event.h"
#include "ip/Address.h"
#include "MemObject.h"
#include "mgr/Registration.h"
#include "NullDelayId.h"
#include "SquidString.h"
#include "SquidTime.h"
#include "Store.h"
#include "StoreClient.h"

/// \ingroup DelayPoolsInternal
long DelayPools::MemoryUsed = 0;

/// \ingroup DelayPoolsInternal
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

    /// \ingroup DelayPoolsInternal
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

/// \ingroup DelayPoolsInternal
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

/// \ingroup DelayPoolsInternal
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

    virtual unsigned int makeKey(Ip::Address &src_addr) const = 0;

    DelaySpec spec;

    /// \ingroup DelayPoolsInternal
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

/// \ingroup DelayPoolsInternal
class IndividualPool : public VectorPool
{

public:
    void *operator new(size_t);
    void operator delete(void *);

protected:
    virtual char const *label() const {return "Individual";}
    virtual unsigned int makeKey(Ip::Address &src_addr) const;
};

/// \ingroup DelayPoolsInternal
class ClassCNetPool : public VectorPool
{

public:
    void *operator new(size_t);
    void operator delete (void *);

protected:
    virtual char const *label() const {return "Network";}
    virtual unsigned int makeKey (Ip::Address &src_addr) const;
};

/* don't use remote storage for these */
/// \ingroup DelayPoolsInternal
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

/// \ingroup DelayPoolsInternal
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

    virtual unsigned int makeKey(Ip::Address &src_addr) const;

    unsigned char makeHostKey(Ip::Address &src_addr) const;

    DelaySpec spec;
    VectorMap<unsigned char, ClassCBucket> buckets;

    class Id;

    friend class ClassCHostPool::Id;

    /// \ingroup DelayPoolsInternal
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
CommonPool::operator delete(void *address)
{
    DelayPools::MemoryUsed -= sizeof(CommonPool);
    ::operator delete(address);
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
#if USE_AUTH
            temp->push_back (new DelayUser);
#endif
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

    for (unsigned int j = 0; j < individuals.size(); ++j)
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
DelayPools::RegisterWithCacheManager(void)
{
    Mgr::RegisterAction("delay", "Delay Pool Levels", Stats, 0, 1);
}

void
DelayPools::Init()
{
    LastUpdate = getCurrentTime();
    RegisterWithCacheManager();
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

    std::vector<Updateable *>::iterator pos = toUpdate.begin();

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
    std::vector<Updateable *>::iterator pos = toUpdate.begin();

    while (pos != toUpdate.end() && *pos != anObject) {
        ++pos;
    }

    if (pos != toUpdate.end()) {
        /* move all objects down one */
        std::vector<Updateable *>::iterator temp = pos;
        ++pos;

        while (pos != toUpdate.end()) {
            *temp = *pos;
            ++temp;
            ++pos;
        }

        toUpdate.pop_back();
    }
}

std::vector<Updateable *> DelayPools::toUpdate;

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
DelayPools::pools(unsigned short newPools)
{
    if (pools()) {
        debugs(3, DBG_CRITICAL, "parse_delay_pool_count: multiple delay_pools lines, aborting all previous delay_pools config");
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

    for (unsigned int i = 0; i < buckets.size(); ++i) {
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

/** returns the used position, or the position to allocate */
template <class Key, class Value>
unsigned char
VectorMap<Key,Value>::findKeyIndex (Key const key) const
{
    for (unsigned int index = 0; index < size(); ++index) {
        assert(indexUsed(index));

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

    /* non-IPv4 are not able to provide IPv4-bitmask for this pool type key. */
    if ( !details.src_addr.isIPv4() )
        return new NullDelayId;

    unsigned int key = makeKey(details.src_addr);

    if (keyAllocated(key))
        return new Id(this, buckets.findKeyIndex(key));

    unsigned char const resultIndex = buckets.insert(key);

    buckets.values[resultIndex].init(*rate());

    return new Id(this, resultIndex);
}

void *
VectorPool::Id::operator new(size_t size)
{
    DelayPools::MemoryUsed += sizeof (Id);
    return ::operator new (size);
}

void
VectorPool::Id::operator delete(void *address)
{
    DelayPools::MemoryUsed -= sizeof (Id);
    ::operator delete (address);
}

VectorPool::Id::Id(VectorPool::Pointer aPool, int anIndex) : theVector (aPool), theIndex (anIndex)
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
IndividualPool::makeKey(Ip::Address &src_addr) const
{
    /* IPv4 required for this pool */
    if ( !src_addr.isIPv4() )
        return 1;

    struct in_addr host;
    src_addr.getInAddr(host);
    return (ntohl(host.s_addr) & 0xff);
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
ClassCNetPool::makeKey(Ip::Address &src_addr) const
{
    /* IPv4 required for this pool */
    if ( !src_addr.isIPv4() )
        return 1;

    struct in_addr net;
    src_addr.getInAddr(net);
    return ( (ntohl(net.s_addr) >> 8) & 0xff);
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
ClassCHostPool::makeHostKey(Ip::Address &src_addr) const
{
    /* IPv4 required for this pool */
    if ( !src_addr.isIPv4() )
        return 1;

    /* Temporary bypass for IPv4-only */
    struct in_addr host;
    src_addr.getInAddr(host);
    return (ntohl(host.s_addr) & 0xff);
}

unsigned int
ClassCHostPool::makeKey(Ip::Address &src_addr) const
{
    /* IPv4 required for this pool */
    if ( !src_addr.isIPv4() )
        return 1;

    struct in_addr net;
    src_addr.getInAddr(net);
    return ( (ntohl(net.s_addr) >> 8) & 0xff);
}

DelayIdComposite::Pointer
ClassCHostPool::id(CompositeSelectionDetails &details)
{
    if (rate()->restore_bps == -1)
        return new NullDelayId;

    /* non-IPv4 are not able to provide IPv4-bitmask for this pool type key. */
    if ( !details.src_addr.isIPv4() )
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

#endif /* USE_DELAY_POOLS */

