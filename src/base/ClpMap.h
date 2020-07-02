/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_BASE_CLPMAP_H
#define SQUID__SRC_BASE_CLPMAP_H

#include "mem/PoolingAllocator.h"
#include "sbuf/Algorithms.h"
#include "SquidTime.h"

#include <functional>
#include <list>
#include <unordered_map>

template<class EntryValue>
size_t
DefaultMemoryUsage(const EntryValue *e)
{
    return sizeof(*e);
}

/// An in-memory cache enforcing three primary policies:
/// Capacity: The memory used by cached entries has a configurable limit;
/// Lifetime: Entries are hidden (and may be deleted) after their TTL expires;
/// Priority: Capacity victims are purged in LRU order.
template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *) = DefaultMemoryUsage>
class ClpMap
{
public:
    class Entry
    {
    public:
        Entry(const Key &aKey, EntryValue *t, int ttl): key(aKey), value(t), expires(squid_curtime+ttl) {}
        ~Entry() {delete value;}
        Entry(const Entry &) = delete;
        Entry & operator = (const Entry &) = delete;
        Entry(Entry &&) = default;
        Entry & operator = (Entry &&) = default;

    public:
        Key key; ///< the key of entry
        EntryValue *value = nullptr; ///< A pointer to the stored value
        time_t expires = 0; ///< When the entry is to be removed
        size_t memCounted = 0; ///< memory accounted for this entry in parent ClpMap
    };

    /// container for stored data
    typedef std::list<Entry, PoolingAllocator<Entry> > Storage;
    typedef typename Storage::iterator StorageIterator;

    /// Key:Entry* mapping for fast lookups by key
    typedef std::pair<Key, StorageIterator> MapItem;
    /// key:queue_item mapping for fast lookups by key
    typedef std::unordered_map<Key, StorageIterator, std::hash<Key>, std::equal_to<Key>, PoolingAllocator<MapItem> > KeyMapping;
    typedef typename KeyMapping::iterator KeyMapIterator;

    ClpMap(int aTtl, size_t aSize) : defaultTtl(aTtl) { assert(aTtl >= 0); setMemLimit(aSize); }
    ~ClpMap() = default;
    ClpMap(ClpMap const &) = delete;
    ClpMap & operator = (ClpMap const &) = delete;

    /// Search for an entry, and return a pointer
    EntryValue *get(const Key &key);
    /// Add an entry to the map
    bool add(const Key &key, EntryValue *t);
    /// Add an entry to the map with specific TTL
    bool add(const Key &key, EntryValue *t, int ttl);
    /// Delete an entry from the map
    void del(const Key &key);
    /// (re-)set the memory capacity for this map
    void setMemLimit(size_t newLimit);
    /// The memory capacity for the map
    size_t memLimit() const {return memLimit_;}
    /// The free space of the map
    size_t freeMem() const { return memLimit() - memoryUsed(); }
    /// The current memory usage of the map
    size_t memoryUsed() const {return memUsed_;}
    /// The number of stored entries
    size_t entries() const { return data.size(); }

private:
    bool expired(const Entry &e) const;
    void trim(size_t wantSpace);
    void erase(const KeyMapIterator &);
    KeyMapIterator find(const Key &);
    size_t memoryCountedFor(const Key &, const EntryValue *);

    /// The {key, value, ttl} tuples.
    /// Currently stored and maintained in LRU sequence.
    Storage data;

    /// index of stored data by key
    KeyMapping index;

    /// TTL to use if none provided to add().
    int defaultTtl = std::numeric_limits<int>::max();
    size_t memLimit_ = 0; ///< The maximum memory to use
    size_t memUsed_ = 0;  ///< The amount of memory currently used
};

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::setMemLimit(const size_t newLimit)
{
    assert(newLimit >= 0);
    if (memUsed_ > newLimit)
        trim(memLimit_ - newLimit);
    memLimit_ = newLimit;
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
typename ClpMap<Key, EntryValue, MemoryUsedByEV>::KeyMapIterator
ClpMap<Key, EntryValue, MemoryUsedByEV>::find(const Key &key)
{
    const auto i = index.find(key);
    if (i == index.end()) {
        return i;
    }

    const auto e = i->second;
    if (!expired(*e)) {
        if (e != data.begin())
            data.splice(data.begin(), data, e);
        return i;
    }
    // else fall through to cleanup

    erase(i);
    return index.end();
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
EntryValue *
ClpMap<Key, EntryValue, MemoryUsedByEV>::get(const Key &key)
{
    const auto i = find(key);
    if (i != index.end()) {
        const Entry &e = *(i->second);
        return e.value;
    }
    return NULL;
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
size_t
ClpMap<Key, EntryValue, MemoryUsedByEV>::memoryCountedFor(const Key &k, const EntryValue *v)
{
    // TODO: handle Entry which change size while stored
    size_t entrySz = sizeof(Entry) + MemoryUsedByEV(v) + k.length();
    return sizeof(MapItem) + k.length() + entrySz;
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
bool
ClpMap<Key, EntryValue, MemoryUsedByEV>::add(const Key &key, EntryValue *t)
{
    return add(key, t, defaultTtl);
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
bool
ClpMap<Key, EntryValue, MemoryUsedByEV>::add(const Key &key, EntryValue *t, int ttl)
{
    if (ttl < 0)
        return false;

    if (memLimit() == 0)
        return false;

    del(key);

    const auto wantSpace = memoryCountedFor(key, t);
    if (wantSpace > memLimit())
        return false;
    trim(wantSpace);

    data.emplace_front(key, t, ttl);
    index.emplace(key, data.begin());

    data.begin()->memCounted = wantSpace;
    memUsed_ += wantSpace;
    return true;
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
bool
ClpMap<Key, EntryValue, MemoryUsedByEV>::expired(const ClpMap::Entry &entry) const
{
    return entry.expires < squid_curtime;
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::erase(const KeyMapIterator &i)
{
    assert(i != index.end());
    const auto dataPosition = i->second;
    const auto sz = dataPosition->memCounted;
    index.erase(i); // destroys a pointer to our Entry
    data.erase(dataPosition); // destroys our Entry
    memUsed_ -= sz;
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::del(const Key &key)
{
    const auto i = find(key);
    erase(i);
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::trim(size_t wantSpace)
{
    assert(wantSpace <= memLimit()); // no infinite loops and in-vain trimming
    while (freeMem() < wantSpace) {
        assert(!data.empty());
        del(data.rbegin()->key);
    }
}

#endif /* SQUID__SRC_BASE_CLPMAP_H */
