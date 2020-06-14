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

/**
 * A Map for caching data by Capacity, Lifetime, and Priority (CLP)
 * Unlike other Map containers data is;
 * - added only if it fits within a predetermined memory limit (Capacity),
 * - gets expired based on TTL (Lifetime), and a fading Priority Queue.
 */
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
    /// (Re-)set the maximum size for this map
    void setMemLimit(size_t aSize);
    /// The available size for the map
    size_t memLimit() const {return memLimit_;}
    /// The free space of the map
    size_t freeMem() const { return (memLimit() > memoryUsed() ? memLimit() - memoryUsed() : 0);}
    /// The current size of the map
    size_t memoryUsed() const {return memUsed_;}
    /// The number of stored entries
    size_t entries() const { return data.size(); }

private:
    bool expired(const Entry &e) const;
    void trim(size_t wantSpace);
    void erase(const KeyMapIterator &);
    void findEntry(const Key &, KeyMapIterator &);
    size_t memoryCountedFor(const Key &, const EntryValue *);

    /// The {key, value, ttl} tuples.
    /// Currently stored and maintained in LRU sequence.
    Storage data;

    /// index of stored data by key
    KeyMapping index;

    /// TTL to use if none provided to add().
    int defaultTtl = std::numeric_limits<int>::max;
    size_t memLimit_ = 0; ///< The maximum memory to use
    size_t memUsed_ = 0;  ///< The amount of memory currently used
};

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::setMemLimit(size_t aSize)
{
    assert(aSize >= 0);
    if (memUsed_ > aSize)
        trim(memLimit_ - aSize);
    memLimit_ = aSize;
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::findEntry(const Key &key, KeyMapIterator &i)
{
    i = index.find(key);
    if (i == index.end()) {
        return;
    }

    auto &e = (*i).second;
    if (!expired(*e)) {
        if (e != data.begin())
            data.splice(data.begin(), data, e);
        return;
    }
    // else fall through to cleanup

    erase(i);
    i = index.end();
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
EntryValue *
ClpMap<Key, EntryValue, MemoryUsedByEV>::get(const Key &key)
{
    KeyMapIterator i;
    findEntry(key, i);
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
    if (wantSpace >= memLimit())
        return false;
    trim(wantSpace);

    data.emplace_front(key, t, ttl);
    index.emplace(key, data.begin());

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
    auto &e = (*i).second;
    const auto sz = memoryCountedFor(e->key, e->value);
    data.erase(e);
    index.erase(i);
    memUsed_ -= sz;
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::del(const Key &key)
{
    KeyMapIterator i;
    findEntry(key, i);
    erase(i);
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::trim(size_t wantSpace)
{
    while (memLimit() < (memoryUsed() + wantSpace)) {
        auto i = data.end();
        --i;
        if (i != data.end()) {
            del(i->key);
        }
    }
}

#endif /* SQUID__SRC_BASE_CLPMAP_H */
