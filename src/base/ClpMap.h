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
        Entry(Entry &&) = default;
        Entry & operator = (Entry &&) = default;
    private:
        Entry(const Entry &) = delete;
        Entry & operator = (const Entry &) = delete;
    public:
        Key key; ///< the key of entry
        EntryValue *value = nullptr; ///< A pointer to the stored value
        time_t expires = 0; ///< When the entry is to be removed
    };

    /// container for LRU algorithm management
    typedef std::list<Entry *, PoolingAllocator<Entry *> > Queue;

    typedef std::pair<Key, Entry> MapPair;
    /// key:queue_item mapping for fast lookups by key
    typedef std::unordered_map<Key, Entry, std::hash<Key>, std::equal_to<Key>, PoolingAllocator<MapPair> > Map;
    typedef typename Map::iterator MapIterator;

    ClpMap(int ttl, size_t size);
    ~ClpMap() = default;
    /// Search for an entry, and return a pointer
    EntryValue *get(const Key &key);
    /// Add an entry to the map
    bool add(const Key &key, EntryValue *t);
    /// Add an entry to the map with specific TTL
    bool add(const Key &key, EntryValue *t, int ttl);
    /// Delete an entry from the map
    bool del(const Key &key);
    /// (Re-)set the maximum size for this map
    void setMemLimit(size_t aSize);
    /// The available size for the map
    size_t memLimit() const {return memLimit_;}
    /// The free space of the map
    size_t freeMem() const { return (memLimit() > memoryUsed() ? memLimit() - memoryUsed() : 0);}
    /// The current size of the map
    size_t memoryUsed() const {return memUsed_;}
    /// The number of stored entries
    int entries() const {return entries_;}
private:
    ClpMap(ClpMap const &);
    ClpMap & operator = (ClpMap const &);

    bool expired(const Entry &e) const;
    void trim(size_t wantSpace = 0);
    void touch(const MapIterator &i);
    bool del(const MapIterator &i);
    void findEntry(const Key &key, ClpMap::MapIterator &i);
    size_t memoryCountedFor(const Key &, const EntryValue *);

    Map storage; ///< The Key/value * pairs
    Queue lruIndex; ///< LRU cache index

    /// TTL to use if none provided to add(). 0 to disable caching.
    int defaultTtl = std::numeric_limits<int>::max;
    size_t memLimit_ = 0; ///< The maximum memory to use
    size_t memUsed_ = 0;  ///< The amount of memory currently used
    int entries_ = 0;     ///< The stored entries
};

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
ClpMap<Key, EntryValue, MemoryUsedByEV>::ClpMap(int aTtl, size_t aSize) :
    defaultTtl(aTtl)
{
    setMemLimit(aSize);
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::setMemLimit(size_t aSize)
{
    const auto oldLimit = memLimit_;
    if (aSize > 0)
        memLimit_ = aSize;
    else
        memLimit_ = 0;

    if (oldLimit > memLimit_)
        trim();
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::findEntry(const Key &key, ClpMap::MapIterator &i)
{
    i = storage.find(key);
    if (i == storage.end()) {
        return;
    }

    if (!expired(i->second)) {
        touch(i); // update LRU state
        return;
    }
    // else fall through to cleanup

    del(i);
    i = storage.end();
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
EntryValue *
ClpMap<Key, EntryValue, MemoryUsedByEV>::get(const Key &key)
{
    MapIterator i;
    findEntry(key, i);
    if (i != storage.end()) {
        const Entry &e = i->second;
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
    return sizeof(MapPair) + k.length() + entrySz;
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
    if (ttl == 0)
        return false;

    if (memLimit() == 0)
        return false;

    del(key);

    const auto wantSz = memoryCountedFor(key, t);
    if (wantSz >= memLimit())
        return false;
    trim(wantSz);

    auto result = storage.emplace(key, Entry(key, t, ttl));
    assert(result.second);
    lruIndex.emplace_front(&result.first->second);

    ++entries_;
    memUsed_ += wantSz;
    return true;
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
bool
ClpMap<Key, EntryValue, MemoryUsedByEV>::expired(const ClpMap::Entry &entry) const
{
    return entry.expires < squid_curtime;
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
bool
ClpMap<Key, EntryValue, MemoryUsedByEV>::del(ClpMap::MapIterator const &i)
{
    if (i != storage.end()) {
        Entry *e = &i->second;
        const auto sz = memoryCountedFor(e->key, e->value);
        lruIndex.remove(e);
        storage.erase(i);
        --entries_;
        memUsed_ -= sz;
        return true;
    }
    return false;
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
bool
ClpMap<Key, EntryValue, MemoryUsedByEV>::del(const Key &key)
{
    MapIterator i;
    findEntry(key, i);
    return del(i);
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::trim(size_t wantSpace)
{
    while (memLimit() < (memoryUsed() + wantSpace)) {
        auto i = lruIndex.end();
        --i;
        if (i != lruIndex.end()) {
            del((*i)->key);
        }
    }
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::touch(ClpMap::MapIterator const &i)
{
    // this must not be done when nothing is being cached.
    if (defaultTtl == 0 || memLimit() == 0)
        return;

    auto pos = std::find(lruIndex.begin(), lruIndex.end(), &i->second);
    if (pos != lruIndex.begin()) {
        lruIndex.splice(lruIndex.begin(), lruIndex, pos, std::next(pos));
    }
}

#endif /* SQUID__SRC_BASE_CLPMAP_H */
