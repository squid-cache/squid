/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_BASE_CLPMAP_H
#define SQUID__SRC_BASE_CLPMAP_H

#include "SquidTime.h"

#include <list>
#include <map>

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
        Entry(const Key &aKey, EntryValue *t): key(aKey), value(t), date(squid_curtime) {}
        ~Entry() {delete value;}
    private:
        Entry(Entry &);
        Entry & operator = (Entry &);
    public:
        Key key; ///< the key of entry
        EntryValue *value = nullptr; ///< A pointer to the stored value
        time_t date = 0; ///< The date the entry created
    };
    typedef std::list<Entry *> Queue;
    typedef typename std::list<Entry *>::iterator QueueIterator;

    /// key:queue_item mapping for fast lookups by key
    typedef std::map<Key, QueueIterator> Map;
    typedef typename Map::iterator MapIterator;
    typedef std::pair<Key, QueueIterator> MapPair;

    ClpMap(int ttl, size_t size);
    ~ClpMap();
    /// Search for an entry, and return a pointer
    EntryValue *get(const Key &key);
    /// Add an entry to the map
    bool add(const Key &key, EntryValue *t);
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
    Queue index; ///< LRU cache index
    int ttl = 0;          ///< TTL >0 for caching, == 0 cache is disabled, <0 store for ever
    size_t memLimit_ = 0; ///< The maximum memory to use
    size_t memUsed_ = 0;  ///< The amount of memory currently used
    int entries_ = 0;     ///< The stored entries
};

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
ClpMap<Key, EntryValue, MemoryUsedByEV>::ClpMap(int aTtl, size_t aSize) :
    ttl(aTtl)
{
    setMemLimit(aSize);
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
ClpMap<Key, EntryValue, MemoryUsedByEV>::~ClpMap()
{
    for (QueueIterator i = index.begin(); i != index.end(); ++i) {
        delete *i;
    }
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
    index.push_front(*(i->second));
    index.erase(i->second);
    i->second = index.begin();

    if (const Entry *e = *i->second) {
        if (!expired(*e))
            return;
        // else fall through to cleanup
    }

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
        touch(i);
        Entry *e = *i->second;
        return e->value;
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
    if (ttl == 0)
        return false;

    if (memLimit() == 0)
        return false;

    del(key);

    const auto wantSz = memoryCountedFor(key, t);
    if (wantSz >= memLimit())
        return false;
    trim(wantSz);

    index.push_front(new Entry(key, t));
    storage.insert(MapPair(key, index.begin()));

    ++entries_;
    memUsed_ += wantSz;
    return true;
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
bool
ClpMap<Key, EntryValue, MemoryUsedByEV>::expired(const ClpMap::Entry &entry) const
{
    if (ttl < 0)
        return false;

    return (entry.date + ttl < squid_curtime);
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
bool
ClpMap<Key, EntryValue, MemoryUsedByEV>::del(ClpMap::MapIterator const &i)
{
    if (i != storage.end()) {
        Entry *e = *i->second;
        const auto sz = memoryCountedFor(e->key, e->value);
        index.erase(i->second);
        storage.erase(i);
        delete e;
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
        QueueIterator i = index.end();
        --i;
        if (i != index.end()) {
            del((*i)->key);
        }
    }
}

template <class Key, class EntryValue, size_t MemoryUsedByEV(const EntryValue *)>
void
ClpMap<Key, EntryValue, MemoryUsedByEV>::touch(ClpMap::MapIterator const &i)
{
    // this must not be done when nothing is being cached.
    if (ttl == 0 || memLimit() == 0)
        return;

    index.push_front(*(i->second));
    index.erase(i->second);
    i->second = index.begin();
}

#endif /* SQUID__SRC_BASE_CLPMAP_H */
