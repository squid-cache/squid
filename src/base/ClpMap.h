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
#include "SquidTime.h"

#include <functional>
#include <list>
#include <unordered_map>

template<class Value>
size_t
DefaultMemoryUsage(const Value &e)
{
    return sizeof(e);
}

/// An in-RAM associative container enforcing three primary caching policies:
/// * Capacity: The memory used by cached entries has a configurable limit;
/// * Lifetime: Entries are hidden (and may be deleted) after their TTL expires;
/// * Priority: Capacity victims are purged in LRU order.
/// Individual cache entry operations have average constant-time complexity.
///
/// Value must meet STL requirements of Erasable and EmplaceConstructible.
/// Key must come with std::hash<Key> and std::equal_to<Key> instantiations.
/// Key::length() must return the number of RAM bytes in use by the key.
/// MemoryUsedBy() must return the number of RAM bytes in use by the value.
template <class Key, class Value, size_t MemoryUsedBy(const Value &) = DefaultMemoryUsage>
class ClpMap
{
public:
    /// maximum desired entry caching duration (a.k.a. TTL), in seconds
    using Ttl = int;

    explicit ClpMap(const size_t capacity) { setMemLimit(capacity); }
    ClpMap(size_t capacity, Ttl defaultTtl);
    ~ClpMap() = default;

    // copying disabled because it may be expensive for large maps
    // moving (implicitly) disabled for simplicity sake
    ClpMap(const ClpMap &) = delete;
    ClpMap &operator =(const ClpMap &) = delete;

    /// \return a pointer to a fresh cached value (or nil)
    /// The underlying value is owned by the map, so the pointer may be
    /// invalidated by any non-constant method call, including another get().
    /// Also moves the found entry to the end of the purging queue.
    const Value *get(const Key &);

    /// Copy the given value into the map (with the given key and TTL)
    /// \retval true the value was successfully copied into the map
    /// \retval false caching was rejected (the map remains unchanged)
    bool add(const Key &, const Value &, Ttl);

    /// Copy the given value into the map (with the given key and default TTL)
    bool add(const Key &key, const Value &v) { return add(key, v, defaultTtl_); }

    /// Remove the corresponding entry (if any)
    void del(const Key &);

    /// Reset the memory capacity for this map, purging if needed
    void setMemLimit(size_t newLimit);

    /// The memory capacity for the map
    size_t memLimit() const { return memLimit_; }

    /// The free space of the map
    size_t freeMem() const { return memLimit() - memoryUsed(); }

    /// The current (approximate) memory usage of the map
    size_t memoryUsed() const { return memUsed_; }

    /// The number of currently stored entries, including expired ones
    size_t entries() const { return entries_.size(); }

private:
    /// the keeper of cache entry Key, Value, and caching-related entry metadata
    class Entry
    {
    public:
        Entry(const Key &aKey, const Value &v, const Ttl ttl): key(aKey), value(v), expires(squid_curtime+ttl) {}

        /// whether the entry is stale
        bool expired() const { return expires < squid_curtime; }

    public:
        Key key; ///< the entry search key; see ClpMap::get()
        Value value; ///< cached value provided by the map user
        time_t expires = 0; ///< get() stops returning the entry after this time
        size_t memCounted = 0; ///< memory accounted for this entry in our ClpMap
    };

    /// Entries in LRU order
    using Entries = std::list<Entry, PoolingAllocator<Entry> >;
    using EntriesIterator = typename Entries::iterator;

    using IndexItem = std::pair<Key, EntriesIterator>;
    /// key:entry_position mapping for fast entry lookups by key
    using Index = std::unordered_map<Key, EntriesIterator, std::hash<Key>, std::equal_to<Key>, PoolingAllocator<IndexItem> >;
    using IndexIterator = typename Index::iterator;

    static size_t MemoryCountedFor(const Key &, const Value &);

    void trim(size_t wantSpace);
    void erase(const IndexIterator &);
    IndexIterator find(const Key &);

    /// cached entries, including expired ones, in LRU order
    Entries entries_;

    /// entries_ positions indexed by the entry key
    Index index_;

    /// entry TTL to use if none provided to add()
    Ttl defaultTtl_ = std::numeric_limits<Ttl>::max();

    /// the maximum memory we are allowed to use for all cached entries
    size_t memLimit_ = 0;

    /// the total amount of memory we currently use for all cached entries
    size_t memUsed_ = 0;
};

template <class Key, class Value, size_t MemoryUsedBy(const Value &)>
ClpMap<Key, Value, MemoryUsedBy>::ClpMap(const size_t capacity, const Ttl defaultTtl):
    defaultTtl_(defaultTtl)
{
    assert(defaultTtl >= 0);
    setMemLimit(capacity);
}

template <class Key, class Value, size_t MemoryUsedBy(const Value &)>
void
ClpMap<Key, Value, MemoryUsedBy>::setMemLimit(const size_t newLimit)
{
    assert(newLimit >= 0);
    if (memUsed_ > newLimit)
        trim(memLimit_ - newLimit);
    memLimit_ = newLimit;
}

/// \returns the index position of an entry identified by its key (or end())
template <class Key, class Value, size_t MemoryUsedBy(const Value &)>
typename ClpMap<Key, Value, MemoryUsedBy>::IndexIterator
ClpMap<Key, Value, MemoryUsedBy>::find(const Key &key)
{
    const auto i = index_.find(key);
    if (i == index_.end())
        return i;

    const auto e = i->second;
    if (!e->expired()) {
        if (e != entries_.begin())
            entries_.splice(entries_.begin(), entries_, e);
        return i;
    }
    // else fall through to cleanup

    erase(i);
    return index_.end();
}

template <class Key, class Value, size_t MemoryUsedBy(const Value &)>
const Value *
ClpMap<Key, Value, MemoryUsedBy>::get(const Key &key)
{
    const auto i = find(key);
    if (i != index_.end()) {
        const auto &e = *(i->second);
        return &e.value;
    }
    return nullptr;
}

template <class Key, class Value, size_t MemoryUsedBy(const Value &)>
size_t
ClpMap<Key, Value, MemoryUsedBy>::MemoryCountedFor(const Key &k, const Value &v)
{
    // approximate calculation (e.g., containers store wrappers not value_types)
    const auto storageSz = sizeof(typename Entries::value_type) + k.length() + MemoryUsedBy(v);
    const auto indexSz = sizeof(typename Index::value_type) + k.length();
    return storageSz + indexSz;
}

template <class Key, class Value, size_t MemoryUsedBy(const Value &)>
bool
ClpMap<Key, Value, MemoryUsedBy>::add(const Key &key, const Value &v, const Ttl ttl)
{
    // optimization: avoid del() search, MemoryCountedFor() in always-empty maps
    if (memLimit() == 0)
        return false;

    del(key);

    if (ttl < 0)
        return false; // already expired; will never be returned by get()

    const auto wantSpace = MemoryCountedFor(key, v);
    if (wantSpace > memLimit())
        return false; // will never fit
    trim(wantSpace);

    entries_.emplace_front(key, v, ttl); // TODO: After C++17 migration, use the return value
    index_.emplace(key, entries_.begin());

    entries_.begin()->memCounted = wantSpace;
    memUsed_ += wantSpace;
    return true;
}

/// removes the cached entry (identified by its index) from the map
template <class Key, class Value, size_t MemoryUsedBy(const Value &)>
void
ClpMap<Key, Value, MemoryUsedBy>::erase(const IndexIterator &i)
{
    assert(i != index_.end());
    const auto entryPosition = i->second;

    const auto sz = entryPosition->memCounted;
    assert(memUsed_ >= sz);
    memUsed_ -= sz;

    index_.erase(i); // destroys a "pointer" to our Entry
    entries_.erase(entryPosition); // destroys our Entry
}

template <class Key, class Value, size_t MemoryUsedBy(const Value &)>
void
ClpMap<Key, Value, MemoryUsedBy>::del(const Key &key)
{
    const auto i = find(key);
    erase(i);
}

/// purges entries to make free memory large enough to fit wantSpace bytes
template <class Key, class Value, size_t MemoryUsedBy(const Value &)>
void
ClpMap<Key, Value, MemoryUsedBy>::trim(const size_t wantSpace)
{
    assert(wantSpace <= memLimit()); // no infinite loops and in-vain trimming
    while (freeMem() < wantSpace) {
        assert(!entries_.empty());
        // TODO: Purge expired entries first. They are useless, but their
        // presence may lead to purging potentially useful fresh entries here.
        del(entries_.rbegin()->key);
    }
}

#endif /* SQUID__SRC_BASE_CLPMAP_H */
