/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_CLPMAP_H
#define SQUID_SRC_BASE_CLPMAP_H

#include "mem/PoolingAllocator.h"
#include "SquidMath.h"
#include "time/gadgets.h"

#include <functional>
#include <limits>
#include <list>
#include <optional>
#include <unordered_map>

template<class Value>
uint64_t
DefaultMemoryUsage(const Value &e)
{
    return sizeof(e);
}

/// An in-memory associative container enforcing three primary caching policies:
/// * Capacity: The memory used by cached entries has a configurable limit;
/// * Lifetime: Entries are hidden (and may be deleted) after their TTL expires;
/// * Priority: Capacity victims are purged in LRU order.
/// Individual cache entry operations have average constant-time complexity.
///
/// Value must meet STL requirements of Erasable and EmplaceConstructible.
/// Key must come with std::hash<Key> and std::equal_to<Key> instantiations.
/// Key::length() must return the number of memory bytes in use by the key.
/// MemoryUsedBy() must return the number of memory bytes in use by the value.
template <class Key, class Value, uint64_t MemoryUsedBy(const Value &) = DefaultMemoryUsage>
class ClpMap
{
public:
    /// maximum desired entry caching duration (a.k.a. TTL), in seconds
    using Ttl = int;

    explicit ClpMap(const uint64_t capacity) { setMemLimit(capacity); }
    ClpMap(uint64_t capacity, Ttl defaultTtl);
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
    void setMemLimit(uint64_t newLimit);

    /// The memory capacity for the map
    uint64_t memLimit() const { return memLimit_; }

    /// The free space of the map
    uint64_t freeMem() const { return memLimit() - memoryUsed(); }

    /// The current (approximate) memory usage of the map
    uint64_t memoryUsed() const { return memUsed_; }

    /// The number of currently stored entries, including expired ones
    size_t entries() const { return entries_.size(); }

private:
    /// the keeper of cache entry Key, Value, and caching-related entry metadata
    class Entry
    {
    public:
        Entry(const Key &, const Value &, const Ttl);

        /// whether the entry is stale
        bool expired() const { return expires < squid_curtime; }

    public:
        Key key; ///< the entry search key; see ClpMap::get()
        Value value; ///< cached value provided by the map user
        time_t expires = 0; ///< get() stops returning the entry after this time
        uint64_t memCounted = 0; ///< memory accounted for this entry in our ClpMap
    };

    /// Entries in LRU order
    using Entries = std::list<Entry, PoolingAllocator<Entry> >;
    using EntriesIterator = typename Entries::iterator;

    using IndexItem = std::pair<const Key, EntriesIterator>;
    /// key:entry_position mapping for fast entry lookups by key
    using Index = std::unordered_map<Key, EntriesIterator, std::hash<Key>, std::equal_to<Key>, PoolingAllocator<IndexItem> >;
    using IndexIterator = typename Index::iterator;

    static std::optional<uint64_t> MemoryCountedFor(const Key &, const Value &);

    void trim(uint64_t wantSpace);
    void erase(const IndexIterator &);
    IndexIterator find(const Key &);

    /// cached entries, including expired ones, in LRU order
    Entries entries_;

    /// entries_ positions indexed by the entry key
    Index index_;

    /// entry TTL to use if none provided to add()
    Ttl defaultTtl_ = std::numeric_limits<Ttl>::max();

    /// the maximum memory we are allowed to use for all cached entries
    uint64_t memLimit_ = 0;

    /// the total amount of memory we currently use for all cached entries
    uint64_t memUsed_ = 0;
};

template <class Key, class Value, uint64_t MemoryUsedBy(const Value &)>
ClpMap<Key, Value, MemoryUsedBy>::ClpMap(const uint64_t capacity, const Ttl defaultTtl):
    defaultTtl_(defaultTtl)
{
    assert(defaultTtl >= 0);
    setMemLimit(capacity);
}

template <class Key, class Value, uint64_t MemoryUsedBy(const Value &)>
void
ClpMap<Key, Value, MemoryUsedBy>::setMemLimit(const uint64_t newLimit)
{
    if (memUsed_ > newLimit)
        trim(memLimit_ - newLimit);
    memLimit_ = newLimit;
}

/// \returns the index position of an entry identified by its key (or end())
template <class Key, class Value, uint64_t MemoryUsedBy(const Value &)>
typename ClpMap<Key, Value, MemoryUsedBy>::IndexIterator
ClpMap<Key, Value, MemoryUsedBy>::find(const Key &key)
{
    const auto i = index_.find(key);
    if (i == index_.end())
        return i;

    const auto entryPosition = i->second;
    if (!entryPosition->expired()) {
        if (entryPosition != entries_.begin())
            entries_.splice(entries_.begin(), entries_, entryPosition);
        return i;
    }
    // else fall through to cleanup

    erase(i);
    return index_.end();
}

template <class Key, class Value, uint64_t MemoryUsedBy(const Value &)>
const Value *
ClpMap<Key, Value, MemoryUsedBy>::get(const Key &key)
{
    const auto i = find(key);
    if (i != index_.end()) {
        const auto &entry = *(i->second);
        return &entry.value;
    }
    return nullptr;
}

template <class Key, class Value, uint64_t MemoryUsedBy(const Value &)>
std::optional<uint64_t>
ClpMap<Key, Value, MemoryUsedBy>::MemoryCountedFor(const Key &k, const Value &v)
{
    // Both storage and index store keys, but we count keySz once, assuming that
    // copying a Key does not consume more memory. This assumption holds for
    // Key=SBuf, but, ideally, we should be outsourcing this decision to another
    // configurable function, storing each key once, or hard-coding Key=SBuf.
    const auto keySz = k.length();

    // approximate calculation (e.g., containers store wrappers not value_types)
    return NaturalSum<uint64_t>(
               keySz,
               // storage
               sizeof(typename Entries::value_type),
               MemoryUsedBy(v),
               // index
               sizeof(typename Index::value_type));
}

template <class Key, class Value, uint64_t MemoryUsedBy(const Value &)>
bool
ClpMap<Key, Value, MemoryUsedBy>::add(const Key &key, const Value &v, const Ttl ttl)
{
    // optimization: avoid del() search, MemoryCountedFor() in always-empty maps
    if (memLimit() == 0)
        return false;

    del(key);

    if (ttl < 0)
        return false; // already expired; will never be returned by get()

    const auto memoryRequirements = MemoryCountedFor(key, v);
    if (!memoryRequirements)
        return false; // cannot even compute memory requirements

    const auto wantSpace = memoryRequirements.value();
    if (wantSpace > memLimit() || wantSpace == 0) // 0 is 64-bit integer overflow
        return false; // will never fit
    trim(wantSpace);

    auto &addedEntry = entries_.emplace_front(key, v, ttl);
    index_.emplace(key, entries_.begin());

    addedEntry.memCounted = wantSpace;
    memUsed_ += wantSpace;
    assert(memUsed_ >= wantSpace); // no overflows
    return true;
}

/// removes the cached entry (identified by its index) from the map
template <class Key, class Value, uint64_t MemoryUsedBy(const Value &)>
void
ClpMap<Key, Value, MemoryUsedBy>::erase(const IndexIterator &i)
{
    assert(i != index_.end());
    const auto entryPosition = i->second;

    assert(entryPosition != entries_.end());
    const auto sz = entryPosition->memCounted;
    assert(memUsed_ >= sz);
    memUsed_ -= sz;

    index_.erase(i); // destroys a "pointer" to our Entry
    entries_.erase(entryPosition); // destroys our Entry
}

template <class Key, class Value, uint64_t MemoryUsedBy(const Value &)>
void
ClpMap<Key, Value, MemoryUsedBy>::del(const Key &key)
{
    const auto i = find(key);
    if (i != index_.end())
        erase(i);
}

/// purges entries to make free memory large enough to fit wantSpace bytes
template <class Key, class Value, uint64_t MemoryUsedBy(const Value &)>
void
ClpMap<Key, Value, MemoryUsedBy>::trim(const uint64_t wantSpace)
{
    assert(wantSpace <= memLimit()); // no infinite loops and in-vain trimming
    while (freeMem() < wantSpace) {
        assert(!entries_.empty());
        // TODO: Purge expired entries first. They are useless, but their
        // presence may lead to purging potentially useful fresh entries here.
        del(entries_.rbegin()->key);
    }
}

template <class Key, class Value, uint64_t MemoryUsedBy(const Value &)>
ClpMap<Key, Value, MemoryUsedBy>::Entry::Entry(const Key &aKey, const Value &v, const Ttl ttl) :
    key(aKey),
    value(v),
    expires(0) // reset below
{
    SetToNaturalSumOrMax(expires, squid_curtime, ttl);
}

#endif /* SQUID_SRC_BASE_CLPMAP_H */

