/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_LRUMAP_H
#define SQUID_LRUMAP_H

#include "SquidTime.h"

#include <list>
#include <map>

template <class EntryValue, size_t EntryCost = sizeof(EntryValue)> class LruMap
{
public:
    class Entry
    {
    public:
        Entry(const char *aKey, EntryValue *t): key(aKey), value(t), date(squid_curtime) {}
        ~Entry() {delete value;}
    private:
        Entry(Entry &);
        Entry & operator = (Entry &);
    public:
        std::string key; ///< the key of entry
        EntryValue *value; ///< A pointer to the stored value
        time_t date; ///< The date the entry created
    };
    typedef std::list<Entry *> Queue;
    typedef typename std::list<Entry *>::iterator QueueIterator;

    /// key:queue_item mapping for fast lookups by key
    typedef std::map<std::string, QueueIterator> Map;
    typedef typename Map::iterator MapIterator;
    typedef std::pair<std::string, QueueIterator> MapPair;

    LruMap(int ttl, size_t size);
    ~LruMap();
    /// Search for an entry, and return a pointer
    EntryValue *get(const char *key);
    /// Add an entry to the map
    bool add(const char *key, EntryValue *t);
    /// Delete an entry from the map
    bool del(const char *key);
    /// (Re-)set the maximum size for this map
    void setMemLimit(size_t aSize);
    /// The available size for the map
    size_t memLimit() const {return memLimit_;}
    /// The free space of the map
    size_t freeMem() const { return (memLimit() > size() ? memLimit() - size() : 0);}
    /// The current size of the map
    size_t size() const {return (entries_ * EntryCost);}
    /// The number of stored entries
    int entries() const {return entries_;}
private:
    LruMap(LruMap const &);
    LruMap & operator = (LruMap const &);

    bool expired(const Entry &e) const;
    void trim();
    void touch(const MapIterator &i);
    bool del(const MapIterator &i);
    void findEntry(const char *key, LruMap::MapIterator &i);

    Map storage; ///< The Key/value * pairs
    Queue index; ///< LRU cache index
    int ttl;///< >0 ttl for caching, == 0 cache is disabled, < 0 store for ever
    size_t memLimit_; ///< The maximum memory to use
    int entries_; ///< The stored entries
};

template <class EntryValue, size_t EntryCost>
LruMap<EntryValue, EntryCost>::LruMap(int aTtl, size_t aSize): entries_(0)
{
    ttl = aTtl;

    setMemLimit(aSize);
}

template <class EntryValue, size_t EntryCost>
LruMap<EntryValue, EntryCost>::~LruMap()
{
    for (QueueIterator i = index.begin(); i != index.end(); ++i) {
        delete *i;
    }
}

template <class EntryValue, size_t EntryCost>
void
LruMap<EntryValue, EntryCost>::setMemLimit(size_t aSize)
{
    if (aSize > 0)
        memLimit_ = aSize;
    else
        memLimit_ = 0;
}

template <class EntryValue, size_t EntryCost>
void
LruMap<EntryValue, EntryCost>::findEntry(const char *key, LruMap::MapIterator &i)
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

template <class EntryValue, size_t EntryCost>
EntryValue *
LruMap<EntryValue, EntryCost>::get(const char *key)
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

template <class EntryValue, size_t EntryCost>
bool
LruMap<EntryValue, EntryCost>::add(const char *key, EntryValue *t)
{
    if (ttl == 0)
        return false;

    del(key);
    trim();

    if (memLimit() == 0)
        return false;

    index.push_front(new Entry(key, t));
    storage.insert(MapPair(key, index.begin()));

    ++entries_;
    return true;
}

template <class EntryValue, size_t EntryCost>
bool
LruMap<EntryValue, EntryCost>::expired(const LruMap::Entry &entry) const
{
    if (ttl < 0)
        return false;

    return (entry.date + ttl < squid_curtime);
}

template <class EntryValue, size_t EntryCost>
bool
LruMap<EntryValue, EntryCost>::del(LruMap::MapIterator const &i)
{
    if (i != storage.end()) {
        Entry *e = *i->second;
        index.erase(i->second);
        storage.erase(i);
        delete e;
        --entries_;
        return true;
    }
    return false;
}

template <class EntryValue, size_t EntryCost>
bool
LruMap<EntryValue, EntryCost>::del(const char *key)
{
    MapIterator i;
    findEntry(key, i);
    return del(i);
}

template <class EntryValue, size_t EntryCost>
void
LruMap<EntryValue, EntryCost>::trim()
{
    while (size() >= memLimit()) {
        QueueIterator i = index.end();
        --i;
        if (i != index.end()) {
            del((*i)->key.c_str());
        }
    }
}

template <class EntryValue, size_t EntryCost>
void
LruMap<EntryValue, EntryCost>::touch(LruMap::MapIterator const &i)
{
    // this must not be done when nothing is being cached.
    if (ttl == 0)
        return;

    index.push_front(*(i->second));
    index.erase(i->second);
    i->second = index.begin();
}

#endif

