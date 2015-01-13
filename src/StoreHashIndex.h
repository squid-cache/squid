/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STOREHASHINDEX_H
#define SQUID_STOREHASHINDEX_H

#include "Store.h"
#include "StoreSearch.h"

/* A summary store that indexs all its children
 * into a memory hash
 */

class StoreSearch;

class StoreHashIndex : public Store
{

public:
    StoreHashIndex();
    StoreHashIndex(StoreHashIndex const &); /* to cause link failures */
    virtual ~StoreHashIndex();
    virtual int callback();
    virtual void create();

    virtual StoreEntry * get
    (const cache_key *);

    virtual void get
    (String const, STOREGETCLIENT, void * cbdata);

    virtual void init();

    virtual void sync();

    virtual uint64_t maxSize() const;

    virtual uint64_t minSize() const;

    virtual uint64_t currentSize() const;

    virtual uint64_t currentCount() const;

    virtual int64_t maxObjectSize() const;

    virtual void getStats(StoreInfoStats &stats) const;
    virtual void stat(StoreEntry&) const;

    virtual void reference(StoreEntry&);

    virtual bool dereference(StoreEntry&, bool);

    virtual void maintain();

    virtual StoreSearch *search(String const url, HttpRequest *);

private:
    /* migration logic */
    StorePointer store(int const x) const;
    SwapDir &dir(int const idx) const;
};

class StoreHashIndexEntry : public StoreEntry
{};

class StoreSearchHashIndex : public StoreSearch
{

public:
    StoreSearchHashIndex(RefCount<StoreHashIndex> sd);
    StoreSearchHashIndex(StoreSearchHashIndex const &);
    virtual ~StoreSearchHashIndex();
    /* Iterator API - garh, wrong place */
    /* callback the client when a new StoreEntry is available
     * or an error occurs
     */
    virtual void next(void (callback)(void *cbdata), void *cbdata);
    /* return true if a new StoreEntry is immediately available */
    virtual bool next();
    virtual bool error() const;
    virtual bool isDone() const;
    virtual StoreEntry *currentItem();

    RefCount<StoreHashIndex> sd;

private:
    void copyBucket();
    void (*callback)(void *cbdata);
    void *cbdata;
    bool _done;
    int bucket;
    std::vector<StoreEntry *> entries;

    // keep this last. it plays with private/public
    CBDATA_CLASS2(StoreSearchHashIndex);
};

#endif /* SQUID_STOREHASHINDEX_H */

