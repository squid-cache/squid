/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 47    Store Search */

#include "squid.h"
#include "Debug.h"
#include "globals.h"
#include "store/LocalSearch.h"
#include "StoreSearch.h"

namespace Store {

/// iterates local store_table
class LocalSearch : public StoreSearch
{
    CBDATA_CLASS(LocalSearch);

public:
    /* StoreSearch API */
    virtual void next(void (callback)(void *cbdata), void *cbdata) override;
    virtual bool next() override;
    virtual bool error() const override;
    virtual bool isDone() const override;
    virtual StoreEntry *currentItem() override;

private:
    void copyBucket();
    bool _done = false;
    int bucket = 0;
    std::vector<StoreEntry *> entries;
};

} // namespace Store

CBDATA_NAMESPACED_CLASS_INIT(Store, LocalSearch);

StoreSearch *
Store::NewLocalSearch()
{
    return new LocalSearch;
}

void
Store::LocalSearch::next(void (aCallback)(void *), void *aCallbackData)
{
    next();
    aCallback (aCallbackData);
}

bool
Store::LocalSearch::next()
{
    if (!entries.empty())
        entries.pop_back();

    while (!isDone() && !entries.size())
        copyBucket();

    return currentItem() != NULL;
}

bool
Store::LocalSearch::error() const
{
    return false;
}

bool
Store::LocalSearch::isDone() const
{
    return bucket >= store_hash_buckets || _done;
}

StoreEntry *
Store::LocalSearch::currentItem()
{
    if (!entries.size())
        return NULL;

    return entries.back();
}

void
Store::LocalSearch::copyBucket()
{
    /* probably need to lock the store entries...
     * we copy them all to prevent races on the links. */
    assert (!entries.size());
    hash_link *link_ptr = NULL;
    hash_link *link_next = NULL;
    link_next = hash_get_bucket(store_table, bucket);

    while (NULL != (link_ptr = link_next)) {
        link_next = link_ptr->next;
        StoreEntry *e = (StoreEntry *) link_ptr;

        entries.push_back(e);
    }

    // minimize debugging: we may be called more than a million times on startup
    if (const auto count = entries.size())
        debugs(47, 8, "bucket #" << bucket << " entries: " << count);

    ++bucket;
}

