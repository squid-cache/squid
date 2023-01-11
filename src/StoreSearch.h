/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORESEARCH_H
#define SQUID_STORESEARCH_H

#include "base/RefCount.h"
#include "Store.h"

class StoreSearch : public RefCountable
{

public:
    StoreSearch() {}

    StoreSearch(StoreSearch const &); /* no implementation - trigger link failures */
    virtual ~StoreSearch() {}

    /* not ready yet
    void asList(void (*) (CbDataList<StoreEntryPointer), void *cbdata);
    */
    /* callback the client when a new StoreEntry is available
     * or an error occurs
     */
    virtual void next(void (callback)(void *cbdata), void *cbdata) = 0;
    /* return true if a new StoreEntry is immediately available
     * ???- not decided - if false, trigger making a new one available
     * this would be for sync api users that will schedule their own callback
     * to try again later. so if that next() has to allow multiple
     * calls being made to it without error
     */
    virtual bool next() = 0;
    virtual bool error() const = 0;
    virtual bool isDone() const = 0;
    virtual StoreEntry *currentItem() = 0;
};

typedef RefCount<StoreSearch> StoreSearchPointer;

#endif /* SQUID_STORESEARCH_H */

