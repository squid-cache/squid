/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_UFS_STORESEARCHUFS_H
#define SQUID_FS_UFS_STORESEARCHUFS_H

#include "StoreSearch.h"
#include "UFSSwapDir.h"

namespace Fs
{
namespace Ufs
{

/// \ingroup UFS
class StoreSearchUFS : public StoreSearch
{
public:
    StoreSearchUFS(RefCount<UFSSwapDir> sd);
    virtual ~StoreSearchUFS();

    /** \todo Iterator API - garh, wrong place */
    /**
     * callback the client when a new StoreEntry is available
     * or an error occurs
     */
    virtual void next(void (callback)(void *cbdata), void *cbdata);

    /**
     \retval true if a new StoreEntry is immediately available
     \retval false if a new StoreEntry is NOT immediately available
     */
    virtual bool next();

    virtual bool error() const;
    virtual bool isDone() const;
    virtual StoreEntry *currentItem();

    RefCount<UFSSwapDir> sd;
    RemovalPolicyWalker *walker;

private:
    CBDATA_CLASS2(StoreSearchUFS);
    /// \bug (callback) should be hidden behind a proper human readable name
    void (callback)(void *cbdata);
    void *cbdata;
    StoreEntry * current;
    bool _done;

    StoreSearchUFS(StoreSearchUFS const &); //disabled
    StoreSearchUFS& operator=(StoreSearchUFS const &); //disabled
    StoreSearchUFS(); //disabled
};

} //namespace Ufs
} //namespace Fs
#endif /* SQUID_FS_UFS_STORESEARCHUFS_H */

