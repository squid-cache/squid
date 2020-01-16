/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_UFS_UFSSTRATEGY_H
#define SQUID_FS_UFS_UFSSTRATEGY_H

#include "DiskIO/DiskFile.h"
#include "StoreIOState.h"

class Swapdir;
class StoreEntry;
class DiskIOStrategy;

namespace Fs
{
namespace Ufs
{
/// \ingroup UFS
class UFSStrategy
{
public:
    UFSStrategy (DiskIOStrategy *);
    virtual ~UFSStrategy ();
    virtual bool shedLoad();

    virtual int load();

    StoreIOState::Pointer createState(SwapDir *SD, StoreEntry *e, StoreIOState::STIOCB * callback, void *callback_data) const;
    /* UFS specific */
    virtual RefCount<DiskFile> newFile (char const *path);
    StoreIOState::Pointer open(SwapDir *, StoreEntry *, StoreIOState::STFNCB *,
                               StoreIOState::STIOCB *, void *);
    StoreIOState::Pointer create(SwapDir *, StoreEntry *, StoreIOState::STFNCB *,
                                 StoreIOState::STIOCB *, void *);

    virtual void unlinkFile (char const *);
    virtual void sync();

    virtual int callback();

    /** Init per-instance logic */
    virtual void init();

    /** cachemgr output on the IO instance stats */
    virtual void statfs(StoreEntry & sentry)const;

    /** The io strategy in use */
    DiskIOStrategy *io;

protected:

    friend class UFSSwapDir;

private:
    UFSStrategy(); //disabled
    UFSStrategy(UFSStrategy const &); //disabled
    UFSStrategy &operator=(UFSStrategy const &); //disabled

};

} //namespace Ufs
} //namespace Fs

#endif /* SQUID_FS_UFS_UFSSTRATEGY_H */

