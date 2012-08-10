/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
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
