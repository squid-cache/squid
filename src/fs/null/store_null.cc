
/*
 * $Id: store_null.cc,v 1.4 2002/12/27 10:26:38 robertc Exp $
 *
 * DEBUG: section 47    Store Directory Routines
 * AUTHOR: Duane Wessels
 *
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

#include "squid.h"
#if HAVE_STATVFS
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#endif
#include "SwapDir.h"
#include "Store.h"

class NullSwapDir : public SwapDir 
{
public:
    virtual void init();
    virtual int canStore(StoreEntry const &)const;
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, STFNCB *, STIOCB *, void *);
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, STFNCB *, STIOCB *, void *);
    virtual void parse(int, char*);
    virtual void reconfigure (int, char *);
};

static int null_initialised = 0;
static EVH storeNullDirRebuildComplete;

/* The only externally visible interface */
STSETUP storeFsSetup_null;

void
NullSwapDir::reconfigure(int index, char *path)
{
    (void) 0;
}

static void
storeNullDirDone(void)
{
    null_initialised = 0;
}

static SwapDir *
storeNullNew(void)
{
    SwapDir *result = new NullSwapDir;
    return result;
}

void
NullSwapDir::init()
{
    store_dirs_rebuilding++;
    eventAdd("storeNullDirRebuildComplete", storeNullDirRebuildComplete,
	NULL, 0.0, 1);
}

StoreIOState::Pointer
NullSwapDir::createStoreIO(StoreEntry &, STFNCB *, STIOCB *, void *)
{
    fatal ("Attempt to get a StoreIO from the NULL store!\n");
    return NULL;
}

StoreIOState::Pointer
NullSwapDir::openStoreIO(StoreEntry &, STFNCB *, STIOCB *, void *)
{
    fatal ("Attempt to get a StoreIO from the NULL store!\n");
    return NULL;
}

static void
storeNullDirRebuildComplete(void *unused)
{
    struct _store_rebuild_data counts;
    memset(&counts, '\0', sizeof(counts));
    store_dirs_rebuilding--;
    storeRebuildComplete(&counts);
}

int
NullSwapDir::canStore(StoreEntry const &)const
{
    return -1;
}

void
NullSwapDir::parse(int anIndex, char *aPath)
{
    index = anIndex;
    path = xstrdup(aPath);
    parse_cachedir_options(this, NULL, 0);
}

/* Setup and register the store module */

void
storeFsSetup_null(storefs_entry_t * storefs)
{
    assert(!null_initialised);
    storefs->donefunc = storeNullDirDone;
    storefs->newfunc = storeNullNew;
    null_initialised = 1;
}
