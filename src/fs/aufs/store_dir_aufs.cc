
/*
 * $Id: store_dir_aufs.cc,v 1.55 2003/02/21 22:50:29 robertc Exp $
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
#include "Store.h"

#include "store_asyncufs.h"
#include "ufscommon.h"
#include "SwapDir.h"

MemPool *aufs_qread_pool = NULL;
MemPool *aufs_qwrite_pool = NULL;
static int asyncufs_initialised = 0;

/* The MAIN externally visible function */
STSETUP storeFsSetup_aufs;

/*
 * storeAufsDirCheckObj
 *
 * This routine is called by storeDirSelectSwapDir to see if the given
 * object is able to be stored on this filesystem. AUFS filesystems will
 * happily store anything as long as the LRU time isn't too small.
 */
int
AUFSSwapDir::canStore(StoreEntry const &e) const
{
    int loadav;
    int ql;

#if OLD_UNUSED_CODE

    if (storeAufsDirExpiredReferenceAge(this) < 300) {
        debug(47, 3) ("storeAufsDirCheckObj: NO: LRU Age = %d\n",
                      storeAufsDirExpiredReferenceAge(this));
        /* store_check_cachable_hist.no.lru_age_too_low++; */
        return -1;
    }

#endif
    ql = aioQueueSize();

    if (ql == 0)
        loadav = 0;

    loadav = ql * 1000 / MAGIC1;

    debug(47, 9) ("storeAufsDirCheckObj: load=%d\n", loadav);

    return loadav;
}

void
AUFSSwapDir::unlinkFile(char const *path)
{
#if USE_TRUNCATE_NOT_UNLINK
    aioTruncate(path, NULL, NULL);
#else

    aioUnlink(path, NULL, NULL);
#endif
}

/* ========== LOCAL FUNCTIONS ABOVE, GLOBAL FUNCTIONS BELOW ========== */

static struct cache_dir_option options[] =
    {
#if NOT_YET_DONE
        {"L1", storeAufsDirParseL1, storeAufsDirDumpL1},
        {"L2", storeAufsDirParseL2, storeAufsDirDumpL2},
#endif
        {NULL, NULL}
    };

/*
 * storeAufsDirReconfigure
 *
 * This routine is called when the given swapdir needs reconfiguring 
 */
void
AUFSSwapDir::reconfigure(int anIndex, char *aPath)
{
    UFSSwapDir::reconfigure (anIndex, aPath);

    parse_cachedir_options(this, options, 0);
}

void
AUFSSwapDir::dump(StoreEntry & entry) const
{
    UFSSwapDir::dump(entry);
    dump_cachedir_options(&entry, options, this);
}

/*
 * storeAufsDirParse *
 * Called when a *new* fs is being setup.
 */
void
AUFSSwapDir::parse(int anIndex, char *aPath)
{
    UFSSwapDir::parse(anIndex, aPath);

    parse_cachedir_options(this, options, 0);
}

/*
 * Initial setup / end destruction
 */
static void
storeAufsDirDone(void)
{
    aioDone();
    memPoolDestroy(&aufs_qread_pool);
    memPoolDestroy(&aufs_qwrite_pool);
    asyncufs_initialised = 0;
}

static SwapDir *
storeAufsNew(void)
{
    AUFSSwapDir *result = new AUFSSwapDir;
    result->IO = &AufsIO::Instance;
    return result;
}

void
storeFsSetup_aufs(storefs_entry_t * storefs)
{
    assert(!asyncufs_initialised);
    storefs->donefunc = storeAufsDirDone;
    storefs->newfunc = storeAufsNew;

    asyncufs_initialised = 1;
    aioInit();
}
