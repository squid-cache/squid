
/*
 * $Id: store_dir_aufs.cc,v 1.51 2002/10/13 20:35:24 robertc Exp $
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

MemPool *squidaio_state_pool = NULL;
MemPool *aufs_qread_pool = NULL;
MemPool *aufs_qwrite_pool = NULL;
static int asyncufs_initialised = 0;

static STDUMP storeAufsDirDump;
static STCHECKOBJ storeAufsDirCheckObj;
static void storeAufsDirIOUnlinkFile(char *path);


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
storeAufsDirCheckObj(SwapDir * SD, const StoreEntry * e)
{
    int loadav;
    int ql;

#if OLD_UNUSED_CODE
    if (storeAufsDirExpiredReferenceAge(SD) < 300) {
	debug(47, 3) ("storeAufsDirCheckObj: NO: LRU Age = %d\n",
	    storeAufsDirExpiredReferenceAge(SD));
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
storeAufsDirIOUnlinkFile(char *path)
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
static void
storeAufsDirReconfigure(SwapDir * sd, int index, char *path)
{
    int i;
    int size;
    int l1;
    int l2;

    i = GetInteger();
    size = i << 10;		/* Mbytes to kbytes */
    if (size <= 0)
	fatal("storeAufsDirReconfigure: invalid size value");
    i = GetInteger();
    l1 = i;
    if (l1 <= 0)
	fatal("storeAufsDirReconfigure: invalid level 1 directories value");
    i = GetInteger();
    l2 = i;
    if (l2 <= 0)
	fatal("storeAufsDirReconfigure: invalid level 2 directories value");

    /* just reconfigure it */
    if (size == sd->max_size)
	debug(3, 1) ("Cache dir '%s' size remains unchanged at %d KB\n",
	    path, size);
    else
	debug(3, 1) ("Cache dir '%s' size changed to %d KB\n",
	    path, size);
    sd->max_size = size;

    parse_cachedir_options(sd, options, 0);

    return;
}

void
storeAufsDirDump(StoreEntry * entry, SwapDir * s)
{
    commonUfsDirDump (entry, s);
    dump_cachedir_options(entry, options, s);
}

/*
 * storeAufsDirParse *
 * Called when a *new* fs is being setup.
 */
static void
storeAufsDirParse(SwapDir * sd, int index, char *path)
{
    int i;
    int size;
    int l1;
    int l2;
    squidufsinfo_t *aioinfo;

    i = GetInteger();
    size = i << 10;		/* Mbytes to kbytes */
    if (size <= 0)
	fatal("storeAufsDirParse: invalid size value");
    i = GetInteger();
    l1 = i;
    if (l1 <= 0)
	fatal("storeAufsDirParse: invalid level 1 directories value");
    i = GetInteger();
    l2 = i;
    if (l2 <= 0)
	fatal("storeAufsDirParse: invalid level 2 directories value");

    aioinfo = (squidufsinfo_t *)xmalloc(sizeof(squidufsinfo_t));
    if (aioinfo == NULL)
	fatal("storeAufsDirParse: couldn't xmalloc() squidufsinfo_t!\n");

    sd->index = index;
    sd->path = xstrdup(path);
    sd->max_size = size;
    sd->fsdata = aioinfo;
    aioinfo->l1 = l1;
    aioinfo->l2 = l2;
    aioinfo->swaplog_fd = -1;
    aioinfo->map = NULL;	/* Debugging purposes */
    aioinfo->suggest = 0;
    aioinfo->io.storeDirUnlinkFile = storeAufsDirIOUnlinkFile;
    sd->init = commonUfsDirInit;
    sd->newfs = commonUfsDirNewfs;
    sd->dump = storeAufsDirDump;
    sd->freefs = commonUfsDirFree;
    sd->dblcheck = commonUfsCleanupDoubleCheck;
    sd->statfs = commonUfsDirStats;
    sd->maintainfs = commonUfsDirMaintain;
    sd->checkobj = storeAufsDirCheckObj;
    sd->refobj = commonUfsDirRefObj;
    sd->unrefobj = commonUfsDirUnrefObj;
    sd->callback = aioCheckCallbacks;
    sd->sync = aioSync;
    sd->obj.create = storeAufsCreate;
    sd->obj.open = storeAufsOpen;
    sd->obj.close = storeAufsClose;
    sd->obj.read = storeAufsRead;
    sd->obj.write = storeAufsWrite;
    sd->obj.unlink = storeAufsUnlink;
    sd->log.open = commonUfsDirOpenSwapLog;
    sd->log.close = commonUfsDirCloseSwapLog;
    sd->log.write = commonUfsDirSwapLog;
    sd->log.clean.start = commonUfsDirWriteCleanStart;
    sd->log.clean.nextentry = commonUfsDirCleanLogNextEntry;
    sd->log.clean.done = commonUfsDirWriteCleanDone;

    parse_cachedir_options(sd, options, 0);

    /* Initialise replacement policy stuff */
    sd->repl = createRemovalPolicy(Config.replPolicy);
}

/*
 * Initial setup / end destruction
 */
static void
storeAufsDirDone(void)
{
    aioDone();
    memPoolDestroy(&squidaio_state_pool);
    memPoolDestroy(&aufs_qread_pool);
    memPoolDestroy(&aufs_qwrite_pool);
    asyncufs_initialised = 0;
}

void
storeFsSetup_aufs(storefs_entry_t * storefs)
{
    assert(!asyncufs_initialised);
    storefs->parsefunc = storeAufsDirParse;
    storefs->reconfigurefunc = storeAufsDirReconfigure;
    storefs->donefunc = storeAufsDirDone;
    squidaio_state_pool = memPoolCreate("AUFS IO State data", sizeof(squidaiostate_t));
    aufs_qread_pool = memPoolCreate("AUFS Queued read data",
	sizeof(queued_read));
    aufs_qwrite_pool = memPoolCreate("AUFS Queued write data",
	sizeof(queued_write));

    asyncufs_initialised = 1;
    aioInit();
}
