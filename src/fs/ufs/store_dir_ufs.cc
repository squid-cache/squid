
/*
 * $Id: store_dir_ufs.cc,v 1.50 2002/10/12 09:45:58 robertc Exp $
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

#include "store_ufs.h"
#include "ufscommon.h"

MemPool *ufs_state_pool = NULL;
static int ufs_initialised = 0;

static STDUMP storeUfsDirDump;
static STCHECKOBJ storeUfsDirCheckObj;
static void storeUfsDirIOUnlinkFile(char *path);

STSETUP storeFsSetup_ufs;

/*
 * storeUfsDirCheckObj
 *
 * This routine is called by storeDirSelectSwapDir to see if the given
 * object is able to be stored on this filesystem. UFS filesystems will
 * happily store anything as long as the LRU time isn't too small.
 */
int
storeUfsDirCheckObj(SwapDir * SD, const StoreEntry * e)
{
    /* Return 999 (99.9%) constant load */
    return 999;
}

void
storeUfsDirIOUnlinkFile(char *path)
{
#if USE_UNLINKD
    unlinkdUnlink(path);
#elif USE_TRUNCATE
    truncate(path, 0);
#else
    unlink(path);
#endif
}

/* ========== LOCAL FUNCTIONS ABOVE, GLOBAL FUNCTIONS BELOW ========== */

static struct cache_dir_option options[] =
{
#if NOT_YET_DONE
    {"L1", storeUfsDirParseL1, storeUfsDirDumpL1},
    {"L2", storeUfsDirParseL2, storeUfsDirDumpL2},
#endif
    {NULL, NULL}
};

/*
 * storeUfsDirReconfigure
 *
 * This routine is called when the given swapdir needs reconfiguring 
 */
static void
storeUfsDirReconfigure(SwapDir * sd, int index, char *path)
{
    int i;
    int size;
    int l1;
    int l2;

    i = GetInteger();
    size = i << 10;		/* Mbytes to kbytes */
    if (size <= 0)
	fatal("storeUfsDirReconfigure: invalid size value");
    i = GetInteger();
    l1 = i;
    if (l1 <= 0)
	fatal("storeUfsDirReconfigure: invalid level 1 directories value");
    i = GetInteger();
    l2 = i;
    if (l2 <= 0)
	fatal("storeUfsDirReconfigure: invalid level 2 directories value");

    /* just reconfigure it */
    if (size == sd->max_size)
	debug(3, 1) ("Cache dir '%s' size remains unchanged at %d KB\n",
	    path, size);
    else
	debug(3, 1) ("Cache dir '%s' size changed to %d KB\n",
	    path, size);
    sd->max_size = size;

    parse_cachedir_options(sd, options, 1);
}

void
storeUfsDirDump(StoreEntry * entry, SwapDir * s)
{
    commonUfsDirDump (entry, s);
    dump_cachedir_options(entry, options, s);
}

/*
 * storeUfsDirParse
 *
 * Called when a *new* fs is being setup.
 */
static void
storeUfsDirParse(SwapDir * sd, int index, char *path)
{
    int i;
    int size;
    int l1;
    int l2;
    squidufsinfo_t *ufsinfo;

    i = GetInteger();
    size = i << 10;		/* Mbytes to kbytes */
    if (size <= 0)
	fatal("storeUfsDirParse: invalid size value");
    i = GetInteger();
    l1 = i;
    if (l1 <= 0)
	fatal("storeUfsDirParse: invalid level 1 directories value");
    i = GetInteger();
    l2 = i;
    if (l2 <= 0)
	fatal("storeUfsDirParse: invalid level 2 directories value");

    ufsinfo = xmalloc(sizeof(squidufsinfo_t));
    if (ufsinfo == NULL)
	fatal("storeUfsDirParse: couldn't xmalloc() squidufsinfo_t!\n");

    sd->index = index;
    sd->path = xstrdup(path);
    sd->max_size = size;
    sd->fsdata = ufsinfo;
    ufsinfo->l1 = l1;
    ufsinfo->l2 = l2;
    ufsinfo->swaplog_fd = -1;
    ufsinfo->map = NULL;	/* Debugging purposes */
    ufsinfo->suggest = 0;
    ufsinfo->io.storeDirUnlinkFile = storeUfsDirIOUnlinkFile;
    sd->init = commonUfsDirInit;
    sd->newfs = commonUfsDirNewfs;
    sd->dump = storeUfsDirDump;
    sd->freefs = commonUfsDirFree;
    sd->dblcheck = commonUfsCleanupDoubleCheck;
    sd->statfs = commonUfsDirStats;
    sd->maintainfs = commonUfsDirMaintain;
    sd->checkobj = storeUfsDirCheckObj;
    sd->refobj = commonUfsDirRefObj;
    sd->unrefobj = commonUfsDirUnrefObj;
    sd->callback = NULL;
    sd->sync = NULL;
    sd->obj.create = storeUfsCreate;
    sd->obj.open = storeUfsOpen;
    sd->obj.close = storeUfsClose;
    sd->obj.read = storeUfsRead;
    sd->obj.write = storeUfsWrite;
    sd->obj.unlink = storeUfsUnlink;
    sd->log.open = commonUfsDirOpenSwapLog;
    sd->log.close = commonUfsDirCloseSwapLog;
    sd->log.write = commonUfsDirSwapLog;
    sd->log.clean.start = commonUfsDirWriteCleanStart;
    sd->log.clean.nextentry = commonUfsDirCleanLogNextEntry;
    sd->log.clean.done = commonUfsDirWriteCleanDone;

    parse_cachedir_options(sd, options, 1);

    /* Initialise replacement policy stuff */
    sd->repl = createRemovalPolicy(Config.replPolicy);
}

/*
 * Initial setup / end destruction
 */
static void
storeUfsDirDone(void)
{
    memPoolDestroy(&ufs_state_pool);
    ufs_initialised = 0;
}

void
storeFsSetup_ufs(storefs_entry_t * storefs)
{
    assert(!ufs_initialised);
    storefs->parsefunc = storeUfsDirParse;
    storefs->reconfigurefunc = storeUfsDirReconfigure;
    storefs->donefunc = storeUfsDirDone;
    ufs_state_pool = memPoolCreate("UFS IO State data", sizeof(ufsstate_t));
    ufs_initialised = 1;
}
