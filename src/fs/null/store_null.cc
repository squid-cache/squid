
/*
 * $Id: store_null.cc,v 1.3 2002/04/16 22:43:05 wessels Exp $
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

static int null_initialised = 0;
static void storeNullDirInit(SwapDir * sd);
static void storeNullDirStats(SwapDir * SD, StoreEntry * sentry);
static STCHECKOBJ storeNullDirCheckObj;
static STFSRECONFIGURE storeNullDirReconfigure;
static STLOGCLEANSTART storeNullDirWriteCleanStart;
static STLOGCLEANDONE storeNullDirWriteCleanDone;
static EVH storeNullDirRebuildComplete;

/* The only externally visible interface */
STSETUP storeFsSetup_null;

static void
storeNullDirReconfigure(SwapDir * sd, int index, char *path)
{
    (void) 0;
}

static void
storeNullDirDone(void)
{
    null_initialised = 0;
}

static void
storeNullDirStats(SwapDir * SD, StoreEntry * sentry)
{
    (void) 0;
}

static void
storeNullDirInit(SwapDir * sd)
{
    store_dirs_rebuilding++;
    eventAdd("storeNullDirRebuildComplete", storeNullDirRebuildComplete,
	NULL, 0.0, 1);
}

static void
storeNullDirRebuildComplete(void *unused)
{
    struct _store_rebuild_data counts;
    memset(&counts, '\0', sizeof(counts));
    store_dirs_rebuilding--;
    storeRebuildComplete(&counts);
}

static int
storeNullDirCheckObj(SwapDir * SD, const StoreEntry * e)
{
    return -1;
}

static int
storeNullDirWriteCleanStart(SwapDir * unused)
{
    return 0;
}

static void
storeNullDirWriteCleanDone(SwapDir * unused)
{
    (void) 0;
}

static void
storeNullDirParse(SwapDir * sd, int index, char *path)
{
    sd->index = index;
    sd->path = xstrdup(path);
    sd->statfs = storeNullDirStats;
    sd->init = storeNullDirInit;
    sd->checkobj = storeNullDirCheckObj;
    sd->log.clean.start = storeNullDirWriteCleanStart;
    sd->log.clean.done = storeNullDirWriteCleanDone;
    parse_cachedir_options(sd, NULL, 0);
}

/* Setup and register the store module */

void
storeFsSetup_null(storefs_entry_t * storefs)
{
    assert(!null_initialised);
    storefs->parsefunc = storeNullDirParse;
    storefs->reconfigurefunc = storeNullDirReconfigure;
    storefs->donefunc = storeNullDirDone;
    null_initialised = 1;
}
