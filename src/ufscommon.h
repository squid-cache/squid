
/*
 * $Id: ufscommon.h,v 1.1 2002/10/12 09:45:56 robertc Exp $
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

#ifndef SQUID_UFSCOMMON_H
#define SQUID_UFSCOMMON_H

#include "squid.h"

#define DefaultLevelOneDirs     16
#define DefaultLevelTwoDirs     256
#define STORE_META_BUFSZ 4096

typedef struct _iospecific_t iospecific_t;
struct _iospecific_t {
    void (*storeDirUnlinkFile) (char *);
};

typedef struct _squidufsinfo_t squidufsinfo_t;
struct _squidufsinfo_t {
    int swaplog_fd;
    int l1;
    int l2;
    fileMap *map;
    int suggest;
    iospecific_t io;
};

/* Common UFS routines */
void commonUfsDirSwapLog(const SwapDir * sd, const StoreEntry * e, int op);
FREE storeSwapLogDataFree;
void commonUfsDirWriteCleanDone(SwapDir * sd);
const StoreEntry *commonUfsDirCleanLogNextEntry(SwapDir * sd);
void commonUfsDirCloseSwapLog(SwapDir * sd);
int commonUfsDirWriteCleanStart(SwapDir * sd);
void commonUfsDirInit(SwapDir * sd);
void commonUfsDirUnlinkFile(SwapDir * SD, sfileno f);
void commonUfsDirOpenSwapLog(SwapDir * sd);
void commonUfsDirNewfs(SwapDir * sd);
void commonUfsDirMaintain(SwapDir * SD);
void commonUfsDirRefObj(SwapDir * SD, StoreEntry * e);
void commonUfsDirUnrefObj(SwapDir * SD, StoreEntry * e);
void commonUfsDirReplAdd(SwapDir * SD, StoreEntry * e);
void commonUfsDirReplRemove(StoreEntry * e);
void commonUfsDirStats(SwapDir * SD, StoreEntry * sentry);
void commonUfsDirDump(StoreEntry * entry, SwapDir * s);
void commonUfsDirFree(SwapDir * s);
char *commonUfsDirFullPath(SwapDir * SD, sfileno filn, char *fullpath);
int commonUfsCleanupDoubleCheck(SwapDir * sd, StoreEntry * e);
int commonUfsDirMapBitAllocate(SwapDir * SD);
void commonUfsDirMapBitReset(SwapDir * SD, sfileno filn);

#endif /* SQUID_UFSCOMMON_H */
