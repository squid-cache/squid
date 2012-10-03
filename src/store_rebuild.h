#ifndef SQUID_STORE_REBUILD_H_
#define SQUID_STORE_REBUILD_H_
/*
 * DEBUG: section 20    Store Rebuild Routines
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

// currently a POD
class StoreRebuildData
{
public:
    int objcount;       /* # objects successfully reloaded */
    int expcount;       /* # objects expired */
    int scancount;      /* # entries scanned or read from state file */
    int clashcount;     /* # swapfile clashes avoided */
    int dupcount;       /* # duplicates purged */
    int cancelcount;        /* # SWAP_LOG_DEL objects purged */
    int invalid;        /* # bad lines */
    int badflags;       /* # bad e->flags */
    int bad_log_op;
    int zero_object_sz;
};

void storeRebuildStart(void);
void storeRebuildComplete(StoreRebuildData *);
void storeRebuildProgress(int sd_index, int total, int sofar);

/// loads entry from disk; fills supplied memory buffer on success
bool storeRebuildLoadEntry(int fd, int diskIndex, MemBuf &buf, StoreRebuildData &counts);
/// parses entry buffer and validates entry metadata; fills e on success
bool storeRebuildParseEntry(MemBuf &buf, StoreEntry &e, cache_key *key, StoreRebuildData &counts, uint64_t expectedSize);
/// checks whether the loaded entry should be kept; updates counters
bool storeRebuildKeepEntry(const StoreEntry &e, const cache_key *key, StoreRebuildData &counts);

#endif /* SQUID_STORE_REBUILD_H_ */
