/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Store Rebuild Routines */

#ifndef SQUID_STORE_REBUILD_H_
#define SQUID_STORE_REBUILD_H_

#include "store_key_md5.h"

extern int opt_foreground_rebuild;

class StoreRebuildData
{
public:
    int objcount = 0;       /* # objects successfully reloaded */
    int expcount = 0;       /* # objects expired */
    int scancount = 0;      /* # entries scanned or read from state file */
    int clashcount = 0;     /* # swapfile clashes avoided */
    int dupcount = 0;       /* # duplicates purged */
    int cancelcount = 0;    /* # SWAP_LOG_DEL objects purged */
    int invalid = 0;        /* # bad lines */
    int badflags = 0;       /* # bad e->flags */
    int bad_log_op = 0;
    int zero_object_sz = 0;
};

void storeRebuildStart(void);
void storeRebuildComplete(StoreRebuildData *);
void storeRebuildProgress(int sd_index, int total, int sofar);

/// loads entry from disk; fills supplied memory buffer on success
bool storeRebuildLoadEntry(int fd, int diskIndex, MemBuf &buf, StoreRebuildData &counts);
/// parses entry buffer and validates entry metadata; fills e on success
bool storeRebuildParseEntry(MemBuf &buf, StoreEntry &e, cache_key *key, StoreRebuildData &counts, uint64_t expectedSize);

inline unsigned int
rebuildMaxSpentMsec()
{
    // Balance our desire to maximize the number of entries processed at once
    // (and, hence, minimize overheads and total rebuild time) with a
    // requirement to also process Coordinator events, disk I/Os, etc.
    static const int backgroundMsec = 50; // keep small: most RAM I/Os are under 1ms
    static const int foregroundMsec = 1000; // we do not need to react to signals faster
    return opt_foreground_rebuild ? foregroundMsec : backgroundMsec;
}

#endif /* SQUID_STORE_REBUILD_H_ */

