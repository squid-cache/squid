/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Store Rebuild Routines */

#ifndef SQUID_STORE_REBUILD_H_
#define SQUID_STORE_REBUILD_H_

#include "store_key_md5.h"

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

#endif /* SQUID_STORE_REBUILD_H_ */

