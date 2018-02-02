/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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
    StoreRebuildData() :
        objcount(0), expcount(0), scancount(0), clashcount(0),
        dupcount(0), cancelcount(0), invalid(0), badflags(0),
        bad_log_op(0), zero_object_sz(0)
    {}

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

#endif /* SQUID_STORE_REBUILD_H_ */

