/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Store Rebuild Routines */

#ifndef SQUID_STORE_REBUILD_H_
#define SQUID_STORE_REBUILD_H_

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

