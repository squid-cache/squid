/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Store Rebuild Routines */

#ifndef SQUID_SRC_STORE_REBUILD_H
#define SQUID_SRC_STORE_REBUILD_H

#include "store_key_md5.h"

class MemBuf;

/// cache_dir(s) indexing statistics
class StoreRebuildData
{
public:
    /// maintain earliest initiation time across multiple indexing cache_dirs
    void updateStartTime(const timeval &dirStartTime);

    /// whether we have worked on indexing this(these) cache_dir(s) before
    bool started() const { return startTime.tv_sec > 0; }

    // when adding members, keep the class compatible with placement new onto a
    // zeroed shared memory segment (see Rock::Rebuild::Stats usage)

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
    int64_t validations = 0; ///< the number of validated cache entries, slots
    timeval startTime = {}; ///< absolute time when the rebuild was initiated
};

/// advancement of work that consists of (usually known number) of similar steps
class Progress
{
public:
    Progress(const int64_t stepsCompleted, const int64_t stepsTotal):
        completed(stepsCompleted), goal(stepsTotal) {}

    /// brief progress report suitable for level-0/1 debugging
    void print(std::ostream &os) const;

    int64_t completed; ///< the number of finished work steps
    int64_t goal; ///< the known total number of work steps (or negative)
};

inline std::ostream &
operator <<(std::ostream &os, const Progress &p)
{
    p.print(os);
    return os;
}

void storeRebuildStart(void);
void storeRebuildComplete(StoreRebuildData *);
void storeRebuildProgress(int sd_index, int total, int sofar);

/// loads entry from disk; fills supplied memory buffer on success
bool storeRebuildLoadEntry(int fd, int diskIndex, MemBuf &buf, StoreRebuildData &counts);

/**
 * Parses the given Store entry metadata, filling e and key.
 * Optimization: Both e and key parameters may be updated even on failures.
 *
 * \param buf memory containing serialized Store entry swap metadata (at least)
 * \param e caller's temporary StoreEntry object for returning parsed metadata
 * \param key caller's temporary Store entry key buffer; usable to set e.key
 * \param expectedSize either total entry size (including swap metadata) or 0
 *
 * \retval true success; e/key filled with parsed metadata
 * \retval false failure; e/key ought to be ignored (may be filled/dirty)
 */
bool storeRebuildParseEntry(MemBuf &buf, StoreEntry &e, cache_key *key, StoreRebuildData &counts, uint64_t expectedSize);

#endif /* SQUID_SRC_STORE_REBUILD_H */

