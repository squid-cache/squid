/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_ROCK_REBUILD_H
#define SQUID_FS_ROCK_REBUILD_H

#include "base/AsyncJob.h"
#include "base/RunnersRegistry.h"
#include "cbdata.h"
#include "fs/rock/forward.h"
#include "ipc/mem/Pointer.h"
#include "ipc/StoreMap.h"
#include "MemBuf.h"
#include "store_rebuild.h"

namespace Rock
{

class LoadingEntry;
class LoadingSlot;
class LoadingParts;

/// \ingroup Rock
/// manages store rebuild process: loading meta information from db on disk
class Rebuild: public AsyncJob, private IndependentRunner
{
    CBDATA_CHILD(Rebuild);

public:
    /// cache_dir indexing statistics shared across same-kid process restarts
    class Stats
    {
    public:
        static SBuf Path(const char *dirPath);
        static Ipc::Mem::Owner<Stats> *Init(const SwapDir &);

        static size_t SharedMemorySize() { return sizeof(Stats); }
        size_t sharedMemorySize() const { return SharedMemorySize(); }

        /// whether the rebuild is finished already
        bool completed(const SwapDir &) const;

        StoreRebuildData counts;
    };

    /// starts indexing the given cache_dir if that indexing is necessary
    /// \returns whether the indexing was necessary (and, hence, started)
    static bool Start(SwapDir &dir);

protected:
    /// whether the current kid is responsible for rebuilding the given cache_dir
    static bool IsResponsible(const SwapDir &);

    Rebuild(SwapDir *dir, const Ipc::Mem::Pointer<Stats> &);
    ~Rebuild() override;

    /* Registered Runner API */
    void startShutdown() override;

    /* AsyncJob API */
    void start() override;
    bool doneAll() const override;
    void swanSong() override;

    bool doneLoading() const;
    bool doneValidating() const;

private:
    void checkpoint();
    void steps();
    void loadingSteps();
    void validationSteps();
    void loadOneSlot();
    void validateOneEntry(const sfileno fileNo);
    void validateOneSlot(const SlotId slotId);
    bool importEntry(Ipc::StoreMapAnchor &anchor, const sfileno slotId, const DbCellHeader &header);
    void freeBadEntry(const sfileno fileno, const char *eDescription);

    void failure(const char *msg, int errNo = 0);

    LoadingEntry loadingEntry(const sfileno fileNo);
    void startNewEntry(const sfileno fileno, const SlotId slotId, const DbCellHeader &header);
    void primeNewEntry(Ipc::StoreMapAnchor &anchor, const sfileno fileno, const DbCellHeader &header);
    void finalizeOrFree(const sfileno fileNo, LoadingEntry &le);
    void finalizeOrThrow(const sfileno fileNo, LoadingEntry &le);
    void addSlotToEntry(const sfileno fileno, const SlotId slotId, const DbCellHeader &header);
    void useNewSlot(const SlotId slotId, const DbCellHeader &header);

    LoadingSlot loadingSlot(const SlotId slotId);
    void mapSlot(const SlotId slotId, const DbCellHeader &header);
    void freeUnusedSlot(const SlotId slotId, const bool invalid);
    void freeSlot(const SlotId slotId, const bool invalid);

    template <class SlotIdType>
    void chainSlots(SlotIdType &from, const SlotId to);

    bool sameEntry(const sfileno fileno, const DbCellHeader &header) const;

    SBuf progressDescription() const;

    SwapDir *sd;
    LoadingParts *parts; ///< parts of store entries being loaded from disk

    Ipc::Mem::Pointer<Stats> stats; ///< indexing statistics in shared memory

    int64_t dbSize;
    int dbSlotSize; ///< the size of a db cell, including the cell header
    int64_t dbSlotLimit; ///< total number of db cells
    int64_t dbEntryLimit; ///< maximum number of entries that can be stored in db

    int fd; // store db file descriptor
    int64_t dbOffset; // TODO: calculate in a method, using loadingPos
    int64_t loadingPos; ///< index of the db slot being loaded from disk now
    int64_t validationPos; ///< index of the loaded db slot being validated now
    MemBuf buf; ///< space to load current db slot (and entry metadata) into

    StoreRebuildData &counts; ///< a reference to the shared memory counters

    /// whether we have started indexing this cache_dir before,
    /// presumably in the previous process performing the same-kid role
    const bool resuming;

    static void Steps(void *data);
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_REBUILD_H */

