/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_ROCK_REBUILD_H
#define SQUID_FS_ROCK_REBUILD_H

#include "base/AsyncJob.h"
#include "cbdata.h"
#include "fs/rock/forward.h"
#include "MemBuf.h"
#include "store_rebuild.h"

namespace Rock
{

class LoadingEntry;

/// \ingroup Rock
/// manages store rebuild process: loading meta information from db on disk
class Rebuild: public AsyncJob
{
public:
    Rebuild(SwapDir *dir);
    ~Rebuild();

protected:
    /* AsyncJob API */
    virtual void start();
    virtual bool doneAll() const;
    virtual void swanSong();

private:
    void checkpoint();
    void steps();
    void loadingSteps();
    void validationSteps();
    void loadOneSlot();
    void validateOneEntry();
    bool importEntry(Ipc::StoreMapAnchor &anchor, const sfileno slotId, const DbCellHeader &header);
    void freeBadEntry(const sfileno fileno, const char *eDescription);

    void failure(const char *msg, int errNo = 0);

    void startNewEntry(const sfileno fileno, const SlotId slotId, const DbCellHeader &header);
    void primeNewEntry(Ipc::StoreMapAnchor &anchor, const sfileno fileno, const DbCellHeader &header);
    void addSlotToEntry(const sfileno fileno, const SlotId slotId, const DbCellHeader &header);
    void useNewSlot(const SlotId slotId, const DbCellHeader &header);

    void mapSlot(const SlotId slotId, const DbCellHeader &header);
    void freeSlotIfIdle(const SlotId slotId, const bool invalid);
    void freeBusySlot(const SlotId slotId, const bool invalid);
    void freeSlot(const SlotId slotId, const bool invalid);

    bool canAdd(const sfileno fileno, const SlotId slotId, const DbCellHeader &header) const;
    bool sameEntry(const sfileno fileno, const DbCellHeader &header) const;

    SwapDir *sd;
    LoadingEntry *entries; ///< store entries being loaded from disk

    int64_t dbSize;
    int dbSlotSize; ///< the size of a db cell, including the cell header
    int dbSlotLimit; ///< total number of db cells
    int dbEntryLimit; ///< maximum number of entries that can be stored in db

    int fd; // store db file descriptor
    int64_t dbOffset;
    sfileno loadingPos; ///< index of the db slot being loaded from disk now
    sfileno validationPos; ///< index of the loaded db slot being validated now
    MemBuf buf; ///< space to load current db slot (and entry metadata) into

    StoreRebuildData counts;

    static void Steps(void *data);

    CBDATA_CLASS2(Rebuild);
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_REBUILD_H */

