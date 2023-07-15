/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FS_ROCK_SWAP_DIR_H
#define SQUID_FS_ROCK_SWAP_DIR_H

#include "DiskIO/DiskFile.h"
#include "DiskIO/IORequestor.h"
#include "fs/rock/forward.h"
#include "fs/rock/RockDbCell.h"
#include "fs/rock/RockRebuild.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"
#include "ipc/StoreMap.h"
#include "store/Disk.h"
#include "store_rebuild.h"
#include <vector>

class DiskIOStrategy;
class ReadRequest;
class WriteRequest;

namespace Rock
{

/// \ingroup Rock
class SwapDir: public ::SwapDir, public IORequestor, public Ipc::StoreMapCleaner
{
public:
    typedef RefCount<SwapDir> Pointer;
    typedef Ipc::StoreMap DirMap;

    SwapDir();
    ~SwapDir() override;

    /* public ::SwapDir API */
    void reconfigure() override;
    StoreEntry *get(const cache_key *key) override;
    void evictCached(StoreEntry &) override;
    void evictIfFound(const cache_key *) override;
    void disconnect(StoreEntry &e) override;
    uint64_t currentSize() const override;
    uint64_t currentCount() const override;
    bool doReportStat() const override;
    void finalizeSwapoutSuccess(const StoreEntry &) override;
    void finalizeSwapoutFailure(StoreEntry &) override;
    void create() override;
    void parse(int index, char *path) override;
    bool smpAware() const override { return true; }
    bool hasReadableEntry(const StoreEntry &) const override;

    // temporary path to the shared memory map of first slots of cached entries
    SBuf inodeMapPath() const;
    // temporary path to the shared memory stack of free slots
    const char *freeSlotsPath() const;

    int64_t entryLimitAbsolute() const { return SwapFilenMax+1; } ///< Core limit
    int64_t entryLimitActual() const; ///< max number of possible entries in db
    int64_t slotLimitAbsolute() const; ///< Rock store implementation limit
    int64_t slotLimitActual() const; ///< total number of slots in this db

    /// whether the given slot ID may point to a slot in this db
    bool validSlotId(const SlotId slotId) const;

    /// finds and returns a free db slot to fill or throws
    SlotId reserveSlotForWriting();

    /// purges one or more entries to make full() false and free some slots
    void purgeSome();

    int64_t diskOffset(Ipc::Mem::PageId &pageId) const;
    int64_t diskOffset(int filen) const;
    void writeError(StoreIOState &sio);

    /* StoreMapCleaner API */
    void noteFreeMapSlice(const Ipc::StoreMapSliceId fileno) override;

    uint64_t slotSize; ///< all db slots are of this size

protected:
    /* Store API */
    bool anchorToCache(StoreEntry &) override;
    bool updateAnchored(StoreEntry &) override;

    /* protected ::SwapDir API */
    bool needsDiskStrand() const override;
    void init() override;
    ConfigOption *getOptionTree() const override;
    bool allowOptionReconfigure(const char *const option) const override;
    bool canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const override;
    StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STIOCB *, void *) override;
    StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STIOCB *, void *) override;
    void maintain() override;
    void diskFull() override;
    void reference(StoreEntry &e) override;
    bool dereference(StoreEntry &e) override;
    void updateHeaders(StoreEntry *e) override;
    bool unlinkdUseful() const override;
    void statfs(StoreEntry &e) const override;

    /* IORequestor API */
    void ioCompletedNotification() override;
    void closeCompleted() override;
    void readCompleted(const char *buf, int len, int errflag, RefCount< ::ReadRequest>) override;
    void writeCompleted(int errflag, size_t len, RefCount< ::WriteRequest>) override;

    void parseSize(const bool reconfiguring); ///< parses anonymous cache_dir size option
    void validateOptions(); ///< warns of configuration problems; may quit
    bool parseTimeOption(char const *option, const char *value, int reconfiguring);
    void dumpTimeOption(StoreEntry * e) const;
    bool parseRateOption(char const *option, const char *value, int reconfiguring);
    void dumpRateOption(StoreEntry * e) const;
    bool parseSizeOption(char const *option, const char *value, int reconfiguring);
    void dumpSizeOption(StoreEntry * e) const;

    bool full() const; ///< no more entries can be stored without purging
    void trackReferences(StoreEntry &e); ///< add to replacement policy scope
    void ignoreReferences(StoreEntry &e); ///< delete from repl policy scope

    int64_t diskOffsetLimit() const;

    void updateHeadersOrThrow(Ipc::StoreMapUpdate &update);
    StoreIOState::Pointer createUpdateIO(const Ipc::StoreMapUpdate &, StoreIOState::STIOCB *, void *);

    void anchorEntry(StoreEntry &e, const sfileno filen, const Ipc::StoreMapAnchor &anchor);

    friend class Rebuild;
    friend class IoState;
    friend class HeaderUpdater;
    const char *filePath; ///< location of cache storage file inside path/
    DirMap *map; ///< entry key/sfileno to MaxExtras/inode mapping

private:
    void createError(const char *const msg);
    void handleWriteCompletionSuccess(const WriteRequest &request);
    void handleWriteCompletionProblem(const int errflag, const WriteRequest &request);

    DiskIOStrategy *io;
    RefCount<DiskFile> theFile; ///< cache storage for this cache_dir
    Ipc::Mem::Pointer<Ipc::Mem::PageStack> freeSlots; ///< all unused slots
    Ipc::Mem::PageId *waitingForPage; ///< one-page cache for a "hot" free slot

    /* configurable options */
    DiskFile::Config fileConfig; ///< file-level configuration options

    static const int64_t HeaderSize; ///< on-disk db header size
};

/// initializes shared memory segments used by Rock::SwapDir
class SwapDirRr: public Ipc::Mem::RegisteredRunner
{
public:
    /* ::RegisteredRunner API */
    ~SwapDirRr() override;

protected:
    /* Ipc::Mem::RegisteredRunner API */
    void create() override;

private:
    std::vector<Ipc::Mem::Owner<Rebuild::Stats> *> rebuildStatsOwners;
    std::vector<SwapDir::DirMap::Owner *> mapOwners;
    std::vector< Ipc::Mem::Owner<Ipc::Mem::PageStack> *> freeSlotsOwners;
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_SWAP_DIR_H */

