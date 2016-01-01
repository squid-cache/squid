/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"
#include "ipc/StoreMap.h"
#include "SwapDir.h"

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
    virtual ~SwapDir();

    /* public ::SwapDir API */
    virtual void reconfigure();
    virtual StoreSearch *search(String const url, HttpRequest *);
    virtual StoreEntry *get(const cache_key *key);
    virtual void get(String const, STOREGETCLIENT, void * cbdata);
    virtual void markForUnlink(StoreEntry &e);
    virtual void disconnect(StoreEntry &e);
    virtual uint64_t currentSize() const;
    virtual uint64_t currentCount() const;
    virtual bool doReportStat() const;
    virtual void swappedOut(const StoreEntry &e);
    virtual void create();
    virtual void parse(int index, char *path);

    // temporary path to the shared memory map of first slots of cached entries
    SBuf inodeMapPath() const;
    // temporary path to the shared memory stack of free slots
    const char *freeSlotsPath() const;

    int64_t entryLimitAbsolute() const { return SwapFilenMax+1; } ///< Core limit
    int64_t entryLimitActual() const; ///< max number of possible entries in db
    int64_t slotLimitAbsolute() const; ///< Rock store implementation limit
    int64_t slotLimitActual() const; ///< total number of slots in this db

    /// removes a slot from a list of free slots or returns false
    bool useFreeSlot(Ipc::Mem::PageId &pageId);
    /// whether the given slot ID may point to a slot in this db
    bool validSlotId(const SlotId slotId) const;
    /// purges one or more entries to make full() false and free some slots
    void purgeSome();

    int64_t diskOffset(Ipc::Mem::PageId &pageId) const;
    int64_t diskOffset(int filen) const;
    void writeError(StoreEntry &e);

    /* StoreMapCleaner API */
    virtual void noteFreeMapSlice(const Ipc::StoreMapSliceId fileno);

    uint64_t slotSize; ///< all db slots are of this size

protected:
    /* Store API */
    virtual bool anchorCollapsed(StoreEntry &collapsed, bool &inSync);
    virtual bool updateCollapsed(StoreEntry &collapsed);

    /* protected ::SwapDir API */
    virtual bool needsDiskStrand() const;
    virtual void init();
    virtual ConfigOption *getOptionTree() const;
    virtual bool allowOptionReconfigure(const char *const option) const;
    virtual bool canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const;
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual void maintain();
    virtual void diskFull();
    virtual void reference(StoreEntry &e);
    virtual bool dereference(StoreEntry &e, bool);
    virtual bool unlinkdUseful() const;
    virtual void unlink(StoreEntry &e);
    virtual void statfs(StoreEntry &e) const;

    /* IORequestor API */
    virtual void ioCompletedNotification();
    virtual void closeCompleted();
    virtual void readCompleted(const char *buf, int len, int errflag, RefCount< ::ReadRequest>);
    virtual void writeCompleted(int errflag, size_t len, RefCount< ::WriteRequest>);

    void parseSize(const bool reconfiguring); ///< parses anonymous cache_dir size option
    void validateOptions(); ///< warns of configuration problems; may quit
    bool parseTimeOption(char const *option, const char *value, int reconfiguring);
    void dumpTimeOption(StoreEntry * e) const;
    bool parseRateOption(char const *option, const char *value, int reconfiguring);
    void dumpRateOption(StoreEntry * e) const;
    bool parseSizeOption(char const *option, const char *value, int reconfiguring);
    void dumpSizeOption(StoreEntry * e) const;

    void rebuild(); ///< starts loading and validating stored entry metadata

    bool full() const; ///< no more entries can be stored without purging
    void trackReferences(StoreEntry &e); ///< add to replacement policy scope
    void ignoreReferences(StoreEntry &e); ///< delete from repl policy scope

    int64_t diskOffsetLimit() const;

    void anchorEntry(StoreEntry &e, const sfileno filen, const Ipc::StoreMapAnchor &anchor);
    bool updateCollapsedWith(StoreEntry &collapsed, const Ipc::StoreMapAnchor &anchor);

    friend class Rebuild;
    friend class IoState;
    const char *filePath; ///< location of cache storage file inside path/
    DirMap *map; ///< entry key/sfileno to MaxExtras/inode mapping

private:
    void createError(const char *const msg);

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
    virtual ~SwapDirRr();

protected:
    /* Ipc::Mem::RegisteredRunner API */
    virtual void create();

private:
    std::vector<SwapDir::DirMap::Owner *> mapOwners;
    std::vector< Ipc::Mem::Owner<Ipc::Mem::PageStack> *> freeSlotsOwners;
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_SWAP_DIR_H */

