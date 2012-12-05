#ifndef SQUID_FS_ROCK_SWAP_DIR_H
#define SQUID_FS_ROCK_SWAP_DIR_H

#include "SwapDir.h"
#include "DiskIO/DiskFile.h"
#include "DiskIO/IORequestor.h"
#include "fs/rock/RockDbCell.h"
#include "ipc/StoreMap.h"
#include "ipc/mem/Page.h"
#include "ipc/mem/PageStack.h"

class DiskIOStrategy;
class ReadRequest;
class WriteRequest;

namespace Rock
{

class Rebuild;

/// \ingroup Rock
class SwapDir: public ::SwapDir, public IORequestor, public Ipc::StoreMapCleaner
{
public:
    SwapDir();
    virtual ~SwapDir();

    /* public ::SwapDir API */
    virtual void reconfigure();
    virtual StoreSearch *search(String const url, HttpRequest *);
    virtual StoreEntry *get(const cache_key *key);
    virtual void get(String const, STOREGETCLIENT, void * cbdata);
    virtual void disconnect(StoreEntry &e);
    virtual uint64_t currentSize() const;
    virtual uint64_t currentCount() const;
    virtual bool doReportStat() const;
    virtual void swappedOut(const StoreEntry &e);
    virtual void create();
    virtual void parse(int index, char *path);

    int64_t entryLimitHigh() const { return SwapFilenMax; } ///< Core limit
    int64_t entryLimitAllowed() const;

    bool popDbSlot(Ipc::Mem::PageId &pageId);
    DbCellHeader &dbSlot(const Ipc::Mem::PageId &pageId);
    const DbCellHeader &dbSlot(const Ipc::Mem::PageId &pageId) const;

    int64_t diskOffset(Ipc::Mem::PageId &pageId) const;
    void writeError(const sfileno fileno);

    virtual void cleanReadable(const sfileno fileno);

    // TODO: merge with MemStoreMapExtras?
    struct MapExtras {
        Ipc::Mem::PageId pageId;
    };
    typedef Ipc::StoreMapWithExtras<MapExtras> DirMap;

    uint64_t slotSize; ///< all db slots are of this size

protected:
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

    int64_t diskOffset(int filen) const;
    int64_t diskOffsetLimit() const;
    int entryLimit() const { return map->entryLimit(); }
    int entryMaxPayloadSize() const;
    int entriesNeeded(const int64_t objSize) const;

    friend class Rebuild;
    const char *filePath; ///< location of cache storage file inside path/

private:
    void createError(const char *const msg);

    DiskIOStrategy *io;
    RefCount<DiskFile> theFile; ///< cache storage for this cache_dir
    DirMap *map;
    DbCellHeader *dbSlots;
    Ipc::Mem::Pointer<Ipc::Mem::PageStack> dbSlotIndex;

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
    virtual void create(const RunnerRegistry &);

private:
    Vector<SwapDir::DirMap::Owner *> mapOwners;
    Vector< Ipc::Mem::Owner<Ipc::Mem::PageStack> *> dbSlotsOwners;
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_SWAP_DIR_H */
