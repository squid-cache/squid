/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_STORE_DISK_H
#define SQUID_STORE_DISK_H

#include "store/Controlled.h"
#include "StoreIOState.h"

class ConfigOption;
class RemovalPolicy;

namespace Store {

/// manages a single cache_dir
class Disk: public Controlled
{

public:
    typedef RefCount<Disk> Pointer;

    explicit Disk(char const *aType);
    virtual ~Disk();
    virtual void reconfigure() = 0;
    char const *type() const;

    virtual bool needsDiskStrand() const; ///< needs a dedicated kid process
    virtual bool active() const; ///< may be used in this strand
    /// whether stat should be reported by this SwapDir
    virtual bool doReportStat() const { return active(); }
    /// whether SwapDir may benefit from unlinkd
    virtual bool unlinkdUseful() const = 0;

    /**
     * Notify this disk that it is full.
     * XXX move into a protected api call between store files and their stores, rather than a top level api call
     */
    virtual void diskFull();

    /* Controlled API */
    virtual void create() override;
    virtual StoreEntry *get(const cache_key *) override;
    virtual uint64_t maxSize() const override { return max_size; }
    virtual uint64_t minSize() const override;
    virtual int64_t maxObjectSize() const override;
    virtual void getStats(StoreInfoStats &stats) const override;
    virtual void stat(StoreEntry &) const override;
    virtual void reference(StoreEntry &e) override;
    virtual bool dereference(StoreEntry &e) override;
    virtual void maintain() override;
    /// whether this disk storage is capable of serving multiple workers
    virtual bool smpAware() const = 0;

    /// the size of the smallest entry this cache_dir can store
    int64_t minObjectSize() const;

    /// configure the maximum object size for this storage area.
    /// May be any size up to the total storage area.
    void maxObjectSize(int64_t newMax);

    /// whether we can store an object of the given size
    /// negative objSize means the object size is currently unknown
    bool objectSizeIsAcceptable(int64_t objSize) const;

    /// called when the entry is about to forget its association with cache_dir
    virtual void disconnect(StoreEntry &) {}

    /// finalize the successful swapout that has been already noticed by Store
    virtual void finalizeSwapoutSuccess(const StoreEntry &) = 0;
    /// abort the failed swapout that has been already noticed by Store
    virtual void finalizeSwapoutFailure(StoreEntry &) = 0;

    /// whether this cache dir has an entry with `e.key`
    virtual bool hasReadableEntry(const StoreEntry &e) const = 0;

protected:
    void parseOptions(int reconfiguring);
    void dumpOptions(StoreEntry * e) const;
    virtual ConfigOption *getOptionTree() const;
    virtual bool allowOptionReconfigure(const char *const) const { return true; }

    int64_t sizeInBlocks(const int64_t size) const { return (size + fs.blksize - 1) / fs.blksize; }

private:
    bool optionReadOnlyParse(char const *option, const char *value, int reconfiguring);
    void optionReadOnlyDump(StoreEntry * e) const;
    bool optionObjectSizeParse(char const *option, const char *value, int reconfiguring);
    void optionObjectSizeDump(StoreEntry * e) const;
    char const *theType;

protected:
    uint64_t max_size;        ///< maximum allocatable size of the storage area
    int64_t min_objsize;      ///< minimum size of any object stored here (-1 for no limit)
    int64_t max_objsize;      ///< maximum size of any object stored here (-1 for no limit)

public:
    char *path;
    int index;          /* This entry's index into the swapDirs array */
    int disker; ///< disker kid id dedicated to this SwapDir or -1
    RemovalPolicy *repl;
    int removals;
    int scanned;

    struct Flags {
        Flags() : selected(false), read_only(false) {}
        bool selected;
        bool read_only;
    } flags;

    virtual void dump(StoreEntry &)const;   /* Dump fs config snippet */
    virtual bool doubleCheck(StoreEntry &); /* Double check the obj integrity */
    virtual void statfs(StoreEntry &) const;    /* Dump fs statistics */

    /// check whether we can store the entry; if we can, report current load
    virtual bool canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const = 0;

    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *) = 0;
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *) = 0;

    bool canLog(StoreEntry const &e)const;
    virtual void openLog();
    virtual void closeLog();
    virtual void logEntry(const StoreEntry & e, int op) const;

    class CleanLog
    {

    public:
        virtual ~CleanLog() {}

        virtual const StoreEntry *nextEntry() = 0;
        virtual void write(StoreEntry const &) = 0;
    };

    CleanLog *cleanLog;
    virtual int writeCleanStart();
    virtual void writeCleanDone();
    virtual void parse(int index, char *path) = 0;

    struct {
        int blksize;
    } fs;
};

} // namespace Store

#endif /* SQUID_STORE_DISK_H */

