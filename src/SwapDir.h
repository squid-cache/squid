/*
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */
#ifndef SQUID_SWAPDIR_H
#define SQUID_SWAPDIR_H

#include "SquidConfig.h"
#include "Store.h"
#include "StoreIOState.h"

/* forward decls */
class RemovalPolicy;
class MemStore;

/* Store dir configuration routines */
/* SwapDir *sd, char *path ( + char *opt later when the strtok mess is gone) */

class ConfigOption;

/// hides memory/disk cache distinction from callers
class StoreController : public Store
{

public:
    StoreController();
    virtual ~StoreController();
    virtual int callback();
    virtual void create();

    virtual StoreEntry * get(const cache_key *);

    virtual void get(String const, STOREGETCLIENT, void * cbdata);

    /* Store parent API */
    virtual void handleIdleEntry(StoreEntry &e);
    virtual void maybeTrimMemory(StoreEntry &e, const bool preserveSwappable);

    virtual void init();

    virtual void maintain(); /* perform regular maintenance should be private and self registered ... */

    virtual uint64_t maxSize() const;

    virtual uint64_t minSize() const;

    virtual uint64_t currentSize() const;

    virtual uint64_t currentCount() const;

    virtual int64_t maxObjectSize() const;

    virtual void getStats(StoreInfoStats &stats) const;
    virtual void stat(StoreEntry &) const;

    virtual void sync();	/* Sync the store prior to shutdown */

    virtual StoreSearch *search(String const url, HttpRequest *);

    virtual void reference(StoreEntry &);	/* Reference this object */

    virtual bool dereference(StoreEntry &, bool);	/* Unreference this object */

    /* the number of store dirs being rebuilt. */
    static int store_dirs_rebuilding;

private:
    void createOneStore(Store &aStore);
    bool keepForLocalMemoryCache(const StoreEntry &e) const;

    StorePointer swapDir; ///< summary view of all disk caches
    MemStore *memStore; ///< memory cache
};

/* migrating from the Config based list of swapdirs */
void allocate_new_swapdir(SquidConfig::_cacheSwap *);
void free_cachedir(SquidConfig::_cacheSwap * swap);
extern OBJH storeDirStats;
char *storeDirSwapLogFile(int, const char *);
char *storeSwapFullPath(int, char *);
char *storeSwapSubSubDir(int, char *);
const char *storeSwapPath(int);
int storeDirWriteCleanLogs(int reopen);
extern STDIRSELECT *storeDirSelectSwapDir;
int storeVerifySwapDirs(void);
void storeDirCloseSwapLogs(void);
void storeDirCloseTmpSwapLog(int dirn);
void storeDirDiskFull(sdirno);
void storeDirOpenSwapLogs(void);
void storeDirSwapLog(const StoreEntry *, int op);
void storeDirLRUDelete(StoreEntry *);
void storeDirLRUAdd(StoreEntry *);
int storeDirGetBlkSize(const char *path, int *blksize);
int storeDirGetUFSStats(const char *, int *, int *, int *, int *);

/// manages a single cache_dir
class SwapDir : public Store
{

public:
    typedef RefCount<SwapDir> Pointer;

    SwapDir(char const *aType);
    virtual ~SwapDir();
    virtual void reconfigure() = 0;
    char const *type() const;

    virtual bool needsDiskStrand() const; ///< needs a dedicated kid process
    virtual bool active() const; ///< may be used in this strand
    /// whether stat should be reported by this SwapDir
    virtual bool doReportStat() const { return active(); }
    /// whether SwapDir may benefit from unlinkd
    virtual bool unlinkdUseful() const = 0;

    /* official Store interface functions */
    virtual void diskFull();

    virtual StoreEntry * get(const cache_key *);

    virtual void get(String const, STOREGETCLIENT, void * cbdata);

    virtual uint64_t maxSize() const { return max_size;}

    virtual uint64_t minSize() const;

    /// The maximum size of object which may be stored here.
    /// Larger objects will not be added and may be purged.
    virtual int64_t maxObjectSize() const;

    /// configure the maximum object size for this storage area.
    /// May be any size up to the total storage area.
    void maxObjectSize(int64_t newMax);

    virtual void getStats(StoreInfoStats &stats) const;
    virtual void stat (StoreEntry &anEntry) const;
    virtual StoreSearch *search(String const url, HttpRequest *) = 0;

    /* migrated from store_dir.cc */
    bool objectSizeIsAcceptable(int64_t objsize) const;

    /// called when the entry is about to forget its association with cache_dir
    virtual void disconnect(StoreEntry &) {}

    /// called when entry swap out is complete
    virtual void swappedOut(const StoreEntry &e) = 0;

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
    int index;			/* This entry's index into the swapDirs array */
    int disker; ///< disker kid id dedicated to this SwapDir or -1
    RemovalPolicy *repl;
    int removals;
    int scanned;

    struct Flags {
        Flags() : selected(0), read_only(0) {}
        unsigned int selected:1;
        unsigned int read_only:1;
    } flags;
    virtual void init() = 0;	/* Initialise the fs */
    virtual void create();	/* Create a new fs */
    virtual void dump(StoreEntry &)const;	/* Dump fs config snippet */
    virtual bool doubleCheck(StoreEntry &);	/* Double check the obj integrity */
    virtual void statfs(StoreEntry &) const;	/* Dump fs statistics */
    virtual void maintain();	/* Replacement maintainence */
    /// check whether we can store the entry; if we can, report current load
    virtual bool canStore(const StoreEntry &e, int64_t diskSpaceNeeded, int &load) const = 0;
    /* These two are notifications */
    virtual void reference(StoreEntry &);	/* Reference this object */
    virtual bool dereference(StoreEntry &, bool);	/* Unreference this object */
    virtual int callback();	/* Handle pending callbacks */
    virtual void sync();	/* Sync the store prior to shutdown */
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *) = 0;
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *) = 0;
    virtual void unlink (StoreEntry &);
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

#endif /* SQUID_SWAPDIR_H */
