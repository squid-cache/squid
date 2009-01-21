/*
 * $Id$
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
#ifndef SQUID_UFSCOMMON_H
#define SQUID_UFSCOMMON_H


#define DefaultLevelOneDirs	16
#define DefaultLevelTwoDirs	256
#define STORE_META_BUFSZ	4096

class UFSStrategy;
class ConfigOptionVector;
class DiskIOModule;
class StoreSearch;

#include "SwapDir.h"

/// \ingroup UFS
class UFSSwapDir : public SwapDir
{

public:
    static int IsUFSDir(SwapDir* sd);
    static int DirClean(int swap_index);
    static int FilenoBelongsHere(int fn, int F0, int F1, int F2);

    UFSSwapDir(char const *aType, const char *aModuleType);
    virtual void init();
    virtual void create();
    virtual void dump(StoreEntry &) const;
    ~UFSSwapDir();
    virtual StoreSearch *search(String const url, HttpRequest *);
    virtual bool doubleCheck(StoreEntry &);
    virtual void unlink(StoreEntry &);
    virtual void statfs(StoreEntry &)const;
    virtual void maintain();
    virtual int canStore(StoreEntry const &)const;
    virtual void reference(StoreEntry &);
    virtual void dereference(StoreEntry &);
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual void openLog();
    virtual void closeLog();
    virtual int writeCleanStart();
    virtual void writeCleanDone();
    virtual void logEntry(const StoreEntry & e, int op) const;
    virtual void parse(int index, char *path);
    virtual void reconfigure(int, char *);
    virtual int callback();
    virtual void sync();

    void unlinkFile(sfileno f);
    // move down when unlink is a virtual method
    //protected:
    UFSStrategy *IO;
    char *fullPath(sfileno, char *) const;
    /* temp */
    void closeTmpSwapLog();
    FILE *openTmpSwapLog(int *clean_flag, int *zero_flag);
    char *swapSubDir(int subdirn) const;
    int mapBitTest(sfileno filn);
    void mapBitReset(sfileno filn);
    void mapBitSet(sfileno filn);
    StoreEntry *addDiskRestore(const cache_key * key,
                               sfileno file_number,
                               uint64_t swap_file_sz,
                               time_t expires,
                               time_t timestamp,
                               time_t lastref,
                               time_t lastmod,
                               u_int32_t refcount,
                               u_int16_t flags,
                               int clean);
    int validFileno(sfileno filn, int flag) const;
    int mapBitAllocate();
    virtual ConfigOption *getOptionTree() const;

    void *fsdata;

    bool validL2(int) const;
    bool validL1(int) const;

    void replacementAdd(StoreEntry *e);
    void replacementRemove(StoreEntry *e);

protected:
    fileMap *map;
    int suggest;
    int l1;
    int l2;

private:
    void parseSizeL1L2();
    static int NumberOfUFSDirs;
    static int * UFSDirToGlobalDirMapping;
    bool pathIsDirectory(const char *path)const;
    int swaplog_fd;
    static EVH CleanEvent;
    bool verifyCacheDirs();
    void rebuild();
    int createDirectory(const char *path, int);
    void createSwapSubDirs();
    void dumpEntry(StoreEntry &) const;
    char *logFile(char const *ext = NULL)const;
    void changeIO(DiskIOModule *);
    bool optionIOParse(char const *option, const char *value, int reconfiguring);
    void optionIODump(StoreEntry * e) const;
    mutable ConfigOptionVector *currentIOOptions;
    char const *ioType;

};

#include "RefCount.h"
#include "DiskIO/IORequestor.h"

/**
 * UFS dir specific IO calls
 *
 \todo This should be whittled away.
 *     DiskIOModule should be providing the entire needed API.
 */

class DiskIOStrategy;

class DiskFile;

/// \ingroup UFS
class UFSStrategy
{

public:
    UFSStrategy (DiskIOStrategy *);
    virtual ~UFSStrategy ();
    /* Not implemented */
    UFSStrategy (UFSStrategy const &);
    UFSStrategy &operator=(UFSStrategy const &);

    virtual bool shedLoad();

    virtual int load();

    StoreIOState::Pointer createState(SwapDir *SD, StoreEntry *e, StoreIOState::STIOCB * callback, void *callback_data) const;
    /* UFS specific */
    virtual RefCount<DiskFile> newFile (char const *path);
    StoreIOState::Pointer open(SwapDir *, StoreEntry *, StoreIOState::STFNCB *,
                               StoreIOState::STIOCB *, void *);
    StoreIOState::Pointer create(SwapDir *, StoreEntry *, StoreIOState::STFNCB *,
                                 StoreIOState::STIOCB *, void *);

    virtual void unlinkFile (char const *);
    virtual void sync();

    virtual int callback();

    /** Init per-instance logic */
    virtual void init();

    /** cachemgr output on the IO instance stats */
    virtual void statfs(StoreEntry & sentry)const;

    /** The io strategy in use */
    DiskIOStrategy *io;
protected:

    friend class UFSSwapDir;
};

/** Common ufs-store-dir logic */

class ReadRequest;

/// \ingroup UFS
class UFSStoreState : public StoreIOState, public IORequestor
{

public:
    void * operator new (size_t);
    void operator delete (void *);
    UFSStoreState(SwapDir * SD, StoreEntry * anEntry, STIOCB * callback_, void *callback_data_);
    ~UFSStoreState();
    virtual void close();
    virtual void closeCompleted();
    // protected:
    virtual void ioCompletedNotification();
    virtual void readCompleted(const char *buf, int len, int errflag, RefCount<ReadRequest>);
    virtual void writeCompleted(int errflag, size_t len, RefCount<WriteRequest>);
    RefCount<DiskFile> theFile;
    bool opening;
    bool creating;
    bool closing;
    bool reading;
    bool writing;
    void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data);
    void write(char const *buf, size_t size, off_t offset, FREE * free_func);

protected:
    virtual void doCloseCallback (int errflag);

    class _queued_read
    {

    public:
        MEMPROXY_CLASS(UFSStoreState::_queued_read);
        char *buf;
        size_t size;
        off_t offset;
        STRCB *callback;
        void *callback_data;

    };

    class _queued_write
    {

    public:
        MEMPROXY_CLASS(UFSStoreState::_queued_write);
        char const *buf;
        size_t size;
        off_t offset;
        FREE *free_func;

    };

    /** \todo These should be in the IO strategy */

    struct {
        /**
         * DPW 2006-05-24
         * the write_draining flag is used to avoid recursion inside
         * the UFSStoreState::drainWriteQueue() method.
         */
        bool write_draining;
        /**
         * DPW 2006-05-24
         * The try_closing flag is set by UFSStoreState::tryClosing()
         * when UFSStoreState wants to close the file, but cannot
         * because of pending I/Os.  If set, UFSStoreState will
         * try to close again in the I/O callbacks.
         */
        bool try_closing;
    } flags;
    link_list *pending_reads;
    link_list *pending_writes;
    void queueRead(char *, size_t, off_t, STRCB *, void *);
    void queueWrite(char const *, size_t, off_t, FREE *);
    bool kickReadQueue();
    void drainWriteQueue();
    void tryClosing();
    char *read_buf;

private:
    CBDATA_CLASS(UFSStoreState);
    void openDone();
    void freePending();
    void doWrite();
};

MEMPROXY_CLASS_INLINE(UFSStoreState::_queued_read);
MEMPROXY_CLASS_INLINE(UFSStoreState::_queued_write);


#include "StoreSearch.h"

/// \ingroup UFS
class StoreSearchUFS : public StoreSearch
{

public:
    StoreSearchUFS(RefCount<UFSSwapDir> sd);
    StoreSearchUFS(StoreSearchUFS const &);
    virtual ~StoreSearchUFS();

    /** \todo Iterator API - garh, wrong place */
    /**
     * callback the client when a new StoreEntry is available
     * or an error occurs
     */
    virtual void next(void (callback)(void *cbdata), void *cbdata);

    /**
     \retval true if a new StoreEntry is immediately available
     \retval false if a new StoreEntry is NOT immediately available
     */
    virtual bool next();

    virtual bool error() const;
    virtual bool isDone() const;
    virtual StoreEntry *currentItem();

    RefCount<UFSSwapDir> sd;
    RemovalPolicyWalker *walker;

private:
    CBDATA_CLASS2(StoreSearchUFS);
    /// \bug (callback) should be hidden behind a proper human readable name
    void (callback)(void *cbdata);
    void *cbdata;
    StoreEntry * current;
    bool _done;
};


class StoreSwapLogData;

/// \ingroup UFS
class UFSSwapLogParser
{

public:
    FILE *log;
    int log_entries;
    int record_size;

    UFSSwapLogParser(FILE *fp):log(fp),log_entries(-1), record_size(0) {
    }
    virtual ~UFSSwapLogParser() {};

    static UFSSwapLogParser *GetUFSSwapLogParser(FILE *fp);

    virtual bool ReadRecord(StoreSwapLogData &swapData) = 0;
    int SwapLogEntries();
    void Close() {
        if (log) {
            fclose(log);
            log = NULL;
        }
    }
};


/// \ingroup UFS
class RebuildState : public RefCountable
{

public:
    static EVH RebuildStep;

    RebuildState(RefCount<UFSSwapDir> sd);
    ~RebuildState();

    /** \todo Iterator API - garh, wrong place */
    /**
     * callback the client when a new StoreEntry is available
     * or an error occurs
     */
    virtual void next(void (callback)(void *cbdata), void *cbdata);

    /**
     \retval true if a new StoreEntry is immediately available
     \retval false if a new StoreEntry is NOT immediately available
     */
    virtual bool next();
    virtual bool error() const;
    virtual bool isDone() const;
    virtual StoreEntry *currentItem();

    RefCount<UFSSwapDir> sd;
    int n_read;
    /*    FILE *log;*/
    UFSSwapLogParser *LogParser;
    int speed;
    int curlvl1;
    int curlvl2;

    struct {
        unsigned int need_to_validate:1;
        unsigned int clean:1;
        unsigned int init:1;
    } flags;
    int in_dir;
    int done;
    int fn;

    struct dirent *entry;
    DIR *td;
    char fullpath[SQUID_MAXPATHLEN];
    char fullfilename[SQUID_MAXPATHLEN];

    struct _store_rebuild_data counts;

private:
    CBDATA_CLASS2(RebuildState);
    void rebuildFromDirectory();
    void rebuildFromSwapLog();
    void rebuildStep();
    int getNextFile(sfileno *, int *size);
    StoreEntry *currentEntry() const;
    void currentEntry(StoreEntry *);
    StoreEntry *e;
    bool fromLog;
    bool _done;
    /// \bug (callback) should be hidden behind a proper human readable name
    void (callback)(void *cbdata);
    void *cbdata;
};

#ifdef _USE_INLINE_
#include "ufscommon.cci"
#endif

#endif /* SQUID_UFSCOMMON_H */
