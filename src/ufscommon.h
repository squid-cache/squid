
/*
 * $Id: ufscommon.h,v 1.4 2003/01/23 20:59:10 robertc Exp $
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

#include "squid.h"

#define DefaultLevelOneDirs     16
#define DefaultLevelTwoDirs     256
#define STORE_META_BUFSZ 4096

/* Common UFS routines */
FREE storeSwapLogDataFree;
#include "SwapDir.h"

class UFSStrategy;

class UFSSwapDir : public SwapDir {
public:
  static int IsUFSDir(SwapDir* sd);
  static int DirClean(int swap_index);
  static int FilenoBelongsHere(int fn, int F0, int F1, int F2);

  UFSSwapDir();
  virtual void init();
  virtual void newFileSystem();
  virtual void dump(StoreEntry &) const;
  ~UFSSwapDir();
  virtual bool doubleCheck(StoreEntry &);
  virtual void unlink(StoreEntry &) = 0;
  virtual void statfs(StoreEntry &)const;
  virtual void maintainfs();
  virtual int canStore(StoreEntry const &)const = 0;
  virtual void reference(StoreEntry &);
  virtual void dereference(StoreEntry &);
  virtual StoreIOState::Pointer createStoreIO(StoreEntry &, STFNCB *, STIOCB *, void *);
  virtual StoreIOState::Pointer openStoreIO(StoreEntry &, STFNCB *, STIOCB *, void *);
  virtual void openLog();
  virtual void closeLog();
  virtual int writeCleanStart();
  virtual void writeCleanDone();
  virtual void logEntry(const StoreEntry & e, int op) const;
  virtual void parse(int index, char *path);
  virtual void reconfigure(int, char *);

  void unlinkFile(sfileno f);
  virtual void unlinkFile (char const *) = 0;
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
    size_t swap_file_sz,
    time_t expires,
    time_t timestamp,
    time_t lastref,
    time_t lastmod,
    u_int32_t refcount,
    u_int16_t flags,
    int clean);
  int validFileno(sfileno filn, int flag) const;
  int mapBitAllocate();
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
    static int NumberOfUFSDirs;
    static int * UFSDirToGlobalDirMapping;
    bool pathIsDirectory(const char *path)const;
    int swaplog_fd;
  static EVH CleanEvent;
  void initBitmap();
  bool verifyCacheDirs();
  void rebuild();
  int createDirectory(const char *path, int);
  void createSwapSubDirs();
  void dumpEntry(StoreEntry &) const;
  char *logFile(char const *ext = NULL)const;

};

#include "RefCount.h"

class IORequestor : public RefCountable{
  public:
    typedef RefCount<IORequestor> Pointer;
    virtual void ioCompletedNotification() = 0;
    virtual void closeCompleted() = 0;
    virtual void readCompleted(const char *buf, int len, int errflag) = 0;
    virtual void writeCompleted(int errflag, size_t len) = 0;
};

class DiskFile : public RefCountable {
  public:
    typedef RefCount<DiskFile> Pointer;
    virtual void deleteSelf() const = 0;
    virtual void open (int, mode_t, IORequestor::Pointer) = 0;
    virtual void create (int, mode_t, IORequestor::Pointer) = 0;
    virtual void read(char *, off_t, size_t) = 0;
    virtual void write(char const *buf, size_t size, off_t offset, FREE *free_func) = 0;
    virtual bool canRead() const = 0;
    virtual bool canWrite() const {return true;}
    /* During miogration only */
    virtual int getFD() const {return -1;}
    virtual bool error() const = 0;
};

/* UFS dir specific IO calls */
class UFSStrategy
{
public:
  virtual bool shedLoad() = 0;
  virtual void deleteSelf() const = 0;
  virtual void openFailed(){}
  virtual int load(){return -1;}
  virtual StoreIOState::Pointer createState(SwapDir *, StoreEntry *, STIOCB *, void *)const = 0;
  /* UFS specific */
  virtual DiskFile::Pointer newFile (char const *path) = 0;
  StoreIOState::Pointer open(SwapDir *, StoreEntry *, STFNCB *,
    STIOCB *, void *);
  StoreIOState::Pointer create(SwapDir *, StoreEntry *, STFNCB *,
    STIOCB *, void *);
  /* virtual void strategyStats(StoreEntry *sentry) const = 0; */
  /* virtual void dumpCacheDirParams(StoreEntry * e, const char *option) const = 0; */
};

/* Common ufs-store-dir logic */
class UFSStoreState : public storeIOState, public IORequestor {
  public:
    virtual void deleteSelf() const = 0;
    UFSStoreState();
    ~UFSStoreState();
// protected:
    DiskFile::Pointer theFile;
    bool opening;
    bool creating;
    bool closing;
    bool reading;
    bool writing;
    void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data);
    void write(char const *buf, size_t size, off_t offset, FREE * free_func);
  protected:
    class _queued_read {
      public:
	void *operator new(size_t);
	void operator delete (void *);
	char *buf;
	size_t size;
	off_t offset;
	STRCB *callback;
	void *callback_data;
      private:
	static MemPool *Pool;
    };
    class _queued_write {
      public:
	void *operator new(size_t);
	void operator delete (void *);
	char const *buf;
	size_t size;
	off_t offset;
	FREE *free_func;
      private:
	static MemPool *Pool;
    };
    link_list *pending_reads;
    link_list *pending_writes;
    void queueRead(char *, size_t, off_t, STRCB *, void *);
    void queueWrite(char const *, size_t, off_t, FREE *);
    bool kickReadQueue();
    bool kickWriteQueue();
    char *read_buf;
};

class RebuildState : public RefCountable {
public:
    void *operator new(size_t);
    void operator delete(void *);
    void deleteSelf() const;
    static EVH RebuildFromDirectory;
    static EVH RebuildFromSwapLog;

    _SQUID_INLINE_ RebuildState();
    ~RebuildState();
    UFSSwapDir *sd;
    int n_read;
    FILE *log;
    int speed;
    int curlvl1;
    int curlvl2;
    struct {
	unsigned int need_to_validate:1;
	unsigned int clean:1;
	unsigned int init:1;
    } flags;
    int done;
    int in_dir;
    int fn;
    struct dirent *entry;
    DIR *td;
    char fullpath[SQUID_MAXPATHLEN];
    char fullfilename[SQUID_MAXPATHLEN];
    struct _store_rebuild_data counts;
private:
    CBDATA_CLASS(RebuildState);
    void rebuildFromDirectory();
    void rebuildFromSwapLog();
    int getNextFile(sfileno *, int *size);
    StoreEntry *currentEntry() const;
    void currentEntry(StoreEntry *);
    StoreEntry *e;
};

#ifdef _USE_INLINE_
#include "ufscommon.cci"
#endif

#endif /* SQUID_UFSCOMMON_H */
