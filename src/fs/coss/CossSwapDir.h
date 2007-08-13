#ifndef __COSSSWAPDIR_H__
#define __COSSSWAPDIR_H__

#include "SwapDir.h"
#include "StoreSearch.h"

#ifndef COSS_MEMBUF_SZ
#define	COSS_MEMBUF_SZ	1048576
#endif

/* Note that swap_filen in sio/e are actually disk offsets too! */

/* What we're doing in storeCossAllocate() */
#define COSS_ALLOC_ALLOCATE		1
#define COSS_ALLOC_REALLOC		2

class CossSwapDir;


class CossMemBuf;

class DiskIOStrategy;

class DiskIOModule;

class ConfigOptionVector;
#include "DiskIO/DiskFile.h"
#include "DiskIO/IORequestor.h"

class CossSwapDir : public SwapDir, public IORequestor
{

public:
    CossSwapDir();
    virtual void init();
    virtual void create();
    virtual void dump(StoreEntry &)const;
    ~CossSwapDir();
    virtual StoreSearch *search(String const url, HttpRequest *);
    virtual void unlink (StoreEntry &);
    virtual void statfs (StoreEntry &)const;
    virtual int canStore(StoreEntry const &)const;
    virtual int callback();
    virtual void sync();
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, StoreIOState::STFNCB *, StoreIOState::STIOCB *, void *);
    virtual void openLog();
    virtual void closeLog();
    virtual int writeCleanStart();
    virtual void writeCleanDone();
    virtual void logEntry(const StoreEntry & e, int op) const;
    virtual void parse (int index, char *path);
    virtual void reconfigure (int, char *);
    /* internals */
    virtual off_t storeCossFilenoToDiskOffset(sfileno);
    virtual sfileno storeCossDiskOffsetToFileno(off_t);
    virtual CossMemBuf *storeCossFilenoToMembuf(sfileno f);
    /* IORequestor routines */
    virtual void ioCompletedNotification();
    virtual void closeCompleted();
    virtual void readCompleted(const char *buf, int len, int errflag, RefCount<ReadRequest>);
    virtual void writeCompleted(int errflag, size_t len, RefCount<WriteRequest>);
    //private:
    int swaplog_fd;
    int count;
    dlink_list membufs;

    CossMemBuf *current_membuf;
    off_t current_offset;	/* in Blocks */
    int numcollisions;
    dlink_list cossindex;
    unsigned int blksz_bits;
    unsigned int blksz_mask;  /* just 1<<blksz_bits - 1*/
    DiskIOStrategy *io;
    RefCount<DiskFile> theFile;
    char *storeCossMemPointerFromDiskOffset(off_t offset, CossMemBuf ** mb);
    void storeCossMemBufUnlock(StoreIOState::Pointer);
    CossMemBuf *createMemBuf(off_t start, sfileno curfn, int *collision);
    sfileno allocate(const StoreEntry * e, int which);
    void startMembuf();

private:
    void changeIO(DiskIOModule *module);
    bool optionIOParse(char const *option, const char *value, int reconfiguring);
    void optionIODump(StoreEntry * e) const;
    void optionBlockSizeDump(StoreEntry *) const;
    bool optionBlockSizeParse(const char *, const char *, int);
    char const *stripePath() const;
    ConfigOption * getOptionTree() const;
    const char *ioModule;
    mutable ConfigOptionVector *currentIOOptions;
    const char *stripe_path;
};

extern void storeCossAdd(CossSwapDir *, StoreEntry *);
extern void storeCossRemove(CossSwapDir *, StoreEntry *);
extern void storeCossStartMembuf(CossSwapDir * SD);

class StoreSearchCoss : public StoreSearch
{

public:
    StoreSearchCoss(RefCount<CossSwapDir> sd);
    StoreSearchCoss(StoreSearchCoss const &);
    ~StoreSearchCoss();
    /* Iterator API - garh, wrong place */
    /* callback the client when a new StoreEntry is available
     * or an error occurs 
     */
    virtual void next(void (callback)(void *cbdata), void *cbdata);
    /* return true if a new StoreEntry is immediately available */
    virtual bool next();
    virtual bool error() const;
    virtual bool isDone() const;
    virtual StoreEntry *currentItem();

private:
    CBDATA_CLASS2(StoreSearchCoss);
    RefCount<CossSwapDir> sd;
    void (*callback)(void *cbdata);
    void *cbdata;
    bool _done;
    dlink_node * current;
    dlink_node * next_;
};

#endif
