#ifndef __COSS_H__
#define __COSS_H__

#include "SwapDir.h"

#ifndef COSS_MEMBUF_SZ
#define	COSS_MEMBUF_SZ	1048576
#endif

#ifndef	COSS_BLOCK_SZ
#define	COSS_BLOCK_SZ	512
#endif

/* Macros to help block<->offset transiting */
#define	COSS_OFS_TO_BLK(ofs)		((ofs) / COSS_BLOCK_SZ)
#define	COSS_BLK_TO_OFS(ofs)		((ofs) * COSS_BLOCK_SZ)

/* Note that swap_filen in sio/e are actually disk offsets too! */

/* What we're doing in storeCossAllocate() */
#define COSS_ALLOC_NOTIFY		0
#define COSS_ALLOC_ALLOCATE		1
#define COSS_ALLOC_REALLOC		2

class CossSwapDir;

struct _cossmembuf
{
    dlink_node node;
    size_t diskstart;		/* in blocks */
    size_t diskend;		/* in blocks */
    CossSwapDir *SD;
    int lockcount;
    char buffer[COSS_MEMBUF_SZ];

    struct _cossmembuf_flags
    {

unsigned int full:
        1;

unsigned int writing:
        1;
    }

    flags;
};

struct _cossindex
{
    /* Note: the dlink_node MUST be the first member of the structure.
     * This member is later pointer typecasted to coss_index_node *.
     */
    dlink_node node;
};



/* Per-storeiostate info */

class CossState : public storeIOState
{

public:
    virtual void deleteSelf() const {delete this;}

    void * operator new (size_t);
    void operator delete (void *);
    CossState(CossSwapDir *);
    ~CossState();

    char *readbuffer;
    char *requestbuf;
    size_t requestlen;
    size_t requestoffset;	/* in blocks */
    sfileno reqdiskoffset;	/* in blocks */

    struct
    {

unsigned int reading:
        1;

unsigned int writing:
        1;
    }

    flags;
    size_t st_size;
    void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data);
    void write(char const *buf, size_t size, off_t offset, FREE * free_func);
    void close();

    CossSwapDir *SD;

private:
    static MemPool *Pool;
};

typedef struct _cossmembuf CossMemBuf;

typedef struct _cossindex CossIndexNode;

/* Whether the coss system has been setup or not */
extern int coss_initialised;
extern MemPool *coss_membuf_pool;
extern MemPool *coss_index_pool;

class CossSwapDir : public SwapDir
{

public:
    CossSwapDir();
    virtual void init();
    virtual void newFileSystem();
    virtual void dump(StoreEntry &)const;
    ~CossSwapDir();
    virtual void unlink (StoreEntry &);
    virtual void statfs (StoreEntry &)const;
    virtual int canStore(StoreEntry const &)const;
    virtual int callback();
    virtual void sync();
    virtual StoreIOState::Pointer createStoreIO(StoreEntry &, STFNCB *, STIOCB *, void *);
    virtual StoreIOState::Pointer openStoreIO(StoreEntry &, STFNCB *, STIOCB *, void *);
    virtual void openLog();
    virtual void closeLog();
    virtual int writeCleanStart();
    virtual void writeCleanDone();
    virtual void logEntry(const StoreEntry & e, int op) const;
    virtual void parse (int index, char *path);
    virtual void reconfigure (int, char *);
    //private:
    int fd;
    int swaplog_fd;
    int count;
    dlink_list membufs;

    struct _cossmembuf *current_membuf;
    size_t current_offset;	/* in Blocks */
    int numcollisions;
    dlink_list cossindex;
    async_queue_t aq;
};

extern off_t storeCossAllocate(CossSwapDir * SD, const StoreEntry * e, int which);
extern void storeCossAdd(CossSwapDir *, StoreEntry *);
extern void storeCossRemove(CossSwapDir *, StoreEntry *);
extern void storeCossStartMembuf(CossSwapDir * SD);
#endif
