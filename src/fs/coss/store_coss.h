#ifndef __COSS_H__
#define __COSS_H__

#ifndef COSS_MEMBUF_SZ
#define	COSS_MEMBUF_SZ	1048576
#endif

#define COSS_ALLOC_NOTIFY		0
#define COSS_ALLOC_ALLOCATE		1
#define COSS_ALLOC_REALLOC		2

struct _cossmembuf {
    size_t diskstart;
    size_t diskend;
    SwapDir *SD;
    int lockcount;
    char buffer[COSS_MEMBUF_SZ];
    struct _cossmembuf_flags {
	unsigned int full:1;
	unsigned int writing:1;
    } flags;
    struct _cossmembuf *next;
};


/* Per-storedir info */
struct _cossinfo {
    struct _cossmembuf *membufs;
    struct _cossmembuf *current_membuf;
    size_t current_offset;
    int fd;
    int swaplog_fd;
    int numcollisions;
};


/* Per-storeiostate info */
struct _cossstate {
    char *readbuffer;
    char *requestbuf;
    size_t requestlen;
    size_t requestoffset;
    sfileno reqdiskoffset;
    struct {
	unsigned int reading:1;
	unsigned int writing:1;
    } flags;
};

typedef struct _cossmembuf CossMemBuf;
typedef struct _cossinfo CossInfo;
typedef struct _cossstate CossState;

/* Whether the coss system has been setup or not */
extern int coss_initialised;
extern MemPool *coss_membuf_pool;
extern MemPool *coss_state_pool;


/*
 * Store IO stuff
 */
extern STOBJCREATE storeCossCreate;
extern STOBJOPEN storeCossOpen;
extern STOBJCLOSE storeCossClose;
extern STOBJREAD storeCossRead;
extern STOBJWRITE storeCossWrite;
extern STOBJUNLINK storeCossUnlink;

extern off_t storeCossAllocate(SwapDir * SD, const StoreEntry * e, int which);
extern void storeCossFree(StoreEntry * e);
extern void storeCossMaintainSwapSpace(SwapDir * SD);
extern void storeCossDirStats(SwapDir *, StoreEntry *);
extern void storeCossDirDump(StoreEntry * entry, const char *name, SwapDir * s);
extern void storeCossDirFree(SwapDir *);
extern SwapDir *storeCossDirPick(void);

void storeFsSetup_ufs(storefs_entry_t *);



#endif
