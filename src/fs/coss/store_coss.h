#ifndef __COSS_H__
#define __COSS_H__

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

struct _cossmembuf {
    dlink_node node;
    size_t diskstart;		/* in blocks */
    size_t diskend;		/* in blocks */
    SwapDir *SD;
    int lockcount;
    char buffer[COSS_MEMBUF_SZ];
    struct _cossmembuf_flags {
	unsigned int full:1;
	unsigned int writing:1;
    } flags;
};


/* Per-storedir info */
struct _cossinfo {
    dlink_list membufs;
    struct _cossmembuf *current_membuf;
    size_t current_offset;	/* in Blocks */
    int fd;
    int swaplog_fd;
    int numcollisions;
    dlink_list index;
    int count;
    async_queue_t aq;
    dlink_node *walk_current;
};

struct _cossindex {
    /* Note: the dlink_node MUST be the first member of the structure.
     * This member is later pointer typecasted to coss_index_node *.
     */
    dlink_node node;
};


/* Per-storeiostate info */
struct _cossstate {
    char *readbuffer;
    char *requestbuf;
    size_t requestlen;
    size_t requestoffset;	/* in blocks */
    sfileno reqdiskoffset;	/* in blocks */
    struct {
	unsigned int reading:1;
	unsigned int writing:1;
    } flags;
};

typedef struct _cossmembuf CossMemBuf;
typedef struct _cossinfo CossInfo;
typedef struct _cossstate CossState;
typedef struct _cossindex CossIndexNode;

/* Whether the coss system has been setup or not */
extern int coss_initialised;
extern MemPool *coss_membuf_pool;
extern MemPool *coss_state_pool;
extern MemPool *coss_index_pool;

/*
 * Store IO stuff
 */
extern STOBJCREATE storeCossCreate;
extern STOBJOPEN storeCossOpen;
extern STOBJCLOSE storeCossClose;
extern STOBJREAD storeCossRead;
extern STOBJWRITE storeCossWrite;
extern STOBJUNLINK storeCossUnlink;
extern STSYNC storeCossSync;

extern off_t storeCossAllocate(SwapDir * SD, const StoreEntry * e, int which);
extern void storeCossAdd(SwapDir *, StoreEntry *);
extern void storeCossRemove(SwapDir *, StoreEntry *);
extern void storeCossStartMembuf(SwapDir * SD);

#endif
