/*
 * store_diskd.h
 *
 * Internal declarations for the diskd routines
 */

#ifndef __STORE_DISKD_H__
#define __STORE_DISKD_H__

/*
 * MAGIC2 is the point at which we start blocking on msgsnd/msgrcv.
 * If a queue has MAGIC2 (or more) messages away, then we read the
 * queue until the level falls below MAGIC2.  Recommended value
 * is 75% of SHMBUFS. MAGIC1 is the number of messages away which we
 * stop allowing open/create for.
 */

struct _diskdinfo_t {
    int swaplog_fd;
    int l1;
    int l2;
    fileMap *map;
    int suggest;
    int smsgid;
    int rmsgid;
    int wfd;
    int away;
    struct {
	char *buf;
	link_list *stack;
	int id;
    } shm;
    int magic1;
    int magic2;
};

struct _diskdstate_t {
    int id;
    struct {
	unsigned int close_request:1;
	unsigned int reading:1;
	unsigned int writing:1;
    } flags;
    char *read_buf;
};

enum {
    _MQD_NOP,
    _MQD_OPEN,
    _MQD_CLOSE,
    _MQD_READ,
    _MQD_WRITE,
    _MQD_UNLINK
};

typedef struct _diomsg {
    mtyp_t mtype;
    int id;
    int seq_no;
    void *callback_data;
    int size;
    int offset;
    int status;
    int shm_offset;
} diomsg;

struct _diskd_stats {
    int open_fail_queue_len;
    int block_queue_len;
    int max_away;
    int max_shmuse;
    int shmbuf_count;
    int sent_count;
    int recv_count;
    int sio_id;
};

typedef struct _diskd_stats diskd_stats_t;
typedef struct _diskdinfo_t diskdinfo_t;
typedef struct _diskdstate_t diskdstate_t;

static const int msg_snd_rcv_sz = sizeof(diomsg) - sizeof(mtyp_t);

/* The diskd_state memory pool */
extern MemPool *diskd_state_pool;

extern void storeDiskdDirMapBitReset(SwapDir *, sfileno);
extern int storeDiskdDirMapBitAllocate(SwapDir *);
extern char *storeDiskdDirFullPath(SwapDir * SD, sfileno filn, char *fullpath);
extern void storeDiskdDirUnlinkFile(SwapDir *, sfileno);
extern void storeDiskdDirReplAdd(SwapDir *, StoreEntry *);
extern void storeDiskdDirReplRemove(StoreEntry *);
extern void storeDiskdShmPut(SwapDir *, int);
extern void *storeDiskdShmGet(SwapDir *, int *);
extern void storeDiskdHandle(diomsg * M);


/*
 * Store IO stuff
 */
extern STOBJCREATE storeDiskdCreate;
extern STOBJOPEN storeDiskdOpen;
extern STOBJCLOSE storeDiskdClose;
extern STOBJREAD storeDiskdRead;
extern STOBJWRITE storeDiskdWrite;
extern STOBJUNLINK storeDiskdUnlink;

/*
 * SHMBUFS is the number of shared memory buffers to allocate for
 * Each SwapDir.
 */
#define SHMBUFS 96
#define SHMBUF_BLKSZ SM_PAGE_SIZE
/*
 * MAGIC2 is the point at which we start blocking on msgsnd/msgrcv.
 * If a queue has MAGIC2 (or more) messages away, then we read the
 * queue until the level falls below MAGIC2.  Recommended value
 * is 75% of SHMBUFS.
 */
#define MAGIC1 Config.diskd.magic1
#define MAGIC2 Config.diskd.magic2


extern diskd_stats_t diskd_stats;

#endif
