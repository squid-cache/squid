/*
 * store_aufs.h
 *
 * Internal declarations for the aufs routines
 */

#ifndef __STORE_ASYNCUFS_H__
#define __STORE_ASYNCUFS_H__

#ifdef ASYNC_IO_THREADS
#define NUMTHREADS ASYNC_IO_THREADS
#else
#define NUMTHREADS 16
#endif

#define MAGIC1 (NUMTHREADS/Config.cacheSwap.n_configured/2)

struct _aio_result_t {
    int aio_return;
    int aio_errno;
};

typedef struct _aio_result_t aio_result_t;

typedef void AIOCB(int fd, void *, int aio_return, int aio_errno);

int aio_cancel(aio_result_t *);
int aio_open(const char *, int, mode_t, aio_result_t *);
int aio_read(int, char *, int, off_t, int, aio_result_t *);
int aio_write(int, char *, int, off_t, int, aio_result_t *);
int aio_close(int, aio_result_t *);
int aio_stat(const char *, struct stat *, aio_result_t *);
int aio_unlink(const char *, aio_result_t *);
int aio_opendir(const char *, aio_result_t *);
aio_result_t *aio_poll_done(void);
int aio_operations_pending(void);
int aio_overloaded(void);
int aio_sync(void);
int aio_get_queue_len(void);

void aioInit(void);
void aioDone(void);
void aioCancel(int);
void aioOpen(const char *, int, mode_t, AIOCB *, void *);
void aioClose(int);
void aioWrite(int, int offset, char *, int size, AIOCB *, void *, FREE *);
void aioRead(int, int offset, char *, int size, AIOCB *, void *);
void aioStat(char *, struct stat *, AIOCB *, void *);
void aioUnlink(const char *, AIOCB *, void *);
void aioCheckCallbacks(SwapDir *);
void aioSync(SwapDir *);
int aioQueueSize(void);

struct _aioinfo_t {
    int swaplog_fd;
    int l1;
    int l2;
    fileMap *map;
    int suggest;
};

struct _aiostate_t {
    int fd;
    struct {
	unsigned int close_request:1;
	unsigned int reading:1;
	unsigned int writing:1;
	unsigned int opening:1;
    } flags;
    const char *read_buf;
    link_list *pending_writes;
    link_list *pending_reads;
};

typedef struct _aioinfo_t aioinfo_t;
typedef struct _aiostate_t aiostate_t;

/* The aio_state memory pool */
extern MemPool *aio_state_pool;

extern void storeAufsDirMapBitReset(SwapDir *, sfileno);
extern int storeAufsDirMapBitAllocate(SwapDir *);

extern char *storeAufsDirFullPath(SwapDir * SD, sfileno filn, char *fullpath);
extern void storeAufsDirUnlinkFile(SwapDir *, sfileno);
extern void storeAufsDirReplAdd(SwapDir * SD, StoreEntry *);
extern void storeAufsDirReplRemove(StoreEntry *);

/*
 * Store IO stuff
 */
extern STOBJCREATE storeAufsCreate;
extern STOBJOPEN storeAufsOpen;
extern STOBJCLOSE storeAufsClose;
extern STOBJREAD storeAufsRead;
extern STOBJWRITE storeAufsWrite;
extern STOBJUNLINK storeAufsUnlink;

#endif
