/*
 * store_aufs.h
 *
 * Internal declarations for the aufs routines
 */

#ifndef __STORE_ASYNCUFS_H__
#define __STORE_ASYNCUFS_H__

#ifdef AUFS_IO_THREADS
#define NUMTHREADS AUFS_IO_THREADS
#else
#define NUMTHREADS (Config.cacheSwap.n_configured*16)
#endif

/* Queue limit where swapouts are deferred (load calculation) */
#define MAGIC1 (NUMTHREADS*Config.cacheSwap.n_configured*5)
/* Queue limit where swapins are deferred (open/create fails) */
#define MAGIC2 (NUMTHREADS*Config.cacheSwap.n_configured*20)

/* Which operations to run async */
#define ASYNC_OPEN 1
#define ASYNC_CLOSE 0
#define ASYNC_CREATE 1
#define ASYNC_WRITE 0
#define ASYNC_READ 1

enum _squidaio_request_type {
    _AIO_OP_NONE = 0,
    _AIO_OP_OPEN,
    _AIO_OP_READ,
    _AIO_OP_WRITE,
    _AIO_OP_CLOSE,
    _AIO_OP_UNLINK,
    _AIO_OP_TRUNCATE,
    _AIO_OP_OPENDIR,
    _AIO_OP_STAT
};
typedef enum _squidaio_request_type squidaio_request_type;

struct _squidaio_result_t {
    int aio_return;
    int aio_errno;
    enum _squidaio_request_type result_type;
    void *_data;		/* Internal housekeeping */
    void *data;			/* Available to the caller */
};

typedef struct _squidaio_result_t squidaio_result_t;

typedef void AIOCB(int fd, void *cbdata, const char *buf, int aio_return, int aio_errno);

int squidaio_cancel(squidaio_result_t *);
int squidaio_open(const char *, int, mode_t, squidaio_result_t *);
int squidaio_read(int, char *, int, off_t, int, squidaio_result_t *);
int squidaio_write(int, char *, int, off_t, int, squidaio_result_t *);
int squidaio_close(int, squidaio_result_t *);
int squidaio_stat(const char *, struct stat *, squidaio_result_t *);
int squidaio_unlink(const char *, squidaio_result_t *);
int squidaio_truncate(const char *, off_t length, squidaio_result_t *);
int squidaio_opendir(const char *, squidaio_result_t *);
squidaio_result_t *squidaio_poll_done(void);
int squidaio_operations_pending(void);
int squidaio_sync(void);
int squidaio_get_queue_len(void);
void *squidaio_xmalloc(int size);
void squidaio_xfree(void *p, int size);

void aioInit(void);
void aioDone(void);
void aioCancel(int);
void aioOpen(const char *, int, mode_t, AIOCB *, void *);
void aioClose(int);
void aioWrite(int, int offset, char *, int size, AIOCB *, void *, FREE *);
void aioRead(int, int offset, int size, AIOCB *, void *);
void aioStat(char *, struct stat *, AIOCB *, void *);
void aioUnlink(const char *, AIOCB *, void *);
void aioTruncate(const char *, off_t length, AIOCB *, void *);
int aioCheckCallbacks(SwapDir *);
void aioSync(SwapDir *);
int aioQueueSize(void);

struct _squidaiostate_t {
    int fd;
    struct {
	unsigned int close_request:1;
	unsigned int reading:1;
	unsigned int writing:1;
	unsigned int opening:1;
	unsigned int write_kicking:1;
	unsigned int read_kicking:1;
	unsigned int inreaddone:1;
    } flags;
    char *read_buf;
    link_list *pending_writes;
    link_list *pending_reads;
};

struct _queued_write {
    char *buf;
    size_t size;
    off_t offset;
    FREE *free_func;
};

struct _queued_read {
    char *buf;
    size_t size;
    off_t offset;
    STRCB *callback;
    void *callback_data;
};

typedef struct _squidaiostate_t squidaiostate_t;

/* The squidaio_state memory pools */
extern MemPool *squidaio_state_pool;
extern MemPool *aufs_qread_pool;
extern MemPool *aufs_qwrite_pool;

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
