/*
 * DiskThreads.h
 *
 * Internal declarations for the DiskThreads routines
 */

#ifndef __DISKTHREADS_H__
#define __DISKTHREADS_H__

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
    _AIO_OP_OPENDIR,
    _AIO_OP_STAT
};
typedef enum _squidaio_request_type squidaio_request_type;

typedef void AIOCB(int fd, void *cbdata, const char *buf, int aio_return, int aio_errno);

struct squidaio_result_t
{
    int aio_return;
    int aio_errno;
    enum _squidaio_request_type result_type;
    void *_data;		/* Internal housekeeping */
    void *data;			/* Available to the caller */
};

struct squidaio_ctrl_t
{

    struct squidaio_ctrl_t *next;
    int fd;
    int operation;
    AIOCB *done_handler;
    void *done_handler_data;
    squidaio_result_t result;
    int len;
    char *bufp;
    FREE *free_func;
    dlink_node node;
};

void squidaio_init(void);
void squidaio_shutdown(void);
int squidaio_cancel(squidaio_result_t *);
int squidaio_open(const char *, int, mode_t, squidaio_result_t *);
int squidaio_read(int, char *, int, off_t, int, squidaio_result_t *);
int squidaio_write(int, char *, int, off_t, int, squidaio_result_t *);
int squidaio_close(int, squidaio_result_t *);

int squidaio_stat(const char *, struct stat *, squidaio_result_t *);
int squidaio_unlink(const char *, squidaio_result_t *);
int squidaio_opendir(const char *, squidaio_result_t *);
squidaio_result_t *squidaio_poll_done(void);
int squidaio_operations_pending(void);
int squidaio_sync(void);
int squidaio_get_queue_len(void);
void *squidaio_xmalloc(int size);
void squidaio_xfree(void *p, int size);
void squidaio_stats(StoreEntry *);

void aioInit(void);
void aioDone(void);
void aioCancel(int);
void aioOpen(const char *, int, mode_t, AIOCB *, void *);
void aioClose(int);
void aioWrite(int, int offset, char *, int size, AIOCB *, void *, FREE *);
void aioRead(int, int offset, int size, AIOCB *, void *);

void aioStat(char *, struct stat *, AIOCB *, void *);
void aioUnlink(const char *, AIOCB *, void *);
int aioQueueSize(void);

#include "DiskIO/DiskFile.h"

class DiskThreadsIOStrategy;

struct AIOCounts
{
    int open_start;
    int open_finish;
    int close_start;
    int close_finish;
    int cancel;
    int write_start;
    int write_finish;
    int read_start;
    int read_finish;
    int stat_start;
    int stat_finish;
    int unlink_start;
    int unlink_finish;
    int check_callback;
};

extern AIOCounts squidaio_counts;
extern dlink_list used_list;


#endif
