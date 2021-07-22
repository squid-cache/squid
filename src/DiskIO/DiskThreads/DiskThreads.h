/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * DiskThreads.h
 *
 * Internal declarations for the DiskThreads routines
 */

#ifndef __DISKTHREADS_H__
#define __DISKTHREADS_H__

#include "dlink.h"
#include "mem/forward.h"

/* this non-standard-conformant include is needed in order to have stat(2) and struct stat
   properly defined on some systems (e.g. OpenBSD 5.4) */
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if AUFS_IO_THREADS
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

class squidaio_result_t
{
public:
    int aio_return = 0;
    int aio_errno = 0;
    enum _squidaio_request_type result_type = _AIO_OP_NONE;
    void *_data = nullptr;        /* Internal housekeeping */
    void *data = nullptr;         /* Available to the caller */
};

class squidaio_ctrl_t
{
    MEMPROXY_CLASS(squidaio_ctrl_t);
public:
    squidaio_ctrl_t() : done_handler(NULL), free_func(NULL) {}

    squidaio_ctrl_t *next = nullptr;
    int fd = 0;
    int operation = 0;
    AIOCB *done_handler;
    void *done_handler_data = nullptr;
    squidaio_result_t result;
    int len = 0;
    char *bufp = nullptr;
    FREE *free_func;
    dlink_node node;
};

void squidaio_init(void);
void squidaio_shutdown(void);
int squidaio_cancel(squidaio_result_t *);
int squidaio_open(const char *, int, mode_t, squidaio_result_t *);
int squidaio_read(int, char *, size_t, off_t, int, squidaio_result_t *);
int squidaio_write(int, char *, size_t, off_t, int, squidaio_result_t *);
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
void aioWrite(int, off_t offset, char *, size_t size, AIOCB *, void *, FREE *);
void aioRead(int, off_t offset, size_t size, AIOCB *, void *);

void aioStat(char *, struct stat *, AIOCB *, void *);
void aioUnlink(const char *, AIOCB *, void *);
int aioQueueSize(void);

#include "DiskIO/DiskFile.h"

class DiskThreadsIOStrategy;

class AIOCounts
{
public:
    uint64_t open_start = 0;
    uint64_t open_finish = 0;
    uint64_t close_start = 0;
    uint64_t close_finish = 0;
    uint64_t cancel = 0;
    uint64_t write_start = 0;
    uint64_t write_finish = 0;
    uint64_t read_start = 0;
    uint64_t read_finish = 0;
    uint64_t stat_start = 0;
    uint64_t stat_finish = 0;
    uint64_t unlink_start = 0;
    uint64_t unlink_finish = 0;
    uint64_t check_callback = 0;
};

extern AIOCounts squidaio_counts;
extern dlink_list used_list;

#endif

