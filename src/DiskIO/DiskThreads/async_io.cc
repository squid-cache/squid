/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 32    Asynchronous Disk I/O */

#include "squid.h"
#include "DiskThreads.h"
#include "DiskThreadsIOStrategy.h"
#include "fde.h"
#include "Generic.h"
#include "Store.h"

AIOCounts squidaio_counts;

typedef struct squidaio_unlinkq_t {
    char *path;

    struct squidaio_unlinkq_t *next;
} squidaio_unlinkq_t;

dlink_list used_list;

void
aioOpen(const char *path, int oflag, mode_t mode, AIOCB * callback, void *callback_data)
{
    squidaio_ctrl_t *ctrlp;

    assert(DiskThreadsIOStrategy::Instance.initialised);
    ++squidaio_counts.open_start;
    ctrlp = (squidaio_ctrl_t *)DiskThreadsIOStrategy::Instance.squidaio_ctrl_pool->alloc();
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = cbdataReference(callback_data);
    ctrlp->operation = _AIO_OPEN;
    ctrlp->result.data = ctrlp;
    squidaio_open(path, oflag, mode, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
    return;
}

void
aioClose(int fd)
{
    squidaio_ctrl_t *ctrlp;

    assert(DiskThreadsIOStrategy::Instance.initialised);
    ++squidaio_counts.close_start;
    aioCancel(fd);
    ctrlp = (squidaio_ctrl_t *)DiskThreadsIOStrategy::Instance.squidaio_ctrl_pool->alloc();
    ctrlp->fd = fd;
    ctrlp->done_handler = NULL;
    ctrlp->done_handler_data = NULL;
    ctrlp->operation = _AIO_CLOSE;
    ctrlp->result.data = ctrlp;
    squidaio_close(fd, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
    return;
}

void
aioCancel(int fd)
{
    squidaio_ctrl_t *ctrlp;
    dlink_node *m, *next;

    assert(DiskThreadsIOStrategy::Instance.initialised);
    ++squidaio_counts.cancel;

    for (m = used_list.head; m; m = next) {
        next = m->next;
        ctrlp = (squidaio_ctrl_t *)m->data;

        if (ctrlp->fd != fd)
            continue;

        squidaio_cancel(&ctrlp->result);

        if (ctrlp->done_handler) {
            AIOCB *callback = ctrlp->done_handler;
            void *cbdata;
            ctrlp->done_handler = NULL;
            debugs(32, DBG_IMPORTANT, "this be aioCancel. Danger ahead!");

            if (cbdataReferenceValidDone(ctrlp->done_handler_data, &cbdata))
                callback(fd, cbdata, NULL, -2, -2);

            /* free data if requested to aioWrite() */
            if (ctrlp->free_func)
                ctrlp->free_func(ctrlp->bufp);

            /* free temporary read buffer */
            if (ctrlp->operation == _AIO_READ)
                squidaio_xfree(ctrlp->bufp, ctrlp->len);
        }

        dlinkDelete(m, &used_list);
        DiskThreadsIOStrategy::Instance.squidaio_ctrl_pool->freeOne(ctrlp);
    }
}

void
aioWrite(int fd, off_t offset, char *bufp, size_t len, AIOCB * callback, void *callback_data, FREE * free_func)
{
    squidaio_ctrl_t *ctrlp;
    int seekmode;

    assert(DiskThreadsIOStrategy::Instance.initialised);
    ++squidaio_counts.write_start;
    ctrlp = (squidaio_ctrl_t *)DiskThreadsIOStrategy::Instance.squidaio_ctrl_pool->alloc();
    ctrlp->fd = fd;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = cbdataReference(callback_data);
    ctrlp->operation = _AIO_WRITE;
    ctrlp->bufp = bufp;
    ctrlp->free_func = free_func;

    if (offset >= 0)
        seekmode = SEEK_SET;
    else {
        seekmode = SEEK_END;
        offset = 0;
    }

    ctrlp->result.data = ctrlp;
    squidaio_write(fd, bufp, len, offset, seekmode, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
}               /* aioWrite */

void
aioRead(int fd, off_t offset, size_t len, AIOCB * callback, void *callback_data)
{
    squidaio_ctrl_t *ctrlp;
    int seekmode;

    assert(DiskThreadsIOStrategy::Instance.initialised);
    ++squidaio_counts.read_start;
    ctrlp = (squidaio_ctrl_t *)DiskThreadsIOStrategy::Instance.squidaio_ctrl_pool->alloc();
    ctrlp->fd = fd;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = cbdataReference(callback_data);
    ctrlp->operation = _AIO_READ;
    ctrlp->len = len;
    ctrlp->bufp = (char *)squidaio_xmalloc(len);

    if (offset >= 0)
        seekmode = SEEK_SET;
    else {
        seekmode = SEEK_CUR;
        offset = 0;
    }

    ctrlp->result.data = ctrlp;
    squidaio_read(fd, ctrlp->bufp, len, offset, seekmode, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
    return;
}               /* aioRead */

void

aioStat(char *path, struct stat *sb, AIOCB * callback, void *callback_data)
{
    squidaio_ctrl_t *ctrlp;

    assert(DiskThreadsIOStrategy::Instance.initialised);
    ++squidaio_counts.stat_start;
    ctrlp = (squidaio_ctrl_t *)DiskThreadsIOStrategy::Instance.squidaio_ctrl_pool->alloc();
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = cbdataReference(callback_data);
    ctrlp->operation = _AIO_STAT;
    ctrlp->result.data = ctrlp;
    squidaio_stat(path, sb, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
    return;
}               /* aioStat */

void
aioUnlink(const char *path, AIOCB * callback, void *callback_data)
{
    squidaio_ctrl_t *ctrlp;
    assert(DiskThreadsIOStrategy::Instance.initialised);
    ++squidaio_counts.unlink_start;
    ctrlp = (squidaio_ctrl_t *)DiskThreadsIOStrategy::Instance.squidaio_ctrl_pool->alloc();
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = cbdataReference(callback_data);
    ctrlp->operation = _AIO_UNLINK;
    ctrlp->result.data = ctrlp;
    squidaio_unlink(path, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
}               /* aioUnlink */

int
aioQueueSize(void)
{
    return DiskThreadsIOStrategy::Instance.squidaio_ctrl_pool->inUseCount();
}

