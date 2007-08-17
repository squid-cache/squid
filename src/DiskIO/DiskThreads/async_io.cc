
/*
 * $Id: async_io.cc,v 1.5 2007/08/16 23:32:28 hno Exp $
 *
 * DEBUG: section 32    Asynchronous Disk I/O
 * AUTHOR: Pete Bentley <pete@demon.net>
 * AUTHOR: Stewart Forster <slf@connect.com.au>
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "DiskThreads.h"
#include "Store.h"
#include "fde.h"
#include "DiskThreadsIOStrategy.h"
#include "Generic.h"

AIOCounts squidaio_counts;

typedef struct squidaio_unlinkq_t
{
    char *path;

    struct squidaio_unlinkq_t *next;
}

squidaio_unlinkq_t;

dlink_list used_list;

void
aioOpen(const char *path, int oflag, mode_t mode, AIOCB * callback, void *callback_data)
{
    squidaio_ctrl_t *ctrlp;

    assert(DiskThreadsIOStrategy::Instance.initialised);
    squidaio_counts.open_start++;
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
    squidaio_counts.close_start++;
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
    squidaio_counts.cancel++;

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
            debugs(32, 1, "this be aioCancel. Danger ahead!");

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
        DiskThreadsIOStrategy::Instance.squidaio_ctrl_pool->free(ctrlp);
    }
}


void
aioWrite(int fd, off_t offset, char *bufp, size_t len, AIOCB * callback, void *callback_data, FREE * free_func)
{
    squidaio_ctrl_t *ctrlp;
    int seekmode;

    assert(DiskThreadsIOStrategy::Instance.initialised);
    squidaio_counts.write_start++;
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
}				/* aioWrite */


void
aioRead(int fd, off_t offset, size_t len, AIOCB * callback, void *callback_data)
{
    squidaio_ctrl_t *ctrlp;
    int seekmode;

    assert(DiskThreadsIOStrategy::Instance.initialised);
    squidaio_counts.read_start++;
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
}				/* aioRead */

void

aioStat(char *path, struct stat *sb, AIOCB * callback, void *callback_data)
{
    squidaio_ctrl_t *ctrlp;

    assert(DiskThreadsIOStrategy::Instance.initialised);
    squidaio_counts.stat_start++;
    ctrlp = (squidaio_ctrl_t *)DiskThreadsIOStrategy::Instance.squidaio_ctrl_pool->alloc();
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = cbdataReference(callback_data);
    ctrlp->operation = _AIO_STAT;
    ctrlp->result.data = ctrlp;
    squidaio_stat(path, sb, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
    return;
}				/* aioStat */

void
aioUnlink(const char *path, AIOCB * callback, void *callback_data)
{
    squidaio_ctrl_t *ctrlp;
    assert(DiskThreadsIOStrategy::Instance.initialised);
    squidaio_counts.unlink_start++;
    ctrlp = (squidaio_ctrl_t *)DiskThreadsIOStrategy::Instance.squidaio_ctrl_pool->alloc();
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = cbdataReference(callback_data);
    ctrlp->operation = _AIO_UNLINK;
    ctrlp->result.data = ctrlp;
    squidaio_unlink(path, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
}				/* aioUnlink */

int
aioQueueSize(void)
{
    return DiskThreadsIOStrategy::Instance.squidaio_ctrl_pool->inUseCount();
}
