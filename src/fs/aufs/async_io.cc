
/*
 * $Id: async_io.cc,v 1.16 2002/10/13 20:35:24 robertc Exp $
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
#include "store_asyncufs.h"
#include "Store.h"

#define _AIO_OPEN	0
#define _AIO_READ	1
#define _AIO_WRITE	2
#define _AIO_CLOSE	3
#define _AIO_UNLINK	4
#define _AIO_TRUNCATE	4
#define _AIO_OPENDIR	5
#define _AIO_STAT	6

typedef struct squidaio_ctrl_t {
    struct squidaio_ctrl_t *next;
    int fd;
    int operation;
    AIOCB *done_handler;
    void *done_handler_data;
    squidaio_result_t result;
    char *bufp;
    FREE *free_func;
    dlink_node node;
} squidaio_ctrl_t;

static struct {
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
} squidaio_counts;

typedef struct squidaio_unlinkq_t {
    char *path;
    struct squidaio_unlinkq_t *next;
} squidaio_unlinkq_t;

static dlink_list used_list;
static int initialised = 0;
static OBJH aioStats;
static MemPool *squidaio_ctrl_pool;
static void aioFDWasClosed(int fd);

static void
aioFDWasClosed(int fd)
{
    if (fd_table[fd].flags.closing)
	fd_close(fd);
}

void
aioInit(void)
{
    if (initialised)
	return;
    squidaio_ctrl_pool = memPoolCreate("aio_ctrl", sizeof(squidaio_ctrl_t));
    cachemgrRegister("squidaio_counts", "Async IO Function Counters",
	aioStats, 0, 1);
    initialised = 1;
    comm_quick_poll_required();
}

void
aioDone(void)
{
    memPoolDestroy(&squidaio_ctrl_pool);
    initialised = 0;
}

void
aioOpen(const char *path, int oflag, mode_t mode, AIOCB * callback, void *callback_data)
{
    squidaio_ctrl_t *ctrlp;

    assert(initialised);
    squidaio_counts.open_start++;
    ctrlp = (squidaio_ctrl_t *)memPoolAlloc(squidaio_ctrl_pool);
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

    assert(initialised);
    squidaio_counts.close_start++;
    aioCancel(fd);
    ctrlp = (squidaio_ctrl_t *)memPoolAlloc(squidaio_ctrl_pool);
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
    squidaio_ctrl_t *curr;
    dlink_node *m, *next;

    assert(initialised);
    squidaio_counts.cancel++;
    for (m = used_list.head; m; m = next) {
	next = m->next;
	curr = (squidaio_ctrl_t *)m->data;
	if (curr->fd != fd)
	    continue;

	squidaio_cancel(&curr->result);

	if (curr->done_handler) {
	    AIOCB *callback = curr->done_handler;
	    void *cbdata;
	    curr->done_handler = NULL;
	    debug(32, 2) ("this be aioCancel\n");
	    if (cbdataReferenceValidDone(curr->done_handler_data, &cbdata))
		callback(fd, cbdata, -2, -2);
	}
	dlinkDelete(m, &used_list);
	memPoolFree(squidaio_ctrl_pool, curr);
    }
}


void
aioWrite(int fd, int offset, char *bufp, int len, AIOCB * callback, void *callback_data, FREE * free_func)
{
    squidaio_ctrl_t *ctrlp;
    int seekmode;

    assert(initialised);
    squidaio_counts.write_start++;
    ctrlp = (squidaio_ctrl_t *)memPoolAlloc(squidaio_ctrl_pool);
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
aioRead(int fd, int offset, char *bufp, int len, AIOCB * callback, void *callback_data)
{
    squidaio_ctrl_t *ctrlp;
    int seekmode;

    assert(initialised);
    squidaio_counts.read_start++;
    ctrlp = (squidaio_ctrl_t *)memPoolAlloc(squidaio_ctrl_pool);
    ctrlp->fd = fd;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = cbdataReference(callback_data);
    ctrlp->operation = _AIO_READ;
    if (offset >= 0)
	seekmode = SEEK_SET;
    else {
	seekmode = SEEK_CUR;
	offset = 0;
    }
    ctrlp->result.data = ctrlp;
    squidaio_read(fd, bufp, len, offset, seekmode, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
    return;
}				/* aioRead */

void
aioStat(char *path, struct stat *sb, AIOCB * callback, void *callback_data)
{
    squidaio_ctrl_t *ctrlp;

    assert(initialised);
    squidaio_counts.stat_start++;
    ctrlp = (squidaio_ctrl_t *)memPoolAlloc(squidaio_ctrl_pool);
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
    assert(initialised);
    squidaio_counts.unlink_start++;
    ctrlp = (squidaio_ctrl_t *)memPoolAlloc(squidaio_ctrl_pool);
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = cbdataReference(callback_data);
    ctrlp->operation = _AIO_UNLINK;
    ctrlp->result.data = ctrlp;
    squidaio_unlink(path, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
}				/* aioUnlink */

void
aioTruncate(const char *path, off_t length, AIOCB * callback, void *callback_data)
{
    squidaio_ctrl_t *ctrlp;
    assert(initialised);
    squidaio_counts.unlink_start++;
    ctrlp = (squidaio_ctrl_t *)memPoolAlloc(squidaio_ctrl_pool);
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = cbdataReference(callback_data);
    ctrlp->operation = _AIO_TRUNCATE;
    ctrlp->result.data = ctrlp;
    squidaio_truncate(path, length, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
}				/* aioTruncate */


int
aioCheckCallbacks(SwapDir * SD)
{
    squidaio_result_t *resultp;
    squidaio_ctrl_t *ctrlp;
    int retval = 0;

    assert(initialised);
    squidaio_counts.check_callback++;
    for (;;) {
	if ((resultp = squidaio_poll_done()) == NULL)
	    break;
	ctrlp = (squidaio_ctrl_t *) resultp->data;
	switch (resultp->result_type){
	    case _AIO_OP_NONE:
	    case _AIO_OP_TRUNCATE:
	    case _AIO_OP_OPENDIR:
		 break;
	    case _AIO_OP_OPEN:
		 ++squidaio_counts.open_finish;
		 break;
	    case _AIO_OP_READ:
		 ++squidaio_counts.read_finish;
		 break;
	    case _AIO_OP_WRITE:
		 ++squidaio_counts.write_finish;
		 break;
	    case _AIO_OP_CLOSE:
		 ++squidaio_counts.close_finish;
		 break;
	    case _AIO_OP_UNLINK:
		 ++squidaio_counts.unlink_finish;
		 break;
	    case _AIO_OP_STAT:
		 ++squidaio_counts.stat_finish;
		 break;
	}
	if (ctrlp == NULL)
	    continue;		/* XXX Should not happen */
	dlinkDelete(&ctrlp->node, &used_list);
	if (ctrlp->done_handler) {
	    AIOCB *callback = ctrlp->done_handler;
	    void *cbdata;
	    ctrlp->done_handler = NULL;
	    if (cbdataReferenceValidDone(ctrlp->done_handler_data, &cbdata)) {
		retval = 1;	/* Return that we've actually done some work */
		callback(ctrlp->fd, cbdata,
		    ctrlp->result.aio_return, ctrlp->result.aio_errno);
	    }
	}
	/* free data if requested to aioWrite() */
	if (ctrlp->free_func)
	    ctrlp->free_func(ctrlp->bufp);
	if (ctrlp->operation == _AIO_CLOSE)
	    aioFDWasClosed(ctrlp->fd);
	memPoolFree(squidaio_ctrl_pool, ctrlp);
    }
    return retval;
}

void
aioStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "ASYNC IO Counters:\n");
    storeAppendPrintf(sentry, "Operation\t# Requests\tNumber serviced\n");
    storeAppendPrintf(sentry, "open\t%d\t%d\n", squidaio_counts.open_start,squidaio_counts.open_finish);
    storeAppendPrintf(sentry, "close\t%d\t%d\n", squidaio_counts.close_start,squidaio_counts.close_finish);
    storeAppendPrintf(sentry, "cancel\t%d\t-\n", squidaio_counts.cancel);
    storeAppendPrintf(sentry, "write\t%d\t%d\n", squidaio_counts.write_start,squidaio_counts.write_finish);
    storeAppendPrintf(sentry, "read\t%d\t%d\n", squidaio_counts.read_start,squidaio_counts.read_finish);
    storeAppendPrintf(sentry, "stat\t%d\t%d\n", squidaio_counts.stat_start,squidaio_counts.stat_finish);
    storeAppendPrintf(sentry, "unlink\t%d\t%d\n", squidaio_counts.unlink_start,squidaio_counts.unlink_finish);
    storeAppendPrintf(sentry, "check_callback\t%d\t-\n", squidaio_counts.check_callback);
    storeAppendPrintf(sentry, "queue\t%d\t-\n", squidaio_get_queue_len());
}

/* Flush all pending I/O */
void
aioSync(SwapDir * SD)
{
    if (!initialised)
	return;			/* nothing to do then */
    /* Flush all pending operations */
    debug(32, 1) ("aioSync: flushing pending I/O operations\n");
    do {
	aioCheckCallbacks(SD);
    } while (squidaio_sync());
    debug(32, 1) ("aioSync: done\n");
}

int
aioQueueSize(void)
{
    return memPoolInUseCount(squidaio_ctrl_pool);
}
