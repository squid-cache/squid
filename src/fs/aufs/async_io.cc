
/*
 * $Id: async_io.cc,v 1.6 2000/11/10 21:42:03 hno Exp $
 *
 * DEBUG: section 32    Asynchronous Disk I/O
 * AUTHOR: Pete Bentley <pete@demon.net>
 * AUTHOR: Stewart Forster <slf@connect.com.au>
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

#define _AIO_OPEN	0
#define _AIO_READ	1
#define _AIO_WRITE	2
#define _AIO_CLOSE	3
#define _AIO_UNLINK	4
#define _AIO_TRUNCATE	4
#define _AIO_OPENDIR	5
#define _AIO_STAT	6

typedef struct aio_ctrl_t {
    struct aio_ctrl_t *next;
    int fd;
    int operation;
    AIOCB *done_handler;
    void *done_handler_data;
    aio_result_t result;
    char *bufp;
    FREE *free_func;
    dlink_node node;
} aio_ctrl_t;

struct {
    int open;
    int close;
    int cancel;
    int write;
    int read;
    int stat;
    int unlink;
    int check_callback;
} aio_counts;

typedef struct aio_unlinkq_t {
    char *path;
    struct aio_unlinkq_t *next;
} aio_unlinkq_t;

static dlink_list used_list;
static int initialised = 0;
static OBJH aioStats;
static MemPool *aio_ctrl_pool;
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
    aio_ctrl_pool = memPoolCreate("aio_ctrl", sizeof(aio_ctrl_t));
    cachemgrRegister("aio_counts", "Async IO Function Counters",
	aioStats, 0, 1);
    initialised = 1;
    comm_quick_poll_required();
}

void
aioDone(void)
{
    memPoolDestroy(aio_ctrl_pool);
    initialised = 0;
}

void
aioOpen(const char *path, int oflag, mode_t mode, AIOCB * callback, void *callback_data)
{
    aio_ctrl_t *ctrlp;

    assert(initialised);
    aio_counts.open++;
    ctrlp = memPoolAlloc(aio_ctrl_pool);
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_OPEN;
    cbdataLock(callback_data);
    ctrlp->result.data = ctrlp;
    aio_open(path, oflag, mode, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
    return;
}

void
aioClose(int fd)
{
    aio_ctrl_t *ctrlp;

    assert(initialised);
    aio_counts.close++;
    aioCancel(fd);
    ctrlp = memPoolAlloc(aio_ctrl_pool);
    ctrlp->fd = fd;
    ctrlp->done_handler = NULL;
    ctrlp->done_handler_data = NULL;
    ctrlp->operation = _AIO_CLOSE;
    ctrlp->result.data = ctrlp;
    aio_close(fd, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
    return;
}

void
aioCancel(int fd)
{
    aio_ctrl_t *curr;
    AIOCB *done_handler;
    void *their_data;
    dlink_node *m, *next;

    assert(initialised);
    aio_counts.cancel++;
    for (m = used_list.head; m; m = next) {
	while (m) {
	    curr = m->data;
	    if (curr->fd == fd)
		break;
	    m = m->next;
	}
	if (m == NULL)
	    break;

	aio_cancel(&curr->result);

	if ((done_handler = curr->done_handler)) {
	    their_data = curr->done_handler_data;
	    curr->done_handler = NULL;
	    curr->done_handler_data = NULL;
	    debug(0, 0) ("this be aioCancel\n");
	    if (cbdataValid(their_data))
		done_handler(fd, their_data, -2, -2);
	    cbdataUnlock(their_data);
	}
	next = m->next;
	dlinkDelete(m, &used_list);
	memPoolFree(aio_ctrl_pool, curr);
    }
}


void
aioWrite(int fd, int offset, char *bufp, int len, AIOCB * callback, void *callback_data, FREE * free_func)
{
    aio_ctrl_t *ctrlp;
    int seekmode;

    assert(initialised);
    aio_counts.write++;
    ctrlp = memPoolAlloc(aio_ctrl_pool);
    ctrlp->fd = fd;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_WRITE;
    ctrlp->bufp = bufp;
    ctrlp->free_func = free_func;
    if (offset >= 0)
	seekmode = SEEK_SET;
    else {
	seekmode = SEEK_END;
	offset = 0;
    }
    cbdataLock(callback_data);
    ctrlp->result.data = ctrlp;
    aio_write(fd, bufp, len, offset, seekmode, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
}				/* aioWrite */


void
aioRead(int fd, int offset, char *bufp, int len, AIOCB * callback, void *callback_data)
{
    aio_ctrl_t *ctrlp;
    int seekmode;

    assert(initialised);
    aio_counts.read++;
    ctrlp = memPoolAlloc(aio_ctrl_pool);
    ctrlp->fd = fd;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_READ;
    if (offset >= 0)
	seekmode = SEEK_SET;
    else {
	seekmode = SEEK_CUR;
	offset = 0;
    }
    cbdataLock(callback_data);
    ctrlp->result.data = ctrlp;
    aio_read(fd, bufp, len, offset, seekmode, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
    return;
}				/* aioRead */

void
aioStat(char *path, struct stat *sb, AIOCB * callback, void *callback_data)
{
    aio_ctrl_t *ctrlp;

    assert(initialised);
    aio_counts.stat++;
    ctrlp = memPoolAlloc(aio_ctrl_pool);
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_STAT;
    cbdataLock(callback_data);
    ctrlp->result.data = ctrlp;
    aio_stat(path, sb, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
    return;
}				/* aioStat */

void
aioUnlink(const char *path, AIOCB * callback, void *callback_data)
{
    aio_ctrl_t *ctrlp;
    assert(initialised);
    aio_counts.unlink++;
    ctrlp = memPoolAlloc(aio_ctrl_pool);
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_UNLINK;
    cbdataLock(callback_data);
    ctrlp->result.data = ctrlp;
    aio_unlink(path, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
}				/* aioUnlink */

void
aioTruncate(const char *path, off_t length, AIOCB * callback, void *callback_data)
{
    aio_ctrl_t *ctrlp;
    assert(initialised);
    aio_counts.unlink++;
    ctrlp = memPoolAlloc(aio_ctrl_pool);
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_TRUNCATE;
    cbdataLock(callback_data);
    ctrlp->result.data = ctrlp;
    aio_truncate(path, length, &ctrlp->result);
    dlinkAdd(ctrlp, &ctrlp->node, &used_list);
}				/* aioTruncate */


int
aioCheckCallbacks(SwapDir * SD)
{
    aio_result_t *resultp;
    aio_ctrl_t *ctrlp;
    AIOCB *done_handler;
    void *their_data;
    int retval = 0;
   
    assert(initialised);
    aio_counts.check_callback++;
    for (;;) {
	if ((resultp = aio_poll_done()) == NULL)
	    break;
	ctrlp = (aio_ctrl_t *)resultp->data;
	if (ctrlp == NULL)
	    continue; /* XXX Should not happen */
	dlinkDelete(&ctrlp->node, &used_list);
	if ((done_handler = ctrlp->done_handler)) {
	    their_data = ctrlp->done_handler_data;
	    ctrlp->done_handler = NULL;
	    ctrlp->done_handler_data = NULL;
	    if (cbdataValid(their_data)) {
                retval = 1; /* Return that we've actually done some work */
		done_handler(ctrlp->fd, their_data,
		    ctrlp->result.aio_return, ctrlp->result.aio_errno);
	    }
	    cbdataUnlock(their_data);
	}
	/* free data if requested to aioWrite() */
	if (ctrlp->free_func)
	    ctrlp->free_func(ctrlp->bufp);
	if (ctrlp->operation == _AIO_CLOSE)
	    aioFDWasClosed(ctrlp->fd);
	memPoolFree(aio_ctrl_pool, ctrlp);
    }
    return retval;
}

void
aioStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "ASYNC IO Counters:\n");
    storeAppendPrintf(sentry, "open\t%d\n", aio_counts.open);
    storeAppendPrintf(sentry, "close\t%d\n", aio_counts.close);
    storeAppendPrintf(sentry, "cancel\t%d\n", aio_counts.cancel);
    storeAppendPrintf(sentry, "write\t%d\n", aio_counts.write);
    storeAppendPrintf(sentry, "read\t%d\n", aio_counts.read);
    storeAppendPrintf(sentry, "stat\t%d\n", aio_counts.stat);
    storeAppendPrintf(sentry, "unlink\t%d\n", aio_counts.unlink);
    storeAppendPrintf(sentry, "check_callback\t%d\n", aio_counts.check_callback);
    storeAppendPrintf(sentry, "queue\t%d\n", aio_get_queue_len());
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
    } while (aio_sync());
    debug(32, 1) ("aioSync: done\n");
}

int
aioQueueSize(void)
{
    return memPoolInUseCount(aio_ctrl_pool);
}
