
/*
 * $Id: async_io.cc,v 1.1 2000/05/03 17:15:46 adrian Exp $
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
#define _AIO_OPENDIR	5
#define _AIO_STAT	6

typedef struct aio_ctrl_t {
    struct aio_ctrl_t *next;
    int fd;
    int operation;
    AIOCB *done_handler;
    void *done_handler_data;
    aio_result_t result;
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

static aio_ctrl_t *used_list = NULL;
static int initialised = 0;
static OBJH aioStats;
static MemPool *aio_ctrl_pool;
static void aioFDWasClosed(int fd);

MemPool * aio_state_pool;

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
    aio_state_pool = memPoolCreate("Async UFS IO State data", sizeof(aiostate_t));
    cachemgrRegister("aio_counts", "Async IO Function Counters",
	aioStats, 0, 1);
    initialised = 1;
    comm_quick_poll_required();
}

void
aioDone(void)
{
    memPoolDestroy(aio_ctrl_pool);
    memPoolDestroy(aio_state_pool);
    initialised = 0;
}

void
aioOpen(const char *path, int oflag, mode_t mode, AIOCB * callback, void *callback_data)
{
    aio_ctrl_t *ctrlp;
    int ret;

    assert(initialised);
    aio_counts.open++;
    ctrlp = memPoolAlloc(aio_ctrl_pool);
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_OPEN;
    cbdataLock(callback_data);
    if (aio_open(path, oflag, mode, &ctrlp->result) < 0) {
	ret = open(path, oflag, mode);
	if (callback)
	    (callback) (ctrlp->fd, callback_data, ret, errno);
	cbdataUnlock(callback_data);
	memPoolFree(aio_ctrl_pool, ctrlp);
	return;
    }
    ctrlp->next = used_list;
    used_list = ctrlp;
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
    if (aio_close(fd, &ctrlp->result) < 0) {
	close(fd);		/* Can't create thread - do a normal close */
	memPoolFree(aio_ctrl_pool, ctrlp);
	aioFDWasClosed(fd);
	return;
    }
    ctrlp->next = used_list;
    used_list = ctrlp;
    return;
}

void
aioCancel(int fd)
{
    aio_ctrl_t *curr;
    aio_ctrl_t *prev;
    aio_ctrl_t *next;
    AIOCB *done_handler;
    void *their_data;

    assert(initialised);
    aio_counts.cancel++;
    prev = NULL;
    curr = used_list;
    for (curr = used_list;; curr = next) {
	while (curr != NULL) {
	    if (curr->fd == fd)
		break;
	    prev = curr;
	    curr = curr->next;
	}
	if (curr == NULL)
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
	next = curr->next;
	if (prev == NULL)
	    used_list = next;
	else
	    prev->next = next;

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
    for (ctrlp = used_list; ctrlp != NULL; ctrlp = ctrlp->next)
	if (ctrlp->fd == fd)
	    break;
    if (ctrlp != NULL) {
	debug(0, 0) ("aioWrite: EWOULDBLOCK\n");
	errno = EWOULDBLOCK;
	if (callback)
	    (callback) (fd, callback_data, -1, errno);
	if (free_func)
            free_func(bufp);
	return;
    }
    ctrlp = memPoolAlloc(aio_ctrl_pool);
    ctrlp->fd = fd;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_WRITE;
    if (offset >= 0)
	seekmode = SEEK_SET;
    else {
	seekmode = SEEK_END;
	offset = 0;
    }
    cbdataLock(callback_data);
    if (aio_write(fd, bufp, len, offset, seekmode, &ctrlp->result) < 0) {
	if (errno == ENOMEM || errno == EAGAIN || errno == EINVAL)
	    errno = EWOULDBLOCK;
	if (callback)
	    (callback) (fd, callback_data, -1, errno);
	cbdataUnlock(callback_data);
	memPoolFree(aio_ctrl_pool, ctrlp);
    } else {
	ctrlp->next = used_list;
	used_list = ctrlp;
    }
    /*
     * aio_write copies the buffer so we can free it here
     */
    if (free_func)
        free_func(bufp);
}				/* aioWrite */


void
aioRead(int fd, int offset, char *bufp, int len, AIOCB * callback, void *callback_data)
{
    aio_ctrl_t *ctrlp;
    int seekmode;

    assert(initialised);
    aio_counts.read++;
    for (ctrlp = used_list; ctrlp != NULL; ctrlp = ctrlp->next)
	if (ctrlp->fd == fd)
	    break;
    if (ctrlp != NULL) {
	errno = EWOULDBLOCK;
	if (callback)
	    (callback) (fd, callback_data, -1, errno);
	return;
    }
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
    if (aio_read(fd, bufp, len, offset, seekmode, &ctrlp->result) < 0) {
	if (errno == ENOMEM || errno == EAGAIN || errno == EINVAL)
	    errno = EWOULDBLOCK;
	if (callback)
	    (callback) (fd, callback_data, -1, errno);
	cbdataUnlock(callback_data);
	memPoolFree(aio_ctrl_pool, ctrlp);
	return;
    }
    ctrlp->next = used_list;
    used_list = ctrlp;
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
    if (aio_stat(path, sb, &ctrlp->result) < 0) {
	if (errno == ENOMEM || errno == EAGAIN || errno == EINVAL)
	    errno = EWOULDBLOCK;
	if (callback)
	    (callback) (ctrlp->fd, callback_data, -1, errno);
	cbdataUnlock(callback_data);
	memPoolFree(aio_ctrl_pool, ctrlp);
	return;
    }
    ctrlp->next = used_list;
    used_list = ctrlp;
    return;
}				/* aioStat */

void
aioUnlink(const char *pathname, AIOCB * callback, void *callback_data)
{
    aio_ctrl_t *ctrlp;
    char *path;
    assert(initialised);
    aio_counts.unlink++;
    ctrlp = memPoolAlloc(aio_ctrl_pool);
    ctrlp->fd = -2;
    ctrlp->done_handler = callback;
    ctrlp->done_handler_data = callback_data;
    ctrlp->operation = _AIO_UNLINK;
    path = xstrdup(pathname);
    cbdataLock(callback_data);
    if (aio_unlink(path, &ctrlp->result) < 0) {
	int ret = unlink(path);
	(callback) (ctrlp->fd, callback_data, ret, errno);
	cbdataUnlock(callback_data);
	memPoolFree(aio_ctrl_pool, ctrlp);
	xfree(path);
	return;
    }
    ctrlp->next = used_list;
    used_list = ctrlp;
    xfree(path);
}				/* aioUnlink */


void
aioCheckCallbacks(SwapDir *SD)
{
    aio_result_t *resultp;
    aio_ctrl_t *ctrlp;
    aio_ctrl_t *prev;
    AIOCB *done_handler;
    void *their_data;

    assert(initialised);
    aio_counts.check_callback++;
    for (;;) {
	if ((resultp = aio_poll_done()) == NULL)
	    break;
	prev = NULL;
	for (ctrlp = used_list; ctrlp != NULL; prev = ctrlp, ctrlp = ctrlp->next)
	    if (&ctrlp->result == resultp)
		break;
	if (ctrlp == NULL)
	    continue;
	if (prev == NULL)
	    used_list = ctrlp->next;
	else
	    prev->next = ctrlp->next;
	if ((done_handler = ctrlp->done_handler)) {
	    their_data = ctrlp->done_handler_data;
	    ctrlp->done_handler = NULL;
	    ctrlp->done_handler_data = NULL;
	    if (cbdataValid(their_data))
		done_handler(ctrlp->fd, their_data,
		    ctrlp->result.aio_return, ctrlp->result.aio_errno);
	    cbdataUnlock(their_data);
	}
	if (ctrlp->operation == _AIO_CLOSE)
	    aioFDWasClosed(ctrlp->fd);
	memPoolFree(aio_ctrl_pool, ctrlp);
    }
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
aioSync(SwapDir *SD)
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
