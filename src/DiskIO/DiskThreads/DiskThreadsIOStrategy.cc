
/*
 * $Id$
 *
 * DEBUG: section 79    Squid-side Disk I/O functions.
 * AUTHOR: Robert Collins
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"

#include "CacheManager.h"
#include "DiskThreadsIOStrategy.h"
#include "DiskThreadsDiskFile.h"
/* for statfs */
#include "Store.h"
#include "fde.h"

void
DiskThreadsIOStrategy::init(void)
{
    if (initialised)
        return;

    squidaio_ctrl_pool = memPoolCreate("aio_ctrl", sizeof(squidaio_ctrl_t));

    initialised = true;

    /*
     * We'd like to call squidaio_init() here, but the configuration
     * hasn't been parsed yet and we don't know how many cache_dirs
     * there are, which means we don't know how many threads to start.
     */

    registerWithCacheManager();
}

void
DiskThreadsIOStrategy::registerWithCacheManager(void)
{
    CacheManager::GetInstance()->
    registerAction("squidaio_counts", "Async IO Function Counters",
                   aioStats, 0, 1);
}

void
DiskThreadsIOStrategy::done(void)
{
    if (!initialised)
        return;

    squidaio_shutdown();

    delete squidaio_ctrl_pool;

    squidaio_ctrl_pool = NULL;

    initialised = false;
}

int
DiskThreadsIOStrategy::callback()
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

        switch (resultp->result_type) {

        case _AIO_OP_NONE:

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
            AIOCB *done_callback = ctrlp->done_handler;
            void *cbdata;
            ctrlp->done_handler = NULL;

            if (cbdataReferenceValidDone(ctrlp->done_handler_data, &cbdata)) {
                retval = 1;	/* Return that we've actually done some work */
                done_callback(ctrlp->fd, cbdata, ctrlp->bufp,
                              ctrlp->result.aio_return, ctrlp->result.aio_errno);
            } else {
                if (ctrlp->operation == _AIO_OPEN) {
                    /* The open operation was aborted.. */
                    int fd = ctrlp->result.aio_return;

                    if (fd >= 0)
                        aioClose(fd);
                }
            }
        }

        /* free data if requested to aioWrite() */
        if (ctrlp->free_func)
            ctrlp->free_func(ctrlp->bufp);

        /* free temporary read buffer */
        if (ctrlp->operation == _AIO_READ)
            squidaio_xfree(ctrlp->bufp, ctrlp->len);

        squidaio_ctrl_pool->free(ctrlp);
    }

    return retval;
}

/* Flush all pending I/O */
void
DiskThreadsIOStrategy::sync()
{
    if (!initialised)
        return;			/* nothing to do then */

    /* Flush all pending operations */
    debugs(32, 1, "aioSync: flushing pending I/O operations");

    do {
        callback();
    } while (squidaio_sync());

    debugs(32, 1, "aioSync: done");
}

DiskThreadsIOStrategy::DiskThreadsIOStrategy() :  initialised (false) {}

void
DiskThreadsIOStrategy::aioStats(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "ASYNC IO Counters:\n");
    storeAppendPrintf(sentry, "Operation\t# Requests\tNumber serviced\n");
    storeAppendPrintf(sentry, "open\t%d\t%d\n", squidaio_counts.open_start, squidaio_counts.open_finish);
    storeAppendPrintf(sentry, "close\t%d\t%d\n", squidaio_counts.close_start, squidaio_counts.close_finish);
    storeAppendPrintf(sentry, "cancel\t%d\t-\n", squidaio_counts.cancel);
    storeAppendPrintf(sentry, "write\t%d\t%d\n", squidaio_counts.write_start, squidaio_counts.write_finish);
    storeAppendPrintf(sentry, "read\t%d\t%d\n", squidaio_counts.read_start, squidaio_counts.read_finish);
    storeAppendPrintf(sentry, "stat\t%d\t%d\n", squidaio_counts.stat_start, squidaio_counts.stat_finish);
    storeAppendPrintf(sentry, "unlink\t%d\t%d\n", squidaio_counts.unlink_start, squidaio_counts.unlink_finish);
    storeAppendPrintf(sentry, "check_callback\t%d\t-\n", squidaio_counts.check_callback);
    storeAppendPrintf(sentry, "queue\t%d\t-\n", squidaio_get_queue_len());
    squidaio_stats(sentry);
}

DiskThreadsIOStrategy DiskThreadsIOStrategy::Instance;
bool
DiskThreadsIOStrategy::shedLoad()
{
    /*
     * we should detect some 'too many files open' condition and return
     * NULL here.
     */
#ifdef MAGIC2

    if (aioQueueSize() > MAGIC2)
        return true;

#endif

    return false;
}

int
DiskThreadsIOStrategy::load()
{
    int loadav;
    int ql;

    ql = aioQueueSize();

    if (ql == 0)
        loadav = 0;

    loadav = ql * 1000 / MAGIC1;

    debugs(47, 9, "DiskThreadsIOStrategy::load: load=" << loadav);

    return loadav;
}

DiskFile::Pointer
DiskThreadsIOStrategy::newFile (char const *path)
{
    if (shedLoad()) {
        return NULL;
    }

    return new DiskThreadsDiskFile (path, this);
}

void
DiskThreadsIOStrategy::unlinkFile(char const *path)
{
    statCounter.syscalls.disk.unlinks++;
    aioUnlink(path, NULL, NULL);
}
