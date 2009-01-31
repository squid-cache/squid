
/*
 * $Id$
 *
 * DEBUG: section 6     Disk I/O Routines
 * AUTHOR: Harvest Derived
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
#include "fde.h"
#include "MemBuf.h"

static PF diskHandleRead;
static PF diskHandleWrite;

#if defined(_SQUID_WIN32_) || defined(_SQUID_OS2_)
static int
diskWriteIsComplete(int fd)
{
    return fd_table[fd].disk.write_q ? 0 : 1;
}

#endif

void
disk_init(void)
{
    (void) 0;
}

/*
 * opens a disk file specified by 'path'.  This function always
 * blocks!  There is no callback.
 */
int
file_open(const char *path, int mode)
{
    int fd;
    PROF_start(file_open);

    if (FILE_MODE(mode) == O_WRONLY)
        mode |= O_APPEND;

    errno = 0;

    fd = open(path, mode, 0644);

    statCounter.syscalls.disk.opens++;

    if (fd < 0) {
        debugs(50, 3, "file_open: error opening file " << path << ": " << xstrerror());
        fd = DISK_ERROR;
    } else {
        debugs(6, 5, "file_open: FD " << fd);
        commSetCloseOnExec(fd);
        fd_open(fd, FD_FILE, path);
    }

    PROF_stop(file_open);
    return fd;
}


/* close a disk file. */
void
file_close(int fd)
{
    fde *F = &fd_table[fd];
    PF *read_callback;
    PROF_start(file_close);
    assert(fd >= 0);
    assert(F->flags.open);

    if ((read_callback = F->read_handler)) {
        F->read_handler = NULL;
        read_callback(-1, F->read_data);
    }

    if (F->flags.write_daemon) {
#if defined(_SQUID_WIN32_) || defined(_SQUID_OS2_)
        /*
         * on some operating systems, you can not delete or rename
         * open files, so we won't allow delayed close.
         */

        while (!diskWriteIsComplete(fd))
            diskHandleWrite(fd, NULL);

#else

        F->flags.close_request = 1;

        debugs(6, 2, "file_close: FD " << fd << ", delaying close");

        PROF_stop(file_close);

        return;

#endif

    }

    /*
     * Assert there is no write callback.  Otherwise we might be
     * leaking write state data by closing the descriptor
     */
    assert(F->write_handler == NULL);

#if CALL_FSYNC_BEFORE_CLOSE

    fsync(fd);

#endif

    close(fd);

    debugs(6, F->flags.close_request ? 2 : 5, "file_close: FD " << fd << " really closing\n");

    fd_close(fd);

    statCounter.syscalls.disk.closes++;

    PROF_stop(file_close);
}

/*
 * This function has the purpose of combining multiple writes.  This is
 * to facilitate the ASYNC_IO option since it can only guarantee 1
 * write to a file per trip around the comm.c select() loop. That's bad
 * because more than 1 write can be made to the access.log file per
 * trip, and so this code is purely designed to help batch multiple
 * sequential writes to the access.log file.  Squid will never issue
 * multiple writes for any other file type during 1 trip around the
 * select() loop.       --SLF
 */
static void

diskCombineWrites(struct _fde_disk *fdd)
{
    int len = 0;
    dwrite_q *q = NULL;
    dwrite_q *wq = NULL;
    /*
     * We need to combine multiple write requests on an FD's write
     * queue But only if we don't need to seek() in between them, ugh!
     * XXX This currently ignores any seeks (file_offset)
     */

    if (fdd->write_q != NULL && fdd->write_q->next != NULL) {
        len = 0;

        for (q = fdd->write_q; q != NULL; q = q->next)
            len += q->len - q->buf_offset;

        wq = (dwrite_q *)memAllocate(MEM_DWRITE_Q);

        wq->buf = (char *)xmalloc(len);

        wq->len = 0;

        wq->buf_offset = 0;

        wq->next = NULL;

        wq->free_func = xfree;

        do {
            q = fdd->write_q;
            len = q->len - q->buf_offset;
            xmemcpy(wq->buf + wq->len, q->buf + q->buf_offset, len);
            wq->len += len;
            fdd->write_q = q->next;

            if (q->free_func)
                (q->free_func) (q->buf);

            if (q) {
                memFree(q, MEM_DWRITE_Q);
                q = NULL;
            }
        } while (fdd->write_q != NULL);

        fdd->write_q_tail = wq;

        fdd->write_q = wq;
    }
}

/* write handler */
static void
diskHandleWrite(int fd, void *notused)
{
    int len = 0;
    fde *F = &fd_table[fd];

    struct _fde_disk *fdd = &F->disk;
    dwrite_q *q = fdd->write_q;
    int status = DISK_OK;
    int do_close;

    if (NULL == q)
        return;

    PROF_start(diskHandleWrite);

    debugs(6, 3, "diskHandleWrite: FD " << fd);

    F->flags.write_daemon = 0;

    assert(fdd->write_q != NULL);

    assert(fdd->write_q->len > fdd->write_q->buf_offset);

    debugs(6, 3, "diskHandleWrite: FD " << fd << " writing " << (fdd->write_q->len - fdd->write_q->buf_offset) << " bytes");

    errno = 0;

    if (fdd->write_q->file_offset != -1)
        lseek(fd, fdd->write_q->file_offset, SEEK_SET);

    len = FD_WRITE_METHOD(fd,
                          fdd->write_q->buf + fdd->write_q->buf_offset,
                          fdd->write_q->len - fdd->write_q->buf_offset);

    debugs(6, 3, "diskHandleWrite: FD " << fd << " len = " << len);

    statCounter.syscalls.disk.writes++;

    fd_bytes(fd, len, FD_WRITE);

    if (len < 0) {
        if (!ignoreErrno(errno)) {
            status = errno == ENOSPC ? DISK_NO_SPACE_LEFT : DISK_ERROR;
            debugs(50, 1, "diskHandleWrite: FD " << fd << ": disk write error: " << xstrerror());

            /*
             * If there is no write callback, then this file is
             * most likely something important like a log file, or
             * an interprocess pipe.  Its not a swapfile.  We feel
             * that a write failure on a log file is rather important,
             * and Squid doesn't otherwise deal with this condition.
             * So to get the administrators attention, we exit with
             * a fatal message.
             */

            if (fdd->wrt_handle == NULL)
                fatal("Write failure -- check your disk space and cache.log");

            /*
             * If there is a write failure, then we notify the
             * upper layer via the callback, at the end of this
             * function.  Meanwhile, flush all pending buffers
             * here.  Let the upper layer decide how to handle the
             * failure.  This will prevent experiencing multiple,
             * repeated write failures for the same FD because of
             * the queued data.
             */
            do {
                fdd->write_q = q->next;

                if (q->free_func)
                    (q->free_func) (q->buf);

                if (q) {
                    memFree(q, MEM_DWRITE_Q);
                    q = NULL;
                }
            } while ((q = fdd->write_q));
        }

        len = 0;
    }

    if (q != NULL) {
        /* q might become NULL from write failure above */
        q->buf_offset += len;

        if (q->buf_offset > q->len)
            debugs(50, 1, "diskHandleWriteComplete: q->buf_offset > q->len (" <<
                   q << "," << (int) q->buf_offset << ", " << q->len << ", " <<
                   len << " FD " << fd << ")");


        assert(q->buf_offset <= q->len);

        if (q->buf_offset == q->len) {
            /* complete write */
            fdd->write_q = q->next;

            if (q->free_func)
                (q->free_func) (q->buf);

            if (q) {
                memFree(q, MEM_DWRITE_Q);
                q = NULL;
            }
        }
    }

    if (fdd->write_q == NULL) {
        /* no more data */
        fdd->write_q_tail = NULL;
    } else {
        /* another block is queued */
        diskCombineWrites(fdd);
        commSetSelect(fd, COMM_SELECT_WRITE, diskHandleWrite, NULL, 0);
        F->flags.write_daemon = 1;
    }

    do_close = F->flags.close_request;

    if (fdd->wrt_handle) {
        DWCB *callback = fdd->wrt_handle;
        void *cbdata;
        fdd->wrt_handle = NULL;

        if (cbdataReferenceValidDone(fdd->wrt_handle_data, &cbdata)) {
            callback(fd, status, len, cbdata);
            /*
             * NOTE, this callback can close the FD, so we must
             * not touch 'F', 'fdd', etc. after this.
             */
            PROF_stop(diskHandleWrite);
            return;
            /* XXX But what about close_request??? */
        }
    }

    if (do_close)
        file_close(fd);

    PROF_stop(diskHandleWrite);
}


/* write block to a file */
/* write back queue. Only one writer at a time. */
/* call a handle when writing is complete. */
void
file_write(int fd,
           off_t file_offset,
           void const *ptr_to_buf,
           int len,
           DWCB * handle,
           void *handle_data,
           FREE * free_func)
{
    dwrite_q *wq = NULL;
    fde *F = &fd_table[fd];
    PROF_start(file_write);
    assert(fd >= 0);
    assert(F->flags.open);
    /* if we got here. Caller is eligible to write. */
    wq = (dwrite_q *)memAllocate(MEM_DWRITE_Q);
    wq->file_offset = file_offset;
    wq->buf = (char *)ptr_to_buf;
    wq->len = len;
    wq->buf_offset = 0;
    wq->next = NULL;
    wq->free_func = free_func;

    if (!F->disk.wrt_handle_data) {
        F->disk.wrt_handle = handle;
        F->disk.wrt_handle_data = cbdataReference(handle_data);
    } else {
        /* Detect if there is multiple concurrent users of this fd.. we only support one callback */
        assert(F->disk.wrt_handle_data == handle_data && F->disk.wrt_handle == handle);
    }

    /* add to queue */
    if (F->disk.write_q == NULL) {
        /* empty queue */
        F->disk.write_q = F->disk.write_q_tail = wq;
    } else {
        F->disk.write_q_tail->next = wq;
        F->disk.write_q_tail = wq;
    }

    if (!F->flags.write_daemon) {
        diskHandleWrite(fd, NULL);
    }

    PROF_stop(file_write);
}

/*
 * a wrapper around file_write to allow for MemBuf to be file_written
 * in a snap
 */
void
file_write_mbuf(int fd, off_t off, MemBuf mb, DWCB * handler, void *handler_data)
{
    file_write(fd, off, mb.buf, mb.size, handler, handler_data, mb.freeFunc());
}

/* Read from FD */
static void
diskHandleRead(int fd, void *data)
{
    dread_ctrl *ctrl_dat = (dread_ctrl *)data;
    fde *F = &fd_table[fd];
    int len;
    int rc = DISK_OK;
    /*
     * FD < 0 indicates premature close; we just have to free
     * the state data.
     */

    if (fd < 0) {
        memFree(ctrl_dat, MEM_DREAD_CTRL);
        return;
    }

    PROF_start(diskHandleRead);

    if (F->disk.offset != ctrl_dat->offset) {
        debugs(6, 3, "diskHandleRead: FD " << fd << " seeking to offset " << ctrl_dat->offset);
        lseek(fd, ctrl_dat->offset, SEEK_SET);	/* XXX ignore return? */
        statCounter.syscalls.disk.seeks++;
        F->disk.offset = ctrl_dat->offset;
    }

    errno = 0;
    len = FD_READ_METHOD(fd, ctrl_dat->buf, ctrl_dat->req_len);

    if (len > 0)
        F->disk.offset += len;

    statCounter.syscalls.disk.reads++;

    fd_bytes(fd, len, FD_READ);

    if (len < 0) {
        if (ignoreErrno(errno)) {
            commSetSelect(fd, COMM_SELECT_READ, diskHandleRead, ctrl_dat, 0);
            PROF_stop(diskHandleRead);
            return;
        }

        debugs(50, 1, "diskHandleRead: FD " << fd << ": " << xstrerror());
        len = 0;
        rc = DISK_ERROR;
    } else if (len == 0) {
        rc = DISK_EOF;
    }

    if (cbdataReferenceValid(ctrl_dat->client_data))
        ctrl_dat->handler(fd, ctrl_dat->buf, len, rc, ctrl_dat->client_data);

    cbdataReferenceDone(ctrl_dat->client_data);

    memFree(ctrl_dat, MEM_DREAD_CTRL);

    PROF_stop(diskHandleRead);
}


/* start read operation */
/* buffer must be allocated from the caller.
 * It must have at least req_len space in there.
 * call handler when a reading is complete. */
void
file_read(int fd, char *buf, int req_len, off_t offset, DRCB * handler, void *client_data)
{
    dread_ctrl *ctrl_dat;
    PROF_start(file_read);
    assert(fd >= 0);
    ctrl_dat = (dread_ctrl *)memAllocate(MEM_DREAD_CTRL);
    ctrl_dat->fd = fd;
    ctrl_dat->offset = offset;
    ctrl_dat->req_len = req_len;
    ctrl_dat->buf = buf;
    ctrl_dat->end_of_file = 0;
    ctrl_dat->handler = handler;
    ctrl_dat->client_data = cbdataReference(client_data);
    diskHandleRead(fd, ctrl_dat);
    PROF_stop(file_read);
}

void
safeunlink(const char *s, int quiet)
{
    statCounter.syscalls.disk.unlinks++;

    if (unlink(s) < 0 && !quiet)
        debugs(50, 1, "safeunlink: Couldn't delete " << s << ": " << xstrerror());
}

/*
 * Same as rename(2) but complains if something goes wrong;
 * the caller is responsible for handing and explaining the
 * consequences of errors.
 */
int
xrename(const char *from, const char *to)
{
    debugs(21, 2, "xrename: renaming " << from << " to " << to);
#if defined (_SQUID_OS2_) || defined (_SQUID_WIN32_)

    remove
    (to);

#endif

    if (0 == rename(from, to))
        return 0;

    debugs(21, errno == ENOENT ? 2 : 1, "xrename: Cannot rename " << from << " to " << to << ": " << xstrerror());

    return -1;
}

