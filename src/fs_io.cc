/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 06    Disk I/O Routines */

#include "squid.h"
#include "comm/Loops.h"
#include "fd.h"
#include "fde.h"
#include "fs_io.h"
#include "globals.h"
#include "MemBuf.h"
#include "profiler/Profiler.h"
#include "StatCounters.h"

#include <cerrno>

static PF diskHandleRead;
static PF diskHandleWrite;

#if _SQUID_WINDOWS_ || _SQUID_OS2_
static int
diskWriteIsComplete(int fd)
{
    return fd_table[fd].disk.write_q ? 0 : 1;
}

#endif

/* hack needed on SunStudio to avoid linkage convention mismatch */
static void cxx_xfree(void *ptr)
{
    xfree(ptr);
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

    ++ statCounter.syscalls.disk.opens;

    if (fd < 0) {
        int xerrno = errno;
        debugs(50, 3, "error opening file " << path << ": " << xstrerr(xerrno));
        fd = DISK_ERROR;
    } else {
        debugs(6, 5, "FD " << fd);
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
#if _SQUID_WINDOWS_ || _SQUID_OS2_
        /*
         * on some operating systems, you can not delete or rename
         * open files, so we won't allow delayed close.
         */
        while (!diskWriteIsComplete(fd))
            diskHandleWrite(fd, NULL);
#else
        F->flags.close_request = true;
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

    debugs(6, F->flags.close_request ? 2 : 5, "file_close: FD " << fd << " really closing");

    fd_close(fd);

    ++ statCounter.syscalls.disk.closes;

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
diskCombineWrites(_fde_disk *fdd)
{
    /*
     * We need to combine multiple write requests on an FD's write
     * queue But only if we don't need to seek() in between them, ugh!
     * XXX This currently ignores any seeks (file_offset)
     */

    if (fdd->write_q != NULL && fdd->write_q->next != NULL) {
        int len = 0;

        for (dwrite_q *q = fdd->write_q; q != NULL; q = q->next)
            len += q->len - q->buf_offset;

        dwrite_q *wq = (dwrite_q *)memAllocate(MEM_DWRITE_Q);

        wq->buf = (char *)xmalloc(len);

        wq->len = 0;

        wq->buf_offset = 0;

        wq->next = NULL;

        wq->free_func = cxx_xfree;

        while (fdd->write_q != NULL) {
            dwrite_q *q = fdd->write_q;

            len = q->len - q->buf_offset;
            memcpy(wq->buf + wq->len, q->buf + q->buf_offset, len);
            wq->len += len;
            fdd->write_q = q->next;

            if (q->free_func)
                q->free_func(q->buf);

            memFree(q, MEM_DWRITE_Q);
        };

        fdd->write_q_tail = wq;

        fdd->write_q = wq;
    }
}

/* write handler */
static void
diskHandleWrite(int fd, void *)
{
    int len = 0;
    fde *F = &fd_table[fd];

    _fde_disk *fdd = &F->disk;
    dwrite_q *q = fdd->write_q;
    int status = DISK_OK;
    bool do_close;

    if (NULL == q)
        return;

    PROF_start(diskHandleWrite);

    debugs(6, 3, "diskHandleWrite: FD " << fd);

    F->flags.write_daemon = false;

    assert(fdd->write_q != NULL);

    assert(fdd->write_q->len > fdd->write_q->buf_offset);

    debugs(6, 3, "diskHandleWrite: FD " << fd << " writing " <<
           (fdd->write_q->len - fdd->write_q->buf_offset) << " bytes at " <<
           fdd->write_q->file_offset);

    errno = 0;

    if (fdd->write_q->file_offset != -1) {
        errno = 0;
        if (lseek(fd, fdd->write_q->file_offset, SEEK_SET) == -1) {
            int xerrno = errno;
            debugs(50, DBG_IMPORTANT, "error in seek for FD " << fd << ": " << xstrerr(xerrno));
            // XXX: handle error?
        }
    }

    len = FD_WRITE_METHOD(fd,
                          fdd->write_q->buf + fdd->write_q->buf_offset,
                          fdd->write_q->len - fdd->write_q->buf_offset);

    debugs(6, 3, "diskHandleWrite: FD " << fd << " len = " << len);

    ++ statCounter.syscalls.disk.writes;

    fd_bytes(fd, len, FD_WRITE);

    if (len < 0) {
        if (!ignoreErrno(errno)) {
            status = errno == ENOSPC ? DISK_NO_SPACE_LEFT : DISK_ERROR;
            int xerrno = errno;
            debugs(50, DBG_IMPORTANT, "diskHandleWrite: FD " << fd << ": disk write error: " << xstrerr(xerrno));

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
                    q->free_func(q->buf);

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
            debugs(50, DBG_IMPORTANT, "diskHandleWriteComplete: q->buf_offset > q->len (" <<
                   q << "," << (int) q->buf_offset << ", " << q->len << ", " <<
                   len << " FD " << fd << ")");

        assert(q->buf_offset <= q->len);

        if (q->buf_offset == q->len) {
            /* complete write */
            fdd->write_q = q->next;

            if (q->free_func)
                q->free_func(q->buf);

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
        Comm::SetSelect(fd, COMM_SELECT_WRITE, diskHandleWrite, NULL, 0);
        F->flags.write_daemon = true;
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
    int xerrno;

    /*
     * FD < 0 indicates premature close; we just have to free
     * the state data.
     */

    if (fd < 0) {
        memFree(ctrl_dat, MEM_DREAD_CTRL);
        return;
    }

    PROF_start(diskHandleRead);

#if WRITES_MAINTAIN_DISK_OFFSET
    if (F->disk.offset != ctrl_dat->offset) {
#else
    {
#endif
        debugs(6, 3, "diskHandleRead: FD " << fd << " seeking to offset " << ctrl_dat->offset);
        errno = 0;
        if (lseek(fd, ctrl_dat->offset, SEEK_SET) == -1) {
            xerrno = errno;
            // shouldn't happen, let's detect that
            debugs(50, DBG_IMPORTANT, "error in seek for FD " << fd << ": " << xstrerr(xerrno));
            // XXX handle failures?
        }
        ++ statCounter.syscalls.disk.seeks;
        F->disk.offset = ctrl_dat->offset;
    }

    errno = 0;
    len = FD_READ_METHOD(fd, ctrl_dat->buf, ctrl_dat->req_len);
    xerrno = errno;

    if (len > 0)
        F->disk.offset += len;

    ++ statCounter.syscalls.disk.reads;

    fd_bytes(fd, len, FD_READ);

    if (len < 0) {
        if (ignoreErrno(xerrno)) {
            Comm::SetSelect(fd, COMM_SELECT_READ, diskHandleRead, ctrl_dat, 0);
            PROF_stop(diskHandleRead);
            return;
        }

        debugs(50, DBG_IMPORTANT, "diskHandleRead: FD " << fd << ": " << xstrerr(xerrno));
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
    ++ statCounter.syscalls.disk.unlinks;

    if (unlink(s) < 0 && !quiet) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "safeunlink: Couldn't delete " << s << ": " << xstrerr(xerrno));
    }
}

bool
FileRename(const SBuf &from, const SBuf &to)
{
    debugs(21, 2, "renaming " << from << " to " << to);

    // non-const copy for c_str()
    SBuf from2(from);
    // ensure c_str() lifetimes even if `to` and `from` share memory
    SBuf to2(to.rawContent(), to.length());

#if _SQUID_OS2_ || _SQUID_WINDOWS_
    remove(to2.c_str());
#endif

    if (rename(from2.c_str(), to2.c_str()) == 0)
        return true;

    int xerrno = errno;
    debugs(21, (errno == ENOENT ? 2 : DBG_IMPORTANT), "Cannot rename " << from << " to " << to << ": " << xstrerr(xerrno));

    return false;
}

int
fsBlockSize(const char *path, int *blksize)
{
    struct statvfs sfs;

    if (xstatvfs(path, &sfs)) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "" << path << ": " << xstrerr(xerrno));
        *blksize = 2048;
        return 1;
    }

    *blksize = (int) sfs.f_frsize;

    // Sanity check; make sure we have a meaningful value.
    if (*blksize < 512)
        *blksize = 2048;

    return 0;
}

#define fsbtoblk(num, fsbs, bs) \
    (((fsbs) != 0 && (fsbs) < (bs)) ? \
            (num) / ((bs) / (fsbs)) : (num) * ((fsbs) / (bs)))
int
fsStats(const char *path, int *totl_kb, int *free_kb, int *totl_in, int *free_in)
{
    struct statvfs sfs;

    if (xstatvfs(path, &sfs)) {
        int xerrno = errno;
        debugs(50, DBG_IMPORTANT, "" << path << ": " << xstrerr(xerrno));
        return 1;
    }

    *totl_kb = (int) fsbtoblk(sfs.f_blocks, sfs.f_frsize, 1024);
    *free_kb = (int) fsbtoblk(sfs.f_bfree, sfs.f_frsize, 1024);
    *totl_in = (int) sfs.f_files;
    *free_in = (int) sfs.f_ffree;
    return 0;
}

