/*
 * $Id: disk.cc,v 1.58 1997/04/28 04:23:03 wessels Exp $
 *
 * DEBUG: section 6     Disk I/O Routines
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "squid.h"

#define DISK_LINE_LEN  1024

typedef struct disk_ctrl_t {
    int fd;
    void *data;
} disk_ctrl_t;


typedef struct open_ctrl_t {
    void (*callback) ();
    void *callback_data;
    char *path;
} open_ctrl_t;


typedef struct _dwalk_ctrl {
    int fd;
    off_t offset;
    char *buf;			/* line buffer */
    int cur_len;		/* line len */
    FILE_WALK_HD handler;
    void *client_data;
    int (*line_handler) (int fd, char *buf, int size, void *line_data);
    void *line_data;
} dwalk_ctrl;

/* table for FILE variable, write lock and queue. Indexed by fd. */
FileEntry *file_table;

static int diskHandleRead _PARAMS((int, dread_ctrl *));
static int diskHandleWalk _PARAMS((int, dwalk_ctrl *));
static int diskHandleWrite _PARAMS((int, FileEntry *));
static int diskHandleWriteComplete _PARAMS((void *, int, int));
static int diskHandleReadComplete _PARAMS((void *, int, int));
static int diskHandleWalkComplete _PARAMS((void *, int, int));
static void file_open_complete _PARAMS((void *, int, int));

/* initialize table */
int
disk_init(void)
{
    int fd;

    file_table = xcalloc(Squid_MaxFD, sizeof(FileEntry));
    meta_data.misc += Squid_MaxFD * sizeof(FileEntry);
    for (fd = 0; fd < Squid_MaxFD; fd++) {
	file_table[fd].filename[0] = '\0';
	file_table[fd].at_eof = NO;
	file_table[fd].open_stat = FILE_NOT_OPEN;
	file_table[fd].close_request = NOT_REQUEST;
	file_table[fd].write_daemon = NOT_PRESENT;
	file_table[fd].write_pending = NO_WRT_PENDING;
	file_table[fd].write_q = file_table[fd].write_q_tail = NULL;
    }
    return 0;
}

/* Open a disk file. Return a file descriptor */
int
file_open(const char *path, int (*handler) _PARAMS((void)), int mode, void (*callback) (), void *callback_data)
{
    int fd;
    open_ctrl_t *ctrlp;

    ctrlp = xmalloc(sizeof(open_ctrl_t));
    ctrlp->path = xstrdup(path);
    ctrlp->callback = callback;
    ctrlp->callback_data = callback_data;

    if (mode & O_WRONLY)
	mode |= O_APPEND;
#if defined(O_NONBLOCK) && !defined(_SQUID_SUNOS_) && !defined(_SQUID_SOLARIS_)
    mode |= O_NONBLOCK;
#else
    mode |= O_NDELAY;
#endif

    /* Open file */
#if USE_ASYNC_IO
    if (callback == NULL) {
	fd = open(path, mode, 0644);
	file_open_complete(ctrlp, fd, errno);
	if (fd < 0)
	    return DISK_ERROR;
	return fd;
    }
    aioOpen(path, mode, 0644, file_open_complete, ctrlp);
    return DISK_OK;
#else
    fd = open(path, mode, 0644);
    file_open_complete(ctrlp, fd, errno);
    if (fd < 0)
	return DISK_ERROR;
    return fd;
#endif
}


static void
file_open_complete(void *data, int retcode, int errcode)
{
    open_ctrl_t *ctrlp = (open_ctrl_t *) data;
    FD_ENTRY *conn;
    int fd;

    fd = retcode;
    if (fd < 0) {
	errno = errcode;
	debug(50, 0, "file_open: error opening file %s: %s\n", ctrlp->path,
	    xstrerror());
	if (ctrlp->callback)
	    (ctrlp->callback) (ctrlp->callback_data, DISK_ERROR);
	xfree(ctrlp->path);
	xfree(ctrlp);
	return;
    }
    /* update fdstat */
    fdstat_open(fd, FD_FILE);
    commSetCloseOnExec(fd);

    /* init table */
    xstrncpy(file_table[fd].filename, ctrlp->path, SQUID_MAXPATHLEN);
    file_table[fd].at_eof = NO;
    file_table[fd].open_stat = FILE_OPEN;
    file_table[fd].close_request = NOT_REQUEST;
    file_table[fd].write_pending = NO_WRT_PENDING;
    file_table[fd].write_daemon = NOT_PRESENT;
    file_table[fd].write_q = NULL;

    conn = &fd_table[fd];
    memset(conn, '\0', sizeof(FD_ENTRY));
    if (ctrlp->callback)
	(ctrlp->callback) (ctrlp->callback_data, fd);
    xfree(ctrlp->path);
    xfree(ctrlp);
}

/* must close a disk file */

int
file_must_close(int fd)
{
    FileEntry *entry;
    dwrite_q *q = NULL;
    if (fdstatGetType(fd) != FD_FILE)
	fatal_dump("file_must_close: NOT A FILE");
    entry = &file_table[fd];
    if (entry->open_stat == FILE_NOT_OPEN)
	return DISK_OK;
    entry->close_request = REQUEST;
    entry->write_daemon = NOT_PRESENT;
    entry->write_pending = NO_WRT_PENDING;
    /* Drain queue */
    while (entry->write_q) {
	q = entry->write_q;
	entry->write_q = q->next;
	if (q->free)
	    (q->free) (q->buf);
	safe_free(q);
    }
    entry->write_q_tail = NULL;
    if (entry->wrt_handle)
	entry->wrt_handle(fd, DISK_ERROR, entry->wrt_handle_data);
    commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
    commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
    file_close(fd);
    return DISK_OK;
}

void
file_open_fd(int fd, const char *name, File_Desc_Type type)
{
    FileEntry *f = &file_table[fd];
    fdstat_open(fd, type);
    commSetCloseOnExec(fd);
    xstrncpy(f->filename, name, SQUID_MAXPATHLEN);
    f->at_eof = NO;
    f->open_stat = FILE_OPEN;
    f->close_request = NOT_REQUEST;
    f->write_pending = NO_WRT_PENDING;
    f->write_daemon = NOT_PRESENT;
    f->write_q = NULL;
    memset(&fd_table[fd], '\0', sizeof(FD_ENTRY));
}


/* close a disk file. */
int
file_close(int fd)
{
    FD_ENTRY *conn = NULL;
    if (fd < 0) {
	debug_trap("file_close: bad file number");
	return DISK_ERROR;
    }
    /* we might have to flush all the write back queue before we can
     * close it */
    /* save it for later */

    if (file_table[fd].open_stat == FILE_NOT_OPEN) {
	debug(6, 3, "file_close: FD %d is not OPEN\n", fd);
    } else if (file_table[fd].write_daemon == PRESENT) {
	debug(6, 3, "file_close: FD %d has a write daemon PRESENT\n", fd);
    } else if (file_table[fd].write_pending == WRT_PENDING) {
	debug(6, 3, "file_close: FD %d has a write PENDING\n", fd);
    } else {
	file_table[fd].open_stat = FILE_NOT_OPEN;
	file_table[fd].write_daemon = NOT_PRESENT;
	file_table[fd].filename[0] = '\0';

	if (fdstatGetType(fd) == FD_SOCKET) {
	    debug(6, 0, "FD %d: Someone called file_close() on a socket\n", fd);
	    fatal_dump(NULL);
	}
	/* update fdstat */
	fdstat_close(fd);
	conn = &fd_table[fd];
	memset(conn, '\0', sizeof(FD_ENTRY));
	comm_set_fd_lifetime(fd, -1);	/* invalidate the lifetime */
#if USE_ASYNC_IO
	aioClose(fd);
#else
	close(fd);
#endif
	return DISK_OK;
    }

    /* refused to close file if there is a daemon running */
    /* have pending flag set */
    file_table[fd].close_request = REQUEST;
    return DISK_ERROR;
}


/* write handler */
static int
diskHandleWrite(int fd, FileEntry * entry)
{
    int len = 0;
    disk_ctrl_t *ctrlp;
    dwrite_q *q = NULL;
    dwrite_q *wq = NULL;
    if (!entry->write_q)
	return DISK_OK;
    if (file_table[fd].at_eof == NO)
	lseek(fd, 0, SEEK_END);
    /* We need to combine subsequent write requests after the first */
    if (entry->write_q->next != NULL && entry->write_q->next->next != NULL) {
	for (len = 0, q = entry->write_q->next; q != NULL; q = q->next)
	    len += q->len - q->cur_offset;
	wq = xcalloc(1, sizeof(dwrite_q));
	wq->buf = xmalloc(len);
	wq->len = 0;
	wq->cur_offset = 0;
	wq->next = NULL;
	wq->free = xfree;
	do {
	    q = entry->write_q->next;
	    len = q->len - q->cur_offset;
	    memcpy(wq->buf + wq->len, q->buf + q->cur_offset, len);
	    wq->len += len;
	    entry->write_q->next = q->next;
	    if (q->free)
		(q->free) (q->buf);
	    safe_free(q);
	} while (entry->write_q->next != NULL);
	entry->write_q_tail = wq;
	entry->write_q->next = wq;
    }
    ctrlp = xcalloc(1, sizeof(disk_ctrl_t));
    ctrlp->fd = fd;
    ctrlp->data = (void *) entry;
#if USE_ASYNC_IO
    aioWrite(fd,
	entry->write_q->buf + entry->write_q->cur_offset,
	entry->write_q->len - entry->write_q->cur_offset,
	diskHandleWriteComplete,
	(void *) ctrlp);
    return DISK_OK;
#else
    len = write(fd,
	entry->write_q->buf + entry->write_q->cur_offset,
	entry->write_q->len - entry->write_q->cur_offset);
    return diskHandleWriteComplete(ctrlp, len, errno);
#endif
}

static int
diskHandleWriteComplete(void *data, int retcode, int errcode)
{
    disk_ctrl_t *ctrlp = data;
    FileEntry *entry = ctrlp->data;
    dwrite_q *q = entry->write_q;
    int fd = ctrlp->fd;
    int len = retcode;
    errno = errcode;
    safe_free(data);
    if (q == NULL)		/* Someone aborted and then the write */
	return DISK_ERROR;	/* completed anyway. :( */
    file_table[fd].at_eof = YES;
    if (len < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    len = 0;
	} else {
	    /* disk i/o failure--flushing all outstanding writes  */
	    debug(50, 1, "diskHandleWrite: FD %d: disk write error: %s\n",
		fd, xstrerror());
	    entry->write_daemon = NOT_PRESENT;
	    entry->write_pending = NO_WRT_PENDING;
	    /* call finish handler */
	    do {
		entry->write_q = q->next;
		if (q->free)
		    (q->free) (q->buf);
		safe_free(q);
	    } while ((q = entry->write_q));
	    if (entry->wrt_handle) {
		entry->wrt_handle(fd,
		    errno == ENOSPC ? DISK_NO_SPACE_LEFT : DISK_ERROR,
		    entry->wrt_handle_data);
	    }
	    return DISK_ERROR;
	}
    }
    q->cur_offset += len;
    if (q->cur_offset > q->len)
	fatal_dump("diskHandleWriteComplete: offset > len");
    if (q->cur_offset == q->len) {
	/* complete write */
	entry->write_q = q->next;
	if (q->free)
	    (q->free) (q->buf);
	safe_free(q);
    }
    if (entry->write_q != NULL) {
	/* another block is queued */
	commSetSelect(fd,
	    COMM_SELECT_WRITE,
	    (PF) diskHandleWrite,
	    (void *) entry,
	    0);
	return DISK_OK;
    }
    /* no more data */
    entry->write_q = entry->write_q_tail = NULL;
    entry->write_pending = NO_WRT_PENDING;
    entry->write_daemon = NOT_PRESENT;
    if (entry->wrt_handle)
	entry->wrt_handle(fd, DISK_OK, entry->wrt_handle_data);
    if (file_table[fd].close_request == REQUEST)
	file_close(fd);
    return DISK_OK;
}


/* write block to a file */
/* write back queue. Only one writer at a time. */
/* call a handle when writing is complete. */
int
file_write(int fd,
    char *ptr_to_buf,
    int len,
    FILE_WRITE_HD handle,
    void *handle_data,
    void (*free_func) _PARAMS((void *)))
{
    dwrite_q *wq = NULL;

    if (file_table[fd].open_stat == FILE_NOT_OPEN) {
	debug_trap("file_write: FILE_NOT_OPEN");
	return DISK_ERROR;
    }
    /* if we got here. Caller is eligible to write. */
    wq = xcalloc(1, sizeof(dwrite_q));
    wq->buf = ptr_to_buf;
    wq->len = len;
    wq->cur_offset = 0;
    wq->next = NULL;
    wq->free = free_func;
    file_table[fd].wrt_handle = handle;
    file_table[fd].wrt_handle_data = handle_data;

    /* add to queue */
    file_table[fd].write_pending = WRT_PENDING;
    if (!(file_table[fd].write_q)) {
	/* empty queue */
	file_table[fd].write_q = file_table[fd].write_q_tail = wq;
    } else {
	file_table[fd].write_q_tail->next = wq;
	file_table[fd].write_q_tail = wq;
    }

    if (file_table[fd].write_daemon != PRESENT) {
#if USE_ASYNC_IO
	diskHandleWrite(fd, &file_table[fd]);
#else
	commSetSelect(fd,
	    COMM_SELECT_WRITE,
	    (PF) diskHandleWrite,
	    (void *) &file_table[fd],
	    0);
#endif
	file_table[fd].write_daemon = PRESENT;
    }
    return DISK_OK;
}



/* Read from FD */
static int
diskHandleRead(int fd, dread_ctrl * ctrl_dat)
{
    int len;
    disk_ctrl_t *ctrlp;
    ctrlp = xcalloc(1, sizeof(disk_ctrl_t));
    ctrlp->fd = fd;
    ctrlp->data = (void *) ctrl_dat;
    /* go to requested position. */
    lseek(fd, ctrl_dat->offset, SEEK_SET);
    file_table[fd].at_eof = NO;
#if USE_ASYNC_IO
    aioRead(fd,
	ctrl_dat->buf + ctrl_dat->cur_len,
	ctrl_dat->req_len - ctrl_dat->cur_len,
	diskHandleReadComplete,
	(void *) ctrlp);
    return DISK_OK;
#else
    len = read(fd,
	ctrl_dat->buf + ctrl_dat->cur_len,
	ctrl_dat->req_len - ctrl_dat->cur_len);
    return diskHandleReadComplete(ctrlp, len, errno);
#endif
}

static int
diskHandleReadComplete(void *data, int retcode, int errcode)
{
    disk_ctrl_t *ctrlp = data;
    dread_ctrl *ctrl_dat = ctrlp->data;
    int fd = ctrlp->fd;
    int len = retcode;
    errno = errcode;
    xfree(data);
    if (len < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    commSetSelect(fd,
		COMM_SELECT_READ,
		(PF) diskHandleRead,
		(void *) ctrl_dat,
		0);
	    return DISK_OK;
	}
	debug(50, 1, "diskHandleRead: FD %d: error reading: %s\n",
	    fd, xstrerror());
	ctrl_dat->handler(fd, ctrl_dat->buf,
	    ctrl_dat->cur_len,
	    DISK_ERROR,
	    ctrl_dat->client_data);
	safe_free(ctrl_dat);
	return DISK_ERROR;
    } else if (len == 0) {
	/* EOF */
	ctrl_dat->end_of_file = 1;
	/* call handler */
	ctrl_dat->handler(fd,
	    ctrl_dat->buf,
	    ctrl_dat->cur_len,
	    DISK_EOF,
	    ctrl_dat->client_data);
	safe_free(ctrl_dat);
	return DISK_OK;
    } else {
	ctrl_dat->cur_len += len;
	ctrl_dat->offset = lseek(fd, 0L, SEEK_CUR);
    }
    /* reschedule if need more data. */
    if (ctrl_dat->cur_len < ctrl_dat->req_len) {
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    (PF) diskHandleRead,
	    (void *) ctrl_dat,
	    0);
	return DISK_OK;
    } else {
	/* all data we need is here. */
	/* call handler */
	ctrl_dat->handler(fd,
	    ctrl_dat->buf,
	    ctrl_dat->cur_len,
	    DISK_OK,
	    ctrl_dat->client_data);
	safe_free(ctrl_dat);
	return DISK_OK;
    }
}


/* start read operation */
/* buffer must be allocated from the caller. 
 * It must have at least req_len space in there. 
 * call handler when a reading is complete. */
int
file_read(int fd, char *buf, int req_len, int offset, FILE_READ_HD handler, void *client_data)
{
    dread_ctrl *ctrl_dat;
    if (fd < 0)
	fatal_dump("file_read: bad FD");
    ctrl_dat = xcalloc(1, sizeof(dread_ctrl));
    ctrl_dat->fd = fd;
    ctrl_dat->offset = offset;
    ctrl_dat->req_len = req_len;
    ctrl_dat->buf = buf;
    ctrl_dat->cur_len = 0;
    ctrl_dat->end_of_file = 0;
    ctrl_dat->handler = handler;
    ctrl_dat->client_data = client_data;
#if USE_ASYNC_IO
    diskHandleRead(fd, ctrl_dat);
#else
    commSetSelect(fd,
	COMM_SELECT_READ,
	(PF) diskHandleRead,
	(void *) ctrl_dat,
	0);
#endif
    return DISK_OK;
}


/* Read from FD and pass a line to routine. Walk to EOF. */
static int
diskHandleWalk(int fd, dwalk_ctrl * walk_dat)
{
    int len;
    disk_ctrl_t *ctrlp;
    ctrlp = xcalloc(1, sizeof(disk_ctrl_t));
    ctrlp->fd = fd;
    ctrlp->data = (void *) walk_dat;

    lseek(fd, walk_dat->offset, SEEK_SET);
    file_table[fd].at_eof = NO;
#if USE_ASYNC_IO
    aioRead(fd, walk_dat->buf,
	DISK_LINE_LEN - 1,
	diskHandleWalkComplete,
	(void *) ctrlp);
    return DISK_OK;
#else
    len = read(fd, walk_dat->buf, DISK_LINE_LEN - 1);
    return diskHandleWalkComplete(ctrlp, len, errno);
#endif
}


static int
diskHandleWalkComplete(void *data, int retcode, int errcode)
{
    disk_ctrl_t *ctrlp = (disk_ctrl_t *) data;
    dwalk_ctrl *walk_dat;
    int fd;
    int len;
    LOCAL_ARRAY(char, temp_line, DISK_LINE_LEN);
    int end_pos;
    int st_pos;
    int used_bytes;

    walk_dat = (dwalk_ctrl *) ctrlp->data;
    fd = ctrlp->fd;
    len = retcode;
    errno = errcode;
    xfree(data);

    if (len < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    commSetSelect(fd, COMM_SELECT_READ, (PF) diskHandleWalk,
		(void *) walk_dat, 0);
	    return DISK_OK;
	}
	debug(50, 1, "diskHandleWalk: FD %d: error readingd: %s\n",
	    fd, xstrerror());
	walk_dat->handler(fd, DISK_ERROR, walk_dat->client_data);
	safe_free(walk_dat->buf);
	safe_free(walk_dat);
	return DISK_ERROR;
    } else if (len == 0) {
	/* EOF */
	walk_dat->handler(fd, DISK_EOF, walk_dat->client_data);
	safe_free(walk_dat->buf);
	safe_free(walk_dat);
	return DISK_OK;
    }
    /* emulate fgets here. Cut the into separate line. newline is excluded */
    /* it throws last partial line, if exist, away. */
    used_bytes = st_pos = end_pos = 0;
    while (end_pos < len) {
	if (walk_dat->buf[end_pos] == '\n') {
	    /* new line found */
	    xstrncpy(temp_line, walk_dat->buf + st_pos, end_pos - st_pos + 1);
	    used_bytes += end_pos - st_pos + 1;

	    /* invoke line handler */
	    walk_dat->line_handler(fd, temp_line, strlen(temp_line),
		walk_dat->line_data);

	    /* skip to next line */
	    st_pos = end_pos + 1;
	}
	end_pos++;
    }

    /* update file pointer to the next to be read character */
    walk_dat->offset += used_bytes;

    /* reschedule it for next line. */
    commSetSelect(fd, COMM_SELECT_READ, (PF) diskHandleWalk,
	(void *) walk_dat,
	0);
    return DISK_OK;
}


/* start walk through whole file operation 
 * read one block and chop it to a line and pass it to provided 
 * handler one line at a time.
 * call a completion handler when done. */
int
file_walk(int fd,
    FILE_WALK_HD handler,
    void *client_data,
    FILE_WALK_LHD line_handler,
    void *line_data)
{
    dwalk_ctrl *walk_dat;

    walk_dat = xcalloc(1, sizeof(dwalk_ctrl));
    walk_dat->fd = fd;
    walk_dat->offset = 0;
    walk_dat->buf = xcalloc(1, DISK_LINE_LEN);
    walk_dat->cur_len = 0;
    walk_dat->handler = handler;
    walk_dat->client_data = client_data;
    walk_dat->line_handler = line_handler;
    walk_dat->line_data = line_data;

#if USE_ASYNC_IO
    diskHandleWalk(fd, walk_dat);
#else
    commSetSelect(fd, COMM_SELECT_READ, (PF) diskHandleWalk,
	(void *) walk_dat,
	0);
#endif
    return DISK_OK;
}

char *
diskFileName(int fd)
{
    if (file_table[fd].filename[0])
	return (file_table[fd].filename);
    else
	return (0);
}

int
diskWriteIsComplete(int fd)
{
    return file_table[fd].write_q ? 0 : 1;
}

void
diskFreeMemory(void)
{
    safe_free(file_table);
}
