/*
 * $Id: disk.cc,v 1.93 1997/11/12 00:10:45 wessels Exp $
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
    FOCB *callback;
    void *callback_data;
    char *path;
} open_ctrl_t;

static AIOCB diskHandleWriteComplete;
static AIOCB diskHandleReadComplete;
static PF diskHandleRead;
static PF diskHandleWrite;
static void file_open_complete(void *, int, int);

/* initialize table */
int
disk_init(void)
{
    return 0;
}

/* Open a disk file. Return a file descriptor */
int
file_open(const char *path, int mode, FOCB * callback, void *callback_data)
{
    int fd;
    open_ctrl_t *ctrlp;

    ctrlp = xmalloc(sizeof(open_ctrl_t));
    ctrlp->path = xstrdup(path);
    ctrlp->callback = callback;
    ctrlp->callback_data = callback_data;

    if (mode & O_WRONLY)
	mode |= O_APPEND;
    mode |= SQUID_NONBLOCK;

    /* Open file */
#if USE_ASYNC_IO
    if (callback != NULL) {
	aioOpen(path, mode, 0644, file_open_complete, ctrlp);
	return DISK_OK;
    }
#endif
    fd = open(path, mode, 0644);
    file_open_complete(ctrlp, fd, errno);
    if (fd < 0)
	return DISK_ERROR;
    return fd;
}


static void
file_open_complete(void *data, int fd, int errcode)
{
    open_ctrl_t *ctrlp = (open_ctrl_t *) data;
    if (fd < 0) {
	errno = errcode;
	debug(50, 0) ("file_open: error opening file %s: %s\n", ctrlp->path,
	    xstrerror());
	if (ctrlp->callback)
	    (ctrlp->callback) (ctrlp->callback_data, DISK_ERROR);
	xfree(ctrlp->path);
	xfree(ctrlp);
	return;
    }
    debug(6, 5) ("file_open: FD %d\n", fd);
    commSetCloseOnExec(fd);
    fd_open(fd, FD_FILE, ctrlp->path);
    if (ctrlp->callback)
	(ctrlp->callback) (ctrlp->callback_data, fd);
    xfree(ctrlp->path);
    xfree(ctrlp);
}

/* close a disk file. */
void
file_close(int fd)
{
    fde *F = &fd_table[fd];
    assert(fd >= 0);
    assert(F->open);
    if (EBIT_TEST(F->flags, FD_WRITE_DAEMON)) {
	EBIT_SET(F->flags, FD_CLOSE_REQUEST);
	return;
    }
    if (EBIT_TEST(F->flags, FD_WRITE_PENDING)) {
	EBIT_SET(F->flags, FD_CLOSE_REQUEST);
	return;
    }
    fd_close(fd);
    debug(6, 5) ("file_close: FD %d\n", fd);
#if USE_ASYNC_IO
    aioClose(fd);
#else
    close(fd);
#endif
}


/* write handler */
static void
diskHandleWrite(int fd, void *notused)
{
    int len = 0;
    disk_ctrl_t *ctrlp;
    dwrite_q *q = NULL;
    dwrite_q *wq = NULL;
    fde *F = &fd_table[fd];
    struct _fde_disk *fdd = &F->disk;
    if (!fdd->write_q)
	return;
    /* We need to combine subsequent write requests after the first */
    if (fdd->write_q->next != NULL && fdd->write_q->next->next != NULL) {
	len = 0;
	for (q = fdd->write_q->next; q != NULL; q = q->next)
	    len += q->len - q->cur_offset;
	wq = xcalloc(1, sizeof(dwrite_q));
	wq->buf = xmalloc(len);
	wq->len = 0;
	wq->cur_offset = 0;
	wq->next = NULL;
	wq->free = xfree;
	do {
	    q = fdd->write_q->next;
	    len = q->len - q->cur_offset;
	    xmemcpy(wq->buf + wq->len, q->buf + q->cur_offset, len);
	    wq->len += len;
	    fdd->write_q->next = q->next;
	    if (q->free)
		(q->free) (q->buf);
	    safe_free(q);
	} while (fdd->write_q->next != NULL);
	fdd->write_q_tail = wq;
	fdd->write_q->next = wq;
    }
    ctrlp = xcalloc(1, sizeof(disk_ctrl_t));
    ctrlp->fd = fd;
    assert(fdd->write_q != NULL);
    assert(fdd->write_q->len > fdd->write_q->cur_offset);
#if USE_ASYNC_IO
    aioWrite(fd,
	fdd->write_q->buf + fdd->write_q->cur_offset,
	fdd->write_q->len - fdd->write_q->cur_offset,
	diskHandleWriteComplete,
	ctrlp);
#else
    len = write(fd,
	fdd->write_q->buf + fdd->write_q->cur_offset,
	fdd->write_q->len - fdd->write_q->cur_offset);
    diskHandleWriteComplete(ctrlp, len, errno);
#endif
}

static void
diskHandleWriteComplete(void *data, int len, int errcode)
{
    disk_ctrl_t *ctrlp = data;
    int fd = ctrlp->fd;
    fde *F = &fd_table[fd];
    struct _fde_disk *fdd = &F->disk;
    dwrite_q *q = fdd->write_q;
    int status = DISK_OK;
    errno = errcode;
    safe_free(data);
    fd_bytes(fd, len, FD_WRITE);
    if (q == NULL)		/* Someone aborted then write completed */
	return;
    if (len < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    (void) 0;
	} else {
	    status = errno == ENOSPC ? DISK_NO_SPACE_LEFT : DISK_ERROR;
	    debug(50, 1) ("diskHandleWrite: FD %d: disk write error: %s\n",
		fd, xstrerror());
	    if (fdd->wrt_handle == NULL) {
		/* FLUSH PENDING BUFFERS */
		do {
		    fdd->write_q = q->next;
		    if (q->free)
			(q->free) (q->buf);
		    safe_free(q);
		} while ((q = fdd->write_q));
	    }
	}
	len = 0;
    }
    if (q != NULL) {
	/* q might become NULL from write failure above */
	q->cur_offset += len;
	assert(q->cur_offset <= q->len);
	if (q->cur_offset == q->len) {
	    /* complete write */
	    fdd->write_q = q->next;
	    if (q->free)
		(q->free) (q->buf);
	    safe_free(q);
	}
    }
    if (fdd->write_q == NULL) {
	/* no more data */
	fdd->write_q_tail = NULL;
	EBIT_CLR(F->flags, FD_WRITE_PENDING);
	EBIT_CLR(F->flags, FD_WRITE_DAEMON);
    } else {
	/* another block is queued */
	commSetSelect(fd, COMM_SELECT_WRITE, diskHandleWrite, NULL, 0);
	EBIT_SET(F->flags, FD_WRITE_DAEMON);
    }
    if (fdd->wrt_handle)
	fdd->wrt_handle(fd, status, len, fdd->wrt_handle_data);
    if (EBIT_TEST(F->flags, FD_CLOSE_REQUEST))
	file_close(fd);
}


/* write block to a file */
/* write back queue. Only one writer at a time. */
/* call a handle when writing is complete. */
int
file_write(int fd,
    char *ptr_to_buf,
    int len,
    DWCB handle,
    void *handle_data,
    FREE * free_func)
{
    dwrite_q *wq = NULL;
    fde *F = &fd_table[fd];
    assert(fd >= 0);
    assert(F->open);
    /* if we got here. Caller is eligible to write. */
    wq = xcalloc(1, sizeof(dwrite_q));
    wq->buf = ptr_to_buf;
    wq->len = len;
    wq->cur_offset = 0;
    wq->next = NULL;
    wq->free = free_func;
    F->disk.wrt_handle = handle;
    F->disk.wrt_handle_data = handle_data;
    /* add to queue */
    EBIT_SET(F->flags, FD_WRITE_PENDING);
    if (F->disk.write_q == NULL) {
	/* empty queue */
	F->disk.write_q = F->disk.write_q_tail = wq;
    } else {
	F->disk.write_q_tail->next = wq;
	F->disk.write_q_tail = wq;
    }
    if (!EBIT_TEST(F->flags, FD_WRITE_DAEMON)) {
#if USE_ASYNC_IO
	diskHandleWrite(fd, NULL);
#else
	commSetSelect(fd, COMM_SELECT_WRITE, diskHandleWrite, NULL, 0);
#endif
	EBIT_SET(F->flags, FD_WRITE_DAEMON);
    }
    return DISK_OK;
}



/* Read from FD */
static void
diskHandleRead(int fd, void *data)
{
    dread_ctrl *ctrl_dat = data;
    fde *F = &fd_table[fd];
#if !USE_ASYNC_IO
    int len;
#endif
    disk_ctrl_t *ctrlp = xcalloc(1, sizeof(disk_ctrl_t));
    ctrlp->fd = fd;
    ctrlp->data = ctrl_dat;
#if USE_ASYNC_IO
    aioRead(fd,
	ctrl_dat->buf,
	ctrl_dat->req_len,
	diskHandleReadComplete,
	ctrlp);
#else
    if (F->disk.offset != ctrl_dat->offset) {
	debug(6, 3) ("diskHandleRead: FD %d seeking to offset %d\n",
	    fd, (int) ctrl_dat->offset);
	lseek(fd, ctrl_dat->offset, SEEK_SET);	/* XXX ignore return? */
	F->disk.offset = ctrl_dat->offset;
    }
    len = read(fd, ctrl_dat->buf, ctrl_dat->req_len);
    F->disk.offset += len;
    diskHandleReadComplete(ctrlp, len, errno);
#endif
}

static void
diskHandleReadComplete(void *data, int len, int errcode)
{
    disk_ctrl_t *ctrlp = data;
    dread_ctrl *ctrl_dat = ctrlp->data;
    int fd = ctrlp->fd;
    int rc = DISK_OK;
    errno = errcode;
    xfree(data);
    fd_bytes(fd, len, FD_READ);
    if (len < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    commSetSelect(fd, COMM_SELECT_READ, diskHandleRead, ctrl_dat, 0);
	    return;
	}
	debug(50, 1) ("diskHandleRead: FD %d: %s\n", fd, xstrerror());
	len = 0;
	rc = DISK_ERROR;
    } else if (len == 0) {
	rc = DISK_EOF;
    }
    if (cbdataValid(ctrl_dat->client_data))
	ctrl_dat->handler(fd, ctrl_dat->buf, len, rc, ctrl_dat->client_data);
    cbdataUnlock(ctrl_dat->client_data);
    safe_free(ctrl_dat);
}


/* start read operation */
/* buffer must be allocated from the caller. 
 * It must have at least req_len space in there. 
 * call handler when a reading is complete. */
int
file_read(int fd, char *buf, int req_len, int offset, DRCB * handler, void *client_data)
{
    dread_ctrl *ctrl_dat;
    assert(fd >= 0);
    ctrl_dat = xcalloc(1, sizeof(dread_ctrl));
    ctrl_dat->fd = fd;
    ctrl_dat->offset = offset;
    ctrl_dat->req_len = req_len;
    ctrl_dat->buf = buf;
    ctrl_dat->end_of_file = 0;
    ctrl_dat->handler = handler;
    ctrl_dat->client_data = client_data;
    cbdataLock(client_data);
#if USE_ASYNC_IO
    diskHandleRead(fd, ctrl_dat);
#else
    commSetSelect(fd,
	COMM_SELECT_READ,
	diskHandleRead,
	ctrl_dat,
	0);
#endif
    return DISK_OK;
}

int
diskWriteIsComplete(int fd)
{
    return fd_table[fd].disk.write_q ? 0 : 1;
}
