/* $Id: disk.cc,v 1.8 1996/04/05 17:47:41 wessels Exp $ */

/* DEBUG: Section 6             disk: disk I/O routines */

#include "squid.h"

#define DISK_LINE_LEN  1024
#define MAX_FILE_NAME_LEN 256

typedef struct _dread_ctrl {
    int fd;
    off_t offset;
    int req_len;
    char *buf;
    int cur_len;
    int end_of_file;
    int (*handler) _PARAMS((int fd, char *buf, int size, int errflag, void * data,
	    int offset));
    void * client_data;
} dread_ctrl;

typedef struct _dwalk_ctrl {
    int fd;
    off_t offset;
    char *buf;			/* line buffer */
    int cur_len;		/* line len */
    int (*handler) _PARAMS((int fd, int errflag, void * data));
    void * client_data;
    int (*line_handler) _PARAMS((int fd, char *buf, int size, void * line_data));
    void * line_data;
} dwalk_ctrl;

typedef struct _dwrite_q {
    char *buf;
    int len;
    int cur_offset;
    struct _dwrite_q *next;
} dwrite_q;

typedef struct _FileEntry {
    char filename[MAX_FILE_NAME_LEN];
    enum {
	NO, YES
    } at_eof;
    enum {
	NOT_OPEN, OPEN
    } open_stat;
    enum {
	NOT_REQUEST, REQUEST
    } close_request;
    enum {
	NOT_PRESENT, PRESENT
    } write_daemon;
    enum {
	UNLOCK, LOCK
    } write_lock;
    int access_code;		/* use to verify write lock */
    enum {
	NO_WRT_PENDING, WRT_PENDING
    } write_pending;
    void (*wrt_handle) ();
    void *wrt_handle_data;
    dwrite_q *write_q;
    dwrite_q *write_q_tail;
} FileEntry;


/* table for FILE variable, write lock and queue. Indexed by fd. */
FileEntry *file_table;
static int disk_initialized = 0;

extern int getMaxFD();
extern void fatal_dump _PARAMS((char *));

/* initialize table */
int disk_init()
{
    int fd, max_fd = getMaxFD();

    if (disk_initialized)
	return 0;

    file_table = (FileEntry *) xmalloc(sizeof(FileEntry) * max_fd);
    memset(file_table, '\0', sizeof(FileEntry) * max_fd);

    for (fd = 0; fd < max_fd; fd++) {
	file_table[fd].filename[0] = '\0';
	file_table[fd].at_eof = NO;
	file_table[fd].open_stat = NOT_OPEN;
	file_table[fd].close_request = NOT_REQUEST;
	file_table[fd].write_daemon = NOT_PRESENT;
	file_table[fd].write_lock = UNLOCK;
	file_table[fd].access_code = 0;
	file_table[fd].write_pending = NO_WRT_PENDING;
	file_table[fd].write_q = file_table[fd].write_q_tail = NULL;
    }
    disk_initialized = 1;
    return 0;
}

/* Open a disk file. Return a file descriptor */
int file_open(path, handler, mode)
     char *path;		/* path to file */
     int (*handler) ();		/* Interrupt handler. */
     int mode;
{
    FD_ENTRY *conn;
    int fd;

    /* lazy initialization */
    if (!disk_initialized)
	disk_init();

    /* Open file */
    if ((fd = open(path, mode | O_NDELAY, 0644)) < 0) {
	debug(6, 0, "file_open: error opening file %s: %s\n",
	    path, xstrerror());
	return (DISK_ERROR);
    }
    /* update fdstat */
    fdstat_open(fd, File);

    /* init table */
    strncpy(file_table[fd].filename, path, MAX_FILE_NAME_LEN);
    file_table[fd].at_eof = NO;
    file_table[fd].open_stat = OPEN;
    file_table[fd].close_request = NOT_REQUEST;
    file_table[fd].write_lock = UNLOCK;
    file_table[fd].write_pending = NO_WRT_PENDING;
    file_table[fd].write_daemon = NOT_PRESENT;
    file_table[fd].access_code = 0;
    file_table[fd].write_q = NULL;

    conn = &fd_table[fd];
    memset(conn, 0, sizeof(FD_ENTRY));

    conn->port = 0;
    conn->handler = NULL;

    /* set non-blocking mode */
#if defined(O_NONBLOCK) && !defined(_SQUID_SUNOS_) && !defined(_SQUID_SOLARIS_)
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
	debug(6, 0, "file_open: FD %d: Failure to set O_NONBLOCK: %s\n",
	    fd, xstrerror());
	return DISK_ERROR;
    }
#else
    if (fcntl(fd, F_SETFL, O_NDELAY) < 0) {
	debug(6, 0, "file_open: FD %d: Failure to set O_NDELAY: %s\n",
	    fd, xstrerror());
	return DISK_ERROR;
    }
#endif /* O_NONBLOCK */
    conn->comm_type = COMM_NONBLOCKING;

    return fd;
}

int file_update_open(fd, path)
     int fd;
     char *path;		/* path to file */
{
    FD_ENTRY *conn;

    /* lazy initialization */
    if (!disk_initialized)
	disk_init();

    /* update fdstat */
    fdstat_open(fd, File);

    /* init table */
    strncpy(file_table[fd].filename, path, MAX_FILE_NAME_LEN);
    file_table[fd].at_eof = NO;
    file_table[fd].open_stat = OPEN;
    file_table[fd].close_request = NOT_REQUEST;
    file_table[fd].write_lock = UNLOCK;
    file_table[fd].write_pending = NO_WRT_PENDING;
    file_table[fd].write_daemon = NOT_PRESENT;
    file_table[fd].access_code = 0;
    file_table[fd].write_q = NULL;

    conn = &fd_table[fd];
    memset(conn, 0, sizeof(FD_ENTRY));

    conn->port = 0;
    conn->handler = NULL;

    conn->comm_type = COMM_NONBLOCKING;

    return fd;
}


/* close a disk file. */
int file_close(fd)
     int fd;			/* file descriptor */
{
    FD_ENTRY *conn = NULL;

    /* we might have to flush all the write back queue before we can
     * close it */
    /* save it for later */

    if ((file_table[fd].open_stat == OPEN) &&
	(file_table[fd].write_daemon == NOT_PRESENT) &&
	(file_table[fd].write_pending == NO_WRT_PENDING)) {
	file_table[fd].open_stat = NOT_OPEN;
	file_table[fd].write_lock = UNLOCK;
	file_table[fd].write_daemon = NOT_PRESENT;
	file_table[fd].filename[0] = '\0';

	if (fdstat_type(fd) == Socket) {
	    debug(6, 0, "FD %d: Someone called file_close() on a socket\n", fd);
	    fatal_dump(NULL);
	}
	/* update fdstat */
	fdstat_close(fd);
	conn = &fd_table[fd];
	memset(conn, '\0', sizeof(FD_ENTRY));
	comm_set_fd_lifetime(fd, -1);	/* invalidate the lifetime */
	close(fd);
	return DISK_OK;
    } else {
	/* refused to close file if there is a daemon running */
	/* have pending flag set */
	file_table[fd].close_request = REQUEST;
	return DISK_ERROR;
    }
}


/* return a opened fd associate with given path name. */
/* return DISK_FILE_NOT_FOUND if not found. */
int file_get_fd(filename)
     char *filename;
{
    int fd, max_fd = getMaxFD();
    for (fd = 1; fd < max_fd; fd++) {
	if (file_table[fd].open_stat == OPEN) {
	    if (strncmp(file_table[fd].filename, filename, MAX_FILE_NAME_LEN) == 0) {
		return fd;
	    }
	}
    }
    return DISK_FILE_NOT_FOUND;
}

/* grab a writing lock for file */
int file_write_lock(fd)
     int fd;
{
    if (file_table[fd].write_lock == LOCK) {
	debug(6, 0, "trying to lock a locked file\n");
	return DISK_WRT_LOCK_FAIL;
    } else {
	file_table[fd].write_lock = LOCK;
	file_table[fd].access_code += 1;
	file_table[fd].access_code %= 65536;
	return file_table[fd].access_code;
    }
}


/* release a writing lock for file */
int file_write_unlock(fd, access_code)
     int fd;
     int access_code;
{
    if (file_table[fd].access_code == access_code) {
	file_table[fd].write_lock = UNLOCK;
	return DISK_OK;
    } else {
	debug(6, 0, "trying to unlock the file with the wrong access code\n");
	return DISK_WRT_WRONG_CODE;
    }
}


/* write handler */
int diskHandleWrite(fd, entry)
     int fd;
     FileEntry *entry;
{
    int len;
    dwrite_q *q;
    int block_complete = 0;

    if (file_table[fd].at_eof == NO)
	lseek(fd, 0, SEEK_END);

    for (;;) {
	len = write(fd, (entry->write_q->buf) + entry->write_q->cur_offset,
	    entry->write_q->len - entry->write_q->cur_offset);

	file_table[fd].at_eof = YES;

	if (len < 0) {
	    switch (errno) {
#if EAGAIN != EWOULDBLOCK
	    case EAGAIN:
#endif
	    case EWOULDBLOCK:
		/* just reschedule itself, try again */
		comm_set_select_handler(fd,
		    COMM_SELECT_WRITE,
		    (PF) diskHandleWrite,
		    (void *) entry);
		entry->write_daemon = PRESENT;
		return DISK_OK;
	    default:
		/* disk i/o failure--flushing all outstanding writes  */
		debug(6, 1, "diskHandleWrite: disk write error %s\n",
		    xstrerror());
		entry->write_daemon = NOT_PRESENT;
		entry->write_pending = NO_WRT_PENDING;
		/* call finish handler */
		do {
		    q = entry->write_q;
		    entry->write_q = q->next;
		    if (!entry->wrt_handle) {
			safe_free(q->buf);
		    } else {
			/* XXXXXX 
			 * Notice we call the handler multiple times but
			 * the write handler (in page mode) doesn't know
			 * the buf ptr so it'll be hard to deallocate
			 * memory.
			 * XXXXXX */
			entry->wrt_handle(fd,
			    errno == ENOSPC ? DISK_NO_SPACE_LEFT : DISK_ERROR,
			    entry->wrt_handle_data);
		    }
		    safe_free(q);
		} while (entry->write_q);
		return DISK_ERROR;
	    }
	}
	entry->write_q->cur_offset += len;
	block_complete = (entry->write_q->cur_offset >= entry->write_q->len);

	if (block_complete && (!entry->write_q->next)) {
	    /* No more data */
	    if (!entry->wrt_handle)
		safe_free(entry->write_q->buf);
	    safe_free(entry->write_q);
	    entry->write_q = entry->write_q_tail = NULL;
	    entry->write_pending = NO_WRT_PENDING;
	    entry->write_daemon = NOT_PRESENT;
	    /* call finish handle */
	    if (entry->wrt_handle) {
		entry->wrt_handle(fd, DISK_OK, entry->wrt_handle_data);
	    }
	    /* Close it if requested */
	    if (file_table[fd].close_request == REQUEST) {
		file_close(fd);
	    }
	    return DISK_OK;
	} else if ((block_complete) && (entry->write_q->next)) {
	    /* Do next block */

	    /* XXXXX THESE PRIMITIVES ARE WEIRD XXXXX   
	     * If we have multiple blocks to send, we  
	     * only call the completion handler once, 
	     * so it becomes our job to free buffer space    
	     */

	    q = entry->write_q;
	    entry->write_q = entry->write_q->next;
	    if (!entry->wrt_handle)
		safe_free(q->buf);
	    safe_free(q);
	    /* Schedule next write 
	     *  comm_set_select_handler(fd, COMM_SELECT_WRITE, (PF) diskHandleWrite,
	     *      (void *) entry);
	     */
	    entry->write_daemon = PRESENT;
	    /* Repeat loop */
	} else {		/* !Block_completed; block incomplete */
	    /* reschedule */
	    comm_set_select_handler(fd, COMM_SELECT_WRITE, (PF) diskHandleWrite,
		(void *) entry);
	    entry->write_daemon = PRESENT;
	    return DISK_OK;
	}
    }
}



/* write block to a file */
/* write back queue. Only one writer at a time. */
/* call a handle when writing is complete. */
int file_write(fd, ptr_to_buf, len, access_code, handle, handle_data)
     int fd;
     char* ptr_to_buf;
     int len;
     int access_code;
     void (*handle) ();
     void *handle_data;
{
    dwrite_q *wq;

    if (file_table[fd].open_stat != OPEN) {
	return DISK_ERROR;
    }
    if ((file_table[fd].write_lock == LOCK) &&
	(file_table[fd].access_code != access_code)) {
	debug(6, 0, "file write: access code checked failed. Sync problem.\n");
	return DISK_WRT_WRONG_CODE;
    }
    /* if we got here. Caller is eligible to write. */
    wq = (dwrite_q *) xcalloc(1, sizeof(dwrite_q));

    wq->buf = ptr_to_buf;

    wq->len = len;
    wq->cur_offset = 0;
    wq->next = NULL;
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

    if (file_table[fd].write_daemon == NOT_PRESENT) {
	/* got to start write routine for this fd */
	comm_set_select_handler(fd, COMM_SELECT_WRITE, (PF) diskHandleWrite,
	    (void *) & file_table[fd]);
    }
    return DISK_OK;
}



/* Read from FD */
int diskHandleRead(fd, ctrl_dat)
     int fd;
     dread_ctrl *ctrl_dat;
{
    int len;

    /* go to requested position. */
    lseek(fd, ctrl_dat->offset, SEEK_SET);
    file_table[fd].at_eof = NO;
    len = read(fd, ctrl_dat->buf + ctrl_dat->cur_len,
	ctrl_dat->req_len - ctrl_dat->cur_len);

    if (len < 0)
	switch (errno) {
#if EAGAIN != EWOULDBLOCK
	case EAGAIN:
#endif
	case EWOULDBLOCK:
	    break;
	default:
	    debug(6, 1, "diskHandleRead: FD %d: error reading: %s\n",
		fd, xstrerror());
	    ctrl_dat->handler(fd, ctrl_dat->buf,
		ctrl_dat->cur_len, DISK_ERROR,
		ctrl_dat->client_data, ctrl_dat->offset);
	    safe_free(ctrl_dat);
	    return DISK_ERROR;
    } else if (len == 0) {
	/* EOF */
	ctrl_dat->end_of_file = 1;
	/* call handler */
	ctrl_dat->handler(fd, ctrl_dat->buf, ctrl_dat->cur_len, DISK_EOF,
	    ctrl_dat->client_data, ctrl_dat->offset);
	safe_free(ctrl_dat);
	return DISK_OK;
    }
    ctrl_dat->cur_len += len;
    ctrl_dat->offset = lseek(fd, 0L, SEEK_CUR);

    /* reschedule if need more data. */
    if (ctrl_dat->cur_len < ctrl_dat->req_len) {
	comm_set_select_handler(fd, COMM_SELECT_READ, (PF) diskHandleRead,
	    (void *) ctrl_dat);
	return DISK_OK;
    } else {
	/* all data we need is here. */
	/* calll handler */
	ctrl_dat->handler(fd, ctrl_dat->buf, ctrl_dat->cur_len, DISK_OK,
	    ctrl_dat->client_data, ctrl_dat->offset);
	safe_free(ctrl_dat);
	return DISK_OK;
    }
}


/* start read operation */
/* buffer must be allocated from the caller. 
 * It must have at least req_len space in there. 
 * call handler when a reading is complete. */
int file_read(fd, buf, req_len, offset, handler, client_data)
     int fd;
     char *buf;
     int req_len;
     int offset;
     FILE_READ_HD handler;
     void * client_data;
{
    dread_ctrl *ctrl_dat;

    ctrl_dat = (dread_ctrl *) xmalloc(sizeof(dread_ctrl));
    memset(ctrl_dat, '\0', sizeof(dread_ctrl));
    ctrl_dat->fd = fd;
    ctrl_dat->offset = offset;
    ctrl_dat->req_len = req_len;
    ctrl_dat->buf = buf;
    ctrl_dat->cur_len = 0;
    ctrl_dat->end_of_file = 0;
    ctrl_dat->handler = handler;
    ctrl_dat->client_data = client_data;

    comm_set_select_handler(fd, COMM_SELECT_READ, (PF) diskHandleRead,
	(void *) ctrl_dat);

    return DISK_OK;
}


/* Read from FD and pass a line to routine. Walk to EOF. */
int diskHandleWalk(fd, walk_dat)
     int fd;
     dwalk_ctrl *walk_dat;
{
    int len;
    int end_pos;
    int st_pos;
    int used_bytes;
    char temp_line[DISK_LINE_LEN];

    lseek(fd, walk_dat->offset, SEEK_SET);
    file_table[fd].at_eof = NO;
    len = read(fd, walk_dat->buf, DISK_LINE_LEN - 1);

    if (len < 0)
	switch (errno) {
#if EAGAIN != EWOULDBLOCK
	case EAGAIN:
#endif
	case EWOULDBLOCK:
	    break;
	default:
	    debug(6, 1, "diskHandleWalk: FD %d: error readingd: %s\n",
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
	    strncpy(temp_line, walk_dat->buf + st_pos, end_pos - st_pos);
	    temp_line[end_pos - st_pos] = '\0';
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
    comm_set_select_handler(fd, COMM_SELECT_READ, (PF) diskHandleWalk,
	(void *) walk_dat);
    return DISK_OK;
}


/* start walk through whole file operation 
 * read one block and chop it to a line and pass it to provided 
 * handler one line at a time.
 * call a completion handler when done. */
int file_walk(fd, handler, client_data, line_handler, line_data)
     int fd;
     FILE_WALK_HD handler;
     void * client_data;
     FILE_WALK_LHD line_handler;
     void * line_data;

{
    dwalk_ctrl *walk_dat;

    walk_dat = (dwalk_ctrl *) xmalloc(sizeof(dwalk_ctrl));
    memset(walk_dat, '\0', sizeof(dwalk_ctrl));
    walk_dat->fd = fd;
    walk_dat->offset = 0;
    walk_dat->buf = (void *) xcalloc(1, DISK_LINE_LEN);
    walk_dat->cur_len = 0;
    walk_dat->handler = handler;
    walk_dat->client_data = client_data;
    walk_dat->line_handler = line_handler;
    walk_dat->line_data = line_data;

    comm_set_select_handler(fd, COMM_SELECT_READ, (PF) diskHandleWalk,
	(void *) walk_dat);
    return DISK_OK;
}

char *diskFileName(fd)
     int fd;
{
    if (file_table[fd].filename[0])
	return (file_table[fd].filename);
    else
	return (0);
}
