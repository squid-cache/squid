
/*
 * $Id: comm.cc,v 1.338 2002/10/15 00:49:10 adrian Exp $
 *
 * DEBUG: section 5     Socket Functions
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
#include "StoreIOBuffer.h"
#include "comm.h"

#if defined(_SQUID_CYGWIN_)
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

typedef struct {
    char *host;
    u_short port;
    struct sockaddr_in S;
    CNCB *callback;
    void *data;
    struct in_addr in_addr;
    int locks;
    int fd;
    int tries;
    int addrcount;
    int connstart;
} ConnectStateData;

/* STATIC */
static comm_err_t commBind(int s, struct in_addr, u_short port);
static void commSetReuseAddr(int);
static void commSetNoLinger(int);
static void CommWriteStateCallbackAndFree(int fd, comm_err_t code);
#ifdef TCP_NODELAY
static void commSetTcpNoDelay(int);
#endif
static void commSetTcpRcvbuf(int, int);
static PF commConnectFree;
static PF commConnectHandle;
static PF commHandleWrite;
static IPH commConnectDnsHandle;
static void commConnectCallback(ConnectStateData * cs, comm_err_t status);
static int commResetFD(ConnectStateData * cs);
static int commRetryConnect(ConnectStateData * cs);
CBDATA_TYPE(ConnectStateData);


struct _fdc_t {
	int active;
	dlink_list CommCallbackList;
	struct {
		char *buf;
		int size;
		IOCB *handler;
		void *handler_data;
	} read;
	struct {
		struct sockaddr_in me;
		struct sockaddr_in pn;
		IOACB *handler;
		void *handler_data;
	} accept;
	struct CommFiller {
		StoreIOBuffer requestedData;
		size_t amountDone;
		IOFCB *handler;
		void *handler_data;
	} fill;

};
typedef struct _fdc_t fdc_t;

typedef enum {
	COMM_CB_READ = 1,
	COMM_CB_WRITE,
	COMM_CB_ACCEPT,
	COMM_CB_FILL
} comm_callback_t;

struct _CommCallbackData {
	comm_callback_t type;
	dlink_node fd_node;
	dlink_node h_node;
	int fd;
	int newfd;	/* for accept() */
	char *buf;
	int retval;
	union {
	    IOCB *r_callback;
	    IOACB *a_callback;
	    IOFCB *f_callback;
	} c;
	void *callback_data;
	comm_err_t errcode;
	int xerrno;
	int seqnum;
	struct sockaddr_in me;
	struct sockaddr_in pn;
	StoreIOBuffer sb;
};
typedef struct _CommCallbackData CommCallbackData;

struct _fd_debug_t {
  char *close_file;
  int close_line;
};
typedef struct _fd_debug_t fd_debug_t;

static MemPool *comm_write_pool = NULL;
static MemPool *conn_close_pool = NULL;
static MemPool *comm_callback_pool = NULL;
fdc_t *fdc_table = NULL;
fd_debug_t *fdd_table = NULL;
dlink_list CommCallbackList;
static int CommCallbackSeqnum = 1;


/* New and improved stuff */

/*
 * return whether there are entries in the callback queue
 */
int
comm_existsiocallback(void)
{
	return CommCallbackList.head == NULL;
}

/*
 * add an IO callback
 *
 * IO callbacks are added when we want to notify someone that some IO
 * has finished but we don't want to risk re-entering a non-reentrant
 * code block.
 */
static void
comm_addreadcallback(int fd, IOCB *callback, char *buf, size_t retval, comm_err_t errcode,
  int xerrno, void *callback_data)
{
	CommCallbackData *cio;

	assert(fdc_table[fd].active == 1);

	/* Allocate a new struct */
	cio = (CommCallbackData *)memPoolAlloc(comm_callback_pool);

	/* Throw our data into it */
	cio->fd = fd;
	cio->retval = retval;
	cio->xerrno = xerrno;
	cio->errcode = errcode;
	cio->c.r_callback = callback;
	cio->callback_data = callback_data;
	cio->seqnum = CommCallbackSeqnum;
        cio->buf = buf;
	cio->type = COMM_CB_READ;

	/* Add it to the end of the list */
	dlinkAddTail(cio, &(cio->h_node), &CommCallbackList);

	/* and add it to the end of the fd list */
	dlinkAddTail(cio, &(cio->fd_node), &(fdc_table[fd].CommCallbackList));

}


static void
comm_addacceptcallback(int fd, int newfd, IOACB *callback, struct sockaddr_in *pn,
  struct sockaddr_in *me, comm_err_t errcode, int xerrno, void *callback_data)
{
	CommCallbackData *cio;

	assert(fdc_table[fd].active == 1);

	/* Allocate a new struct */
	cio = (CommCallbackData *)memPoolAlloc(comm_callback_pool);

	/* Throw our data into it */
	cio->fd = fd;
	cio->xerrno = xerrno;
	cio->errcode = errcode;
	cio->c.a_callback = callback;
	cio->callback_data = callback_data;
	cio->seqnum = CommCallbackSeqnum;
	cio->type = COMM_CB_ACCEPT;
	cio->newfd = newfd;
	cio->pn = *pn;
	cio->me = *me;

	/* Add it to the end of the list */
	dlinkAddTail(cio, &(cio->h_node), &CommCallbackList);

	/* and add it to the end of the fd list */
	dlinkAddTail(cio, &(cio->fd_node), &(fdc_table[fd].CommCallbackList));

}

static void
comm_add_fill_callback(int fd, size_t retval, comm_err_t errcode, int xerrno)
{
	CommCallbackData *cio;

	assert(fdc_table[fd].active == 1);

	/* Allocate a new struct */
	cio = (CommCallbackData *)memPoolAlloc(comm_callback_pool);

	/* Throw our data into it */
	cio->fd = fd;
	cio->xerrno = xerrno;
	cio->errcode = errcode;
	cio->c.f_callback = fdc_table[fd].fill.handler;
	cio->callback_data = fdc_table[fd].fill.handler_data;
	cio->seqnum = CommCallbackSeqnum;
	cio->type = COMM_CB_FILL;
	/* retval not used */
	cio->retval = -1;
	cio->sb = fdc_table[fd].fill.requestedData;
	cio->sb.length = retval;
	/* Clear out fd state */
	fdc_table[fd].fill.handler = NULL;
	fdc_table[fd].fill.handler_data = NULL;

	/* Add it to the end of the list */
	dlinkAddTail(cio, &(cio->h_node), &CommCallbackList);

	/* and add it to the end of the fd list */
	dlinkAddTail(cio, &(cio->fd_node), &(fdc_table[fd].CommCallbackList));
}




static void
comm_call_io_callback(CommCallbackData *cio)
{
		switch(cio->type) {
		    case COMM_CB_READ:
		        cio->c.r_callback(cio->fd, cio->buf, cio->retval, cio->errcode, cio->xerrno,
		          cio->callback_data);
			break;
		    case COMM_CB_WRITE:
			fatal("write comm hasn't been implemented yet!");
		        break;
		    case COMM_CB_ACCEPT:
                        cio->c.a_callback(cio->fd, cio->newfd, &cio->me, &cio->pn, cio->errcode,
			  cio->xerrno, cio->callback_data);
			break;
		    case COMM_CB_FILL:
			cio->c.f_callback(cio->fd, cio->sb, cio->errcode,
			  cio->xerrno, cio->callback_data);
                        break;
		    default:
			fatal("unknown comm io callback type!");
			break;
		};
}


/*
 * call the IO callbacks
 *
 * This should be called before comm_select() so code can attempt to
 * initiate some IO.
 *
 * When io callbacks are added, they are added with the current
 * sequence number. The sequence number is incremented in this routine -
 * since callbacks are added to the _tail_ of the list, when we hit a
 * callback with a seqnum _not_ what it was when we entered this routine,    
 * we can stop.
 */
void
comm_calliocallback(void)
{
	CommCallbackData *cio;
	dlink_node *node;
	int oldseqnum = CommCallbackSeqnum;

	/* Call our callbacks until we hit NULL or the seqnum changes */
	while (CommCallbackList.head != NULL) {
		node = (dlink_node *)CommCallbackList.head;
		cio = (CommCallbackData *)node->data;

		/* If seqnum isn't the same, its time to die */
		if (cio->seqnum != oldseqnum)
			break;		/* we've hit newly-added events */

		assert(fdc_table[cio->fd].active == 1);

		dlinkDelete(&cio->h_node, &CommCallbackList);
		dlinkDelete(&cio->fd_node, &(fdc_table[cio->fd].CommCallbackList));
		comm_call_io_callback(cio);
		memPoolFree(comm_callback_pool, cio);
	}
}


/*
 * Queue a callback
 */
static void
comm_read_callback(int fd, int retval, comm_err_t errcode, int xerrno)
{
	fdc_t *Fc = &fdc_table[fd];

	assert(Fc->read.handler != NULL);

	comm_addreadcallback(fd, Fc->read.handler, Fc->read.buf, retval, errcode, xerrno,
	    Fc->read.handler_data);
	Fc->read.handler = NULL;
	Fc->read.handler_data = NULL;
}

/*
 * Attempt a read
 *
 * If the read attempt succeeds or fails, call the callback.
 * Else, wait for another IO notification.
 */
static void
comm_read_try(int fd, void *data)
{
	fdc_t *Fc = &fdc_table[fd];
	int retval;

	/* make sure we actually have a callback */
	assert(Fc->read.handler != NULL);

	/* Attempt a read */
        statCounter.syscalls.sock.reads++;
	retval = FD_READ_METHOD(fd, Fc->read.buf, Fc->read.size);
	if (retval < 0 && !ignoreErrno(errno)) {
		comm_read_callback(fd, -1, COMM_ERROR, errno);
		return;
	};

	/* See if we read anything */
	/* Note - read 0 == socket EOF, which is a valid read */
	if (retval >= 0) {
                fd_bytes(fd, retval, FD_READ);
		comm_read_callback(fd, retval, COMM_OK, 0);
		return;
	}

	/* Nope, register for some more IO */
        commSetSelect(fd, COMM_SELECT_READ, comm_read_try, NULL, 0);
}

/*
 * Queue a read. handler/handler_data are called when the read
 * completes, on error, or on file descriptor close.
 */
void
comm_read(int fd, char *buf, int size, IOCB *handler, void *handler_data)
{
	/* Make sure we're not reading anything and we're not closing */
	assert(fdc_table[fd].active == 1);
	assert(fdc_table[fd].read.handler == NULL);
        assert(!fd_table[fd].flags.closing);

	/* Queue a read */
	fdc_table[fd].read.buf = buf;
	fdc_table[fd].read.size = size;
	fdc_table[fd].read.handler = handler;
	fdc_table[fd].read.handler_data = handler_data;

#if OPTIMISTIC_IO
        comm_read_try(fd, NULL);
#else
	/* Register intrest in a FD read */
        commSetSelect(fd, COMM_SELECT_READ, comm_read_try, NULL, 0);
#endif
}

static void
comm_fill_read(int fd, char *buf, size_t len, comm_err_t flag, int xerrno, void *data)
{
    /* TODO use a reference to the table entry, or use C++ :] */
    StoreIOBuffer *sb;
    _fdc_t::CommFiller *fill;
    assert(fdc_table[fd].active == 1);

    if (flag != COMM_OK) {
        /* Error! */
	/* XXX This was -1 below, but -1 can't be used for size_t parameters.
	 * The callback should set -1 to the client if needed based on the flags
	 */
	comm_add_fill_callback(fd, 0, flag, xerrno);
	return;
    }
    /* flag is COMM_OK */
    /* We handle EOFs as read lengths of 0! Its eww, but its consistent */
    fill = &fdc_table[fd].fill;
    fill->amountDone += len;
    sb = &fdc_table[fd].fill.requestedData;
    assert(fill->amountDone <= sb->length);
    comm_add_fill_callback(fd, fill->amountDone, COMM_OK, 0);
}

/*
 * Try filling a StoreIOBuffer with some data, and call a callback when successful
 */
void
comm_fill_immediate(int fd, StoreIOBuffer sb, IOFCB *callback, void *data)
{
    assert(fdc_table[fd].fill.handler == NULL);
    /* prevent confusion */
    assert (sb.offset == 0);

    /* If we don't have any data, record details and schedule a read */
    fdc_table[fd].fill.handler = callback;
    fdc_table[fd].fill.handler_data = data;
    fdc_table[fd].fill.requestedData = sb;
    fdc_table[fd].fill.amountDone = 0;

    comm_read(fd, sb.data, sb.length, comm_fill_read, NULL);
}


/*
 * Empty the read buffers
 *
 * This is a magical routine that empties the read buffers.
 * Under some platforms (Linux) if a buffer has data in it before
 * you call close(), the socket will hang and take quite a while
 * to timeout.
 */
static void
comm_empty_os_read_buffers(int fd)
{
#ifdef _SQUID_LINUX_
    /* prevent those nasty RST packets */
    char buf[SQUID_TCP_SO_RCVBUF];
    if (fd_table[fd].flags.nonblocking == 1)
    	while (FD_READ_METHOD(fd, buf, SQUID_TCP_SO_RCVBUF) > 0);
#endif
}


/*
 * Return whether a file descriptor has any pending read request callbacks
 *
 * Assumptions: the fd is open (ie, its not closing)
 */
int
comm_has_pending_read_callback(int fd)
{
    dlink_node *node;
    CommCallbackData *cd;

    assert(fd_table[fd].flags.open == 1);
    assert(fdc_table[fd].active == 1);

    /*
     * XXX I don't like having to walk the list!
     * Instead, if this routine is called often enough, we should
     * also maintain a linked list of _read_ events - we can just
     * check if the list head a HEAD..
     * - adrian
     */
    node = fdc_table[fd].CommCallbackList.head;
    while (node != NULL) {
	cd = (CommCallbackData *)node->data;
	if (cd->type == COMM_CB_READ)
	    return 1;
	node = node->next;
    }

    /* Not found */
    return 0;
}

/*
 * return whether a file descriptor has a read handler
 *
 * Assumptions: the fd is open
 */
int
comm_has_pending_read(int fd)
{
	assert(fd_table[fd].flags.open == 1);
	assert(fdc_table[fd].active == 1);

	return (fdc_table[fd].read.handler != NULL);
}

/*
 * Cancel a pending read. Assert that we have the right parameters,
 * and that there are no pending read events!
 */
void
comm_read_cancel(int fd, IOCB *callback, void *data)
{
    assert(fd_table[fd].flags.open == 1);
    assert(fdc_table[fd].active == 1);

    assert(fdc_table[fd].read.handler == callback);
    assert(fdc_table[fd].read.handler_data == data);

    assert(!comm_has_pending_read_callback(fd));

    /* Ok, we can be reasonably sure we won't lose any data here! */

    /* Delete the callback */
    fdc_table[fd].read.handler = NULL;
    fdc_table[fd].read.handler_data = NULL;
}


void
fdc_open(int fd, unsigned int type, char *desc)
{
	assert(fdc_table[fd].active == 0);

	fdc_table[fd].active = 1;
	fd_open(fd, type, desc);
}


/* Older stuff */

static void
CommWriteStateCallbackAndFree(int fd, comm_err_t code)
{
    CommWriteStateData *CommWriteState = fd_table[fd].rwstate;
    CWCB *callback = NULL;
    void *cbdata;
    fd_table[fd].rwstate = NULL;
    if (CommWriteState == NULL)
	return;
    if (CommWriteState->free_func) {
	FREE *free_func = CommWriteState->free_func;
	void *free_buf = CommWriteState->buf;
	CommWriteState->free_func = NULL;
	CommWriteState->buf = NULL;
	free_func(free_buf);
    }
    callback = CommWriteState->handler;
    CommWriteState->handler = NULL;
    if (callback && cbdataReferenceValidDone(CommWriteState->handler_data, &cbdata))
	callback(fd, CommWriteState->buf, CommWriteState->offset, code, cbdata);
    memPoolFree(comm_write_pool, CommWriteState);
}

/* Return the local port associated with fd. */
u_short
comm_local_port(int fd)
{
    struct sockaddr_in addr;
    socklen_t addr_len = 0;
    fde *F = &fd_table[fd];

    /* If the fd is closed already, just return */
    if (!F->flags.open) {
	debug(5, 0) ("comm_local_port: FD %d has been closed.\n", fd);
	return 0;
    }
    if (F->local_port)
	return F->local_port;
    addr_len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *) &addr, &addr_len)) {
	debug(50, 1) ("comm_local_port: Failed to retrieve TCP/UDP port number for socket: FD %d: %s\n", fd, xstrerror());
	return 0;
    }
    F->local_port = ntohs(addr.sin_port);
    debug(5, 6) ("comm_local_port: FD %d: port %d\n", fd, (int) F->local_port);
    return F->local_port;
}

static comm_err_t
commBind(int s, struct in_addr in_addr, u_short port)
{
    struct sockaddr_in S;

    memset(&S, '\0', sizeof(S));
    S.sin_family = AF_INET;
    S.sin_port = htons(port);
    S.sin_addr = in_addr;
    statCounter.syscalls.sock.binds++;
    if (bind(s, (struct sockaddr *) &S, sizeof(S)) == 0)
	return COMM_OK;
    debug(50, 0) ("commBind: Cannot bind socket FD %d to %s:%d: %s\n",
	s,
	S.sin_addr.s_addr == INADDR_ANY ? "*" : inet_ntoa(S.sin_addr),
	(int) port,
	xstrerror());
    return COMM_ERROR;
}

/* Create a socket. Default is blocking, stream (TCP) socket.  IO_TYPE
 * is OR of flags specified in comm.h. Defaults TOS */
int
comm_open(int sock_type,
    int proto,
    struct in_addr addr,
    u_short port,
    int flags,
    const char *note)
{
    return comm_openex(sock_type, proto, addr, port, flags, 0, note);
}


/* Create a socket. Default is blocking, stream (TCP) socket.  IO_TYPE
 * is OR of flags specified in defines.h:COMM_* */
int
comm_openex(int sock_type,
    int proto,
    struct in_addr addr,
    u_short port,
    int flags,
    unsigned char TOS,
    const char *note)
{
    int new_socket;
    int tos = 0;
    fde *F = NULL;

    PROF_start(comm_open);
    /* Create socket for accepting new connections. */
    statCounter.syscalls.sock.sockets++;
    if ((new_socket = socket(AF_INET, sock_type, proto)) < 0) {
	/* Increase the number of reserved fd's if calls to socket()
	 * are failing because the open file table is full.  This
	 * limits the number of simultaneous clients */
	switch (errno) {
	case ENFILE:
	case EMFILE:
	    debug(50, 1) ("comm_open: socket failure: %s\n", xstrerror());
	    fdAdjustReserved();
	    break;
	default:
	    debug(50, 0) ("comm_open: socket failure: %s\n", xstrerror());
	}
	PROF_stop(comm_open);
	return -1;
    }
    /* set TOS if needed */
    if (TOS) {
#ifdef IP_TOS
	tos = TOS;
	if (setsockopt(new_socket, IPPROTO_IP, IP_TOS, (char *) &tos, sizeof(int)) < 0)
	        debug(50, 1) ("comm_open: setsockopt(IP_TOS) on FD %d: %s\n",
		new_socket, xstrerror());
#else
	debug(50, 0) ("comm_open: setsockopt(IP_TOS) not supported on this platform\n");
#endif
    }
    /* update fdstat */
    debug(5, 5) ("comm_open: FD %d is a new socket\n", new_socket);
    fd_open(new_socket, FD_SOCKET, note);
    fdd_table[new_socket].close_file = NULL;
    fdd_table[new_socket].close_line = 0;
    assert(fdc_table[new_socket].active == 0);
    fdc_table[new_socket].active = 1;
    F = &fd_table[new_socket];
    F->local_addr = addr;
    F->tos = tos;
    if (!(flags & COMM_NOCLOEXEC))
	commSetCloseOnExec(new_socket);
    if ((flags & COMM_REUSEADDR))
	commSetReuseAddr(new_socket);
    if (port > (u_short) 0) {
	commSetNoLinger(new_socket);
	if (opt_reuseaddr)
	    commSetReuseAddr(new_socket);
    }
    if (addr.s_addr != no_addr.s_addr) {
	if (commBind(new_socket, addr, port) != COMM_OK) {
	    comm_close(new_socket);
	    return -1;
	    PROF_stop(comm_open);
	}
    }
    F->local_port = port;

    if (flags & COMM_NONBLOCKING)
	if (commSetNonBlocking(new_socket) == COMM_ERROR) {
	    return -1;
	    PROF_stop(comm_open);
	}
#ifdef TCP_NODELAY
    if (sock_type == SOCK_STREAM)
	commSetTcpNoDelay(new_socket);
#endif
    if (Config.tcpRcvBufsz > 0 && sock_type == SOCK_STREAM)
	commSetTcpRcvbuf(new_socket, Config.tcpRcvBufsz);
    PROF_stop(comm_open);
    return new_socket;
}

void
commConnectStart(int fd, const char *host, u_short port, CNCB * callback, void *data)
{
    ConnectStateData *cs;
    debug(5, 3) ("commConnectStart: FD %d, %s:%d\n", fd, host, (int) port);
    cs = cbdataAlloc(ConnectStateData);
    cs->fd = fd;
    cs->host = xstrdup(host);
    cs->port = port;
    cs->callback = callback;
    cs->data = cbdataReference(data);
    comm_add_close_handler(fd, commConnectFree, cs);
    cs->locks++;
    ipcache_nbgethostbyname(host, commConnectDnsHandle, cs);
}

static void
commConnectDnsHandle(const ipcache_addrs * ia, void *data)
{
    ConnectStateData *cs = (ConnectStateData *)data;
    assert(cs->locks == 1);
    cs->locks--;
    if (ia == NULL) {
	debug(5, 3) ("commConnectDnsHandle: Unknown host: %s\n", cs->host);
	if (!dns_error_message) {
	    dns_error_message = "Unknown DNS error";
	    debug(5, 1) ("commConnectDnsHandle: Bad dns_error_message\n");
	}
	assert(dns_error_message != NULL);
	commConnectCallback(cs, COMM_ERR_DNS);
	return;
    }
    assert(ia->cur < ia->count);
    cs->in_addr = ia->in_addrs[ia->cur];
    ipcacheCycleAddr(cs->host, NULL);
    cs->addrcount = ia->count;
    cs->connstart = squid_curtime;
    commConnectHandle(cs->fd, cs);
}

static void
commConnectCallback(ConnectStateData * cs, comm_err_t status)
{
    CNCB *callback = cs->callback;
    void *cbdata = cs->data;
    int fd = cs->fd;
    comm_remove_close_handler(fd, commConnectFree, cs);
    cs->callback = NULL;
    cs->data = NULL;
    commSetTimeout(fd, -1, NULL, NULL);
    commConnectFree(fd, cs);
    if (cbdataReferenceValid(cbdata))
	callback(fd, status, cbdata);
}

static void
commConnectFree(int fd, void *data)
{
    ConnectStateData *cs = (ConnectStateData *)data;
    debug(5, 3) ("commConnectFree: FD %d\n", fd);
    cbdataReferenceDone(cs->data);
    safe_free(cs->host);
    cbdataFree(cs);
}

/* Reset FD so that we can connect() again */
static int
commResetFD(ConnectStateData * cs)
{
    int fd2;
    fde *F;
    if (!cbdataReferenceValid(cs->data))
	return 0;
    statCounter.syscalls.sock.sockets++;
    fd2 = socket(AF_INET, SOCK_STREAM, 0);
    statCounter.syscalls.sock.sockets++;
    if (fd2 < 0) {
	debug(5, 0) ("commResetFD: socket: %s\n", xstrerror());
	if (ENFILE == errno || EMFILE == errno)
	    fdAdjustReserved();
	return 0;
    }
    if (dup2(fd2, cs->fd) < 0) {
	debug(5, 0) ("commResetFD: dup2: %s\n", xstrerror());
	if (ENFILE == errno || EMFILE == errno)
	    fdAdjustReserved();
	close(fd2);
	return 0;
    }
    close(fd2);
    F = &fd_table[cs->fd];
    fd_table[cs->fd].flags.called_connect = 0;
    /*
     * yuck, this has assumptions about comm_open() arguments for
     * the original socket
     */
    if (commBind(cs->fd, F->local_addr, F->local_port) != COMM_OK) {
	debug(5, 0) ("commResetFD: bind: %s\n", xstrerror());
	return 0;
    }
#ifdef IP_TOS
    if (F->tos) {
	int tos = F->tos;
	if (setsockopt(cs->fd, IPPROTO_IP, IP_TOS, (char *) &tos, sizeof(int)) < 0)
	        debug(50, 1) ("commResetFD: setsockopt(IP_TOS) on FD %d: %s\n", cs->fd, xstrerror());
    }
#endif
    if (F->flags.close_on_exec)
	commSetCloseOnExec(cs->fd);
    if (F->flags.nonblocking)
	commSetNonBlocking(cs->fd);
#ifdef TCP_NODELAY
    if (F->flags.nodelay)
	commSetTcpNoDelay(cs->fd);
#endif
    if (Config.tcpRcvBufsz > 0)
	commSetTcpRcvbuf(cs->fd, Config.tcpRcvBufsz);
    return 1;
}

static int
commRetryConnect(ConnectStateData * cs)
{
    assert(cs->addrcount > 0);
    if (cs->addrcount == 1) {
	if (cs->tries >= Config.retry.maxtries)
	    return 0;
	if (squid_curtime - cs->connstart > Config.Timeout.connect)
	    return 0;
    } else {
	if (cs->tries > cs->addrcount)
	    return 0;
    }
    return commResetFD(cs);
}

/* Connect SOCK to specified DEST_PORT at DEST_HOST. */
static void
commConnectHandle(int fd, void *data)
{
    ConnectStateData *cs = (ConnectStateData *)data;
    if (cs->S.sin_addr.s_addr == 0) {
	cs->S.sin_family = AF_INET;
	cs->S.sin_addr = cs->in_addr;
	cs->S.sin_port = htons(cs->port);
	if (Config.onoff.log_fqdn)
	    fqdncache_gethostbyaddr(cs->S.sin_addr, FQDN_LOOKUP_IF_MISS);
    }
    switch (comm_connect_addr(fd, &cs->S)) {
    case COMM_INPROGRESS:
	debug(5, 5) ("commConnectHandle: FD %d: COMM_INPROGRESS\n", fd);
	commSetSelect(fd, COMM_SELECT_WRITE, commConnectHandle, cs, 0);
	break;
    case COMM_OK:
	ipcacheMarkGoodAddr(cs->host, cs->S.sin_addr);
	commConnectCallback(cs, COMM_OK);
	break;
    default:
	cs->tries++;
	ipcacheMarkBadAddr(cs->host, cs->S.sin_addr);
	if (Config.onoff.test_reachability)
	    netdbDeleteAddrNetwork(cs->S.sin_addr);
	if (commRetryConnect(cs)) {
	    cs->locks++;
	    ipcache_nbgethostbyname(cs->host, commConnectDnsHandle, cs);
	} else {
	    commConnectCallback(cs, COMM_ERR_CONNECT);
	}
	break;
    }
}

int
commSetTimeout(int fd, int timeout, PF * handler, void *data)
{
    fde *F;
    debug(5, 3) ("commSetTimeout: FD %d timeout %d\n", fd, timeout);
    assert(fd >= 0);
    assert(fd < Squid_MaxFD);
    F = &fd_table[fd];
    assert(F->flags.open);
    if (timeout < 0) {
	cbdataReferenceDone(F->timeout_data);
	F->timeout_handler = NULL;
	F->timeout = 0;
    } else {
	assert(handler || F->timeout_handler);
	if (handler) {
	    cbdataReferenceDone(F->timeout_data);
	    F->timeout_handler = handler;
	    F->timeout_data = cbdataReference(data);
	}
	F->timeout = squid_curtime + (time_t) timeout;
    }
    return F->timeout;
}

int
comm_connect_addr(int sock, const struct sockaddr_in *address)
{
    comm_err_t status = COMM_OK;
    fde *F = &fd_table[sock];
    int x;
    int err = 0;
    socklen_t errlen;
    assert(ntohs(address->sin_port) != 0);
    PROF_start(comm_connect_addr);
    /* Establish connection. */
    errno = 0;
    if (!F->flags.called_connect) {
	F->flags.called_connect = 1;
	statCounter.syscalls.sock.connects++;
	x = connect(sock, (struct sockaddr *) address, sizeof(*address));
	if (x < 0)
	    debug(5, 9) ("connect FD %d: %s\n", sock, xstrerror());
    } else {
#if defined(_SQUID_NEWSOS6_)
	/* Makoto MATSUSHITA <matusita@ics.es.osaka-u.ac.jp> */
	connect(sock, (struct sockaddr *) address, sizeof(*address));
	if (errno == EINVAL) {
	    errlen = sizeof(err);
	    x = getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen);
	    if (x >= 0)
		errno = x;
	}
#else
	errlen = sizeof(err);
	x = getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errlen);
	if (x == 0)
	    errno = err;
#if defined(_SQUID_SOLARIS_)
	/*
	 * Solaris 2.4's socket emulation doesn't allow you
	 * to determine the error from a failed non-blocking
	 * connect and just returns EPIPE.  Create a fake
	 * error message for connect.   -- fenner@parc.xerox.com
	 */
	if (x < 0 && errno == EPIPE)
	    errno = ENOTCONN;
#endif
#endif
    }
    PROF_stop(comm_connect_addr);
    if (errno == 0 || errno == EISCONN)
	status = COMM_OK;
    else if (ignoreErrno(errno))
	status = COMM_INPROGRESS;
    else
	return COMM_ERROR;
    xstrncpy(F->ipaddr, inet_ntoa(address->sin_addr), 16);
    F->remote_port = ntohs(address->sin_port);
    if (status == COMM_OK) {
	debug(5, 10) ("comm_connect_addr: FD %d connected to %s:%d\n",
	    sock, F->ipaddr, F->remote_port);
    } else if (status == COMM_INPROGRESS) {
	debug(5, 10) ("comm_connect_addr: FD %d connection pending\n", sock);
    }
    return status;
}

/* Wait for an incoming connection on FD.  FD should be a socket returned
 * from comm_listen. */
int
comm_old_accept(int fd, struct sockaddr_in *pn, struct sockaddr_in *me)
{
    int sock;
    struct sockaddr_in P;
    struct sockaddr_in M;
    socklen_t Slen;
    fde *F = NULL;
    Slen = sizeof(P);
    statCounter.syscalls.sock.accepts++;
    PROF_start(comm_accept);
    if ((sock = accept(fd, (struct sockaddr *) &P, &Slen)) < 0) {
	PROF_stop(comm_accept);
	if (ignoreErrno(errno)) {
	    debug(50, 5) ("comm_old_accept: FD %d: %s\n", fd, xstrerror());
	    return COMM_NOMESSAGE;
	} else if (ENFILE == errno || EMFILE == errno) {
	    debug(50, 3) ("comm_old_accept: FD %d: %s\n", fd, xstrerror());
	    return COMM_ERROR;
	} else {
	    debug(50, 1) ("comm_old_accept: FD %d: %s\n", fd, xstrerror());
	    return COMM_ERROR;
	}
    }
    if (pn)
	*pn = P;
    Slen = sizeof(M);
    memset(&M, '\0', Slen);
    getsockname(sock, (struct sockaddr *) &M, &Slen);
    if (me)
	*me = M;
    commSetCloseOnExec(sock);
    /* fdstat update */
    fd_open(sock, FD_SOCKET, "HTTP Request");
    fdd_table[sock].close_file = NULL;
    fdd_table[sock].close_line = 0;
    fdc_table[sock].active = 1;
    F = &fd_table[sock];
    xstrncpy(F->ipaddr, inet_ntoa(P.sin_addr), 16);
    F->remote_port = htons(P.sin_port);
    F->local_port = htons(M.sin_port);
    commSetNonBlocking(sock);
    PROF_stop(comm_accept);
    return sock;
}

void
commCallCloseHandlers(int fd)
{
    fde *F = &fd_table[fd];
    close_handler *ch;
    debug(5, 5) ("commCallCloseHandlers: FD %d\n", fd);
    while ((ch = F->closeHandler) != NULL) {
	F->closeHandler = ch->next;
	debug(5, 5) ("commCallCloseHandlers: ch->handler=%p\n", ch->handler);
	if (cbdataReferenceValid(ch->data))
	    ch->handler(fd, ch->data);
	cbdataReferenceDone(ch->data);
	memPoolFree(conn_close_pool, ch);	/* AAA */
    }
}

#if LINGERING_CLOSE
static void
commLingerClose(int fd, void *unused)
{
    LOCAL_ARRAY(char, buf, 1024);
    int n;
    n = FD_READ_METHOD(fd, buf, 1024);
    if (n < 0)
	debug(5, 3) ("commLingerClose: FD %d read: %s\n", fd, xstrerror());
    comm_close(fd);
}

static void
commLingerTimeout(int fd, void *unused)
{
    debug(5, 3) ("commLingerTimeout: FD %d\n", fd);
    comm_close(fd);
}

/*
 * Inspired by apache
 */
void
comm_lingering_close(int fd)
{
#if USE_SSL
    if (fd_table[fd].ssl)
	ssl_shutdown_method(fd);
#endif
    if (shutdown(fd, 1) < 0) {
	comm_close(fd);
	return;
    }
    fd_note(fd, "lingering close");
    commSetTimeout(fd, 10, commLingerTimeout, NULL);
    commSetSelect(fd, COMM_SELECT_READ, commLingerClose, NULL, 0);
}
#endif

/*
 * enable linger with time of 0 so that when the socket is
 * closed, TCP generates a RESET
 */
void
comm_reset_close(int fd)
{
    struct linger L;
    L.l_onoff = 1;
    L.l_linger = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &L, sizeof(L)) < 0)
	debug(50, 0) ("commResetTCPClose: FD %d: %s\n", fd, xstrerror());
    comm_close(fd);
}


/*
 * Close the socket fd.
 *
 * + call write handlers with ERR_CLOSING
 * + call read handlers with ERR_CLOSING
 * + call closing handlers
 */
void
_comm_close(int fd, char *file, int line)
{
    fde *F = NULL;
    dlink_node *node;
    CommCallbackData *cio;

    debug(5, 5) ("comm_close: FD %d\n", fd);
    assert(fd >= 0);
    assert(fd < Squid_MaxFD);
    F = &fd_table[fd];
    fdd_table[fd].close_file = file;
    fdd_table[fd].close_line = line;

    if (F->flags.closing)
	return;
    if (shutting_down && (!F->flags.open || F->type == FD_FILE))
	return;
    assert(F->flags.open);
    /* The following fails because ipc.c is doing calls to pipe() to create sockets! */
    /* assert(fdc_table[fd].active == 1); */
    assert(F->type != FD_FILE);
    PROF_start(comm_close);
    F->flags.closing = 1;
#if USE_SSL
    if (F->ssl)
	ssl_shutdown_method(fd);
#endif
    commSetTimeout(fd, -1, NULL, NULL);
    CommWriteStateCallbackAndFree(fd, COMM_ERR_CLOSING);

    /* Delete any pending io callbacks */
    while (fdc_table[fd].CommCallbackList.head != NULL) {
	node = fdc_table[fd].CommCallbackList.head;
	cio = (CommCallbackData *)node->data;
	assert(fd == cio->fd); /* just paranoid */
	dlinkDelete(&cio->h_node, &CommCallbackList);
	dlinkDelete(&cio->fd_node, &(fdc_table[cio->fd].CommCallbackList));
	/* We're closing! */
	cio->errcode = COMM_ERR_CLOSING;
	comm_call_io_callback(cio);
	memPoolFree(comm_callback_pool, cio);
    }

    commCallCloseHandlers(fd);
    if (F->uses)		/* assume persistent connect count */
	pconnHistCount(1, F->uses);
#if USE_SSL
    if (F->ssl) {
	SSL_free(F->ssl);
	F->ssl = NULL;
    }
#endif
    comm_empty_os_read_buffers(fd);
    fd_close(fd);		/* update fdstat */
    close(fd);
    fdc_table[fd].active = 0;
    bzero(&fdc_table[fd], sizeof(fdc_t));
    statCounter.syscalls.sock.closes++;
    PROF_stop(comm_close);
}

/* Send a udp datagram to specified TO_ADDR. */
int
comm_udp_sendto(int fd,
    const struct sockaddr_in *to_addr,
    int addr_len,
    const void *buf,
    int len)
{
    int x;
    PROF_start(comm_udp_sendto);
    statCounter.syscalls.sock.sendtos++;
    x = sendto(fd, buf, len, 0, (struct sockaddr *) to_addr, addr_len);
    PROF_stop(comm_udp_sendto);
    if (x < 0) {
#ifdef _SQUID_LINUX_
	if (ECONNREFUSED != errno)
#endif
	    debug(50, 1) ("comm_udp_sendto: FD %d, %s, port %d: %s\n",
		fd,
		inet_ntoa(to_addr->sin_addr),
		(int) htons(to_addr->sin_port),
		xstrerror());
	return COMM_ERROR;
    }
    return x;
}

void
commSetDefer(int fd, DEFER * func, void *data)
{
    fde *F = &fd_table[fd];
    F->defer_check = func;
    F->defer_data = data;
}

void
comm_add_close_handler(int fd, PF * handler, void *data)
{
    close_handler *newHandler = (close_handler *)memPoolAlloc(conn_close_pool);		/* AAA */
    close_handler *c;
    debug(5, 5) ("comm_add_close_handler: FD %d, handler=%p, data=%p\n",
	fd, handler, data);
    for (c = fd_table[fd].closeHandler; c; c = c->next)
	assert(c->handler != handler || c->data != data);
    newHandler->handler = handler;
    newHandler->data = cbdataReference(data);
    newHandler->next = fd_table[fd].closeHandler;
    fd_table[fd].closeHandler = newHandler;
}

void
comm_remove_close_handler(int fd, PF * handler, void *data)
{
    close_handler *p;
    close_handler *last = NULL;
    /* Find handler in list */
    debug(5, 5) ("comm_remove_close_handler: FD %d, handler=%p, data=%p\n",
	fd, handler, data);
    for (p = fd_table[fd].closeHandler; p != NULL; last = p, p = p->next)
	if (p->handler == handler && p->data == data)
	    break;		/* This is our handler */
    assert(p != NULL);
    /* Remove list entry */
    if (last)
	last->next = p->next;
    else
	fd_table[fd].closeHandler = p->next;
    cbdataReferenceDone(p->data);
    memPoolFree(conn_close_pool, p);
}

static void
commSetNoLinger(int fd)
{
    struct linger L;
    L.l_onoff = 0;		/* off */
    L.l_linger = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &L, sizeof(L)) < 0)
	debug(50, 0) ("commSetNoLinger: FD %d: %s\n", fd, xstrerror());
    fd_table[fd].flags.nolinger = 1;
}

static void
commSetReuseAddr(int fd)
{
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0)
	debug(50, 1) ("commSetReuseAddr: FD %d: %s\n", fd, xstrerror());
}

static void
commSetTcpRcvbuf(int fd, int size)
{
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &size, sizeof(size)) < 0)
	debug(50, 1) ("commSetTcpRcvbuf: FD %d, SIZE %d: %s\n",
	    fd, size, xstrerror());
}

int
commSetNonBlocking(int fd)
{
    int flags;
    int dummy = 0;
#ifdef _SQUID_CYGWIN_
    int nonblocking = TRUE;
    if (fd_table[fd].type != FD_PIPE) {
	if (ioctl(fd, FIONBIO, &nonblocking) < 0) {
	    debug(50, 0) ("commSetNonBlocking: FD %d: %s %D\n", fd, xstrerror(), fd_table[fd].type);
	    return COMM_ERROR;
	}
    } else {
#endif
	if ((flags = fcntl(fd, F_GETFL, dummy)) < 0) {
	    debug(50, 0) ("FD %d: fcntl F_GETFL: %s\n", fd, xstrerror());
	    return COMM_ERROR;
	}
	if (fcntl(fd, F_SETFL, flags | SQUID_NONBLOCK) < 0) {
	    debug(50, 0) ("commSetNonBlocking: FD %d: %s\n", fd, xstrerror());
	    return COMM_ERROR;
	}
#ifdef _SQUID_CYGWIN_
    }
#endif
    fd_table[fd].flags.nonblocking = 1;
    return 0;
}

int
commUnsetNonBlocking(int fd)
{
    int flags;
    int dummy = 0;
    if ((flags = fcntl(fd, F_GETFL, dummy)) < 0) {
	debug(50, 0) ("FD %d: fcntl F_GETFL: %s\n", fd, xstrerror());
	return COMM_ERROR;
    }
    if (fcntl(fd, F_SETFL, flags & (~SQUID_NONBLOCK)) < 0) {
	debug(50, 0) ("commUnsetNonBlocking: FD %d: %s\n", fd, xstrerror());
	return COMM_ERROR;
    }
    fd_table[fd].flags.nonblocking = 0;
    return 0;
}

void
commSetCloseOnExec(int fd)
{
#ifdef FD_CLOEXEC
    int flags;
    int dummy = 0;
    if ((flags = fcntl(fd, F_GETFL, dummy)) < 0) {
	debug(50, 0) ("FD %d: fcntl F_GETFL: %s\n", fd, xstrerror());
	return;
    }
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
	debug(50, 0) ("FD %d: set close-on-exec failed: %s\n", fd, xstrerror());
    fd_table[fd].flags.close_on_exec = 1;
#endif
}

#ifdef TCP_NODELAY
static void
commSetTcpNoDelay(int fd)
{
    int on = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof(on)) < 0)
	debug(50, 1) ("commSetTcpNoDelay: FD %d: %s\n", fd, xstrerror());
    fd_table[fd].flags.nodelay = 1;
}
#endif


void
comm_init(void)
{
    fd_table =(fde *) xcalloc(Squid_MaxFD, sizeof(fde));
    fdd_table = (fd_debug_t *)xcalloc(Squid_MaxFD, sizeof(fd_debug_t));
    fdc_table = (fdc_t *)xcalloc(Squid_MaxFD, sizeof(fdc_t));
    /* XXX account fd_table */
    /* Keep a few file descriptors free so that we don't run out of FD's
     * after accepting a client but before it opens a socket or a file.
     * Since Squid_MaxFD can be as high as several thousand, don't waste them */
    RESERVED_FD = XMIN(100, Squid_MaxFD / 4);
    CBDATA_INIT_TYPE(ConnectStateData);

    comm_callback_pool = memPoolCreate("comm callbacks", sizeof(CommCallbackData));
    comm_write_pool = memPoolCreate("CommWriteStateData", sizeof(CommWriteStateData));
    conn_close_pool = memPoolCreate("close_handler", sizeof(close_handler));
}

/* Write to FD. */
static void
commHandleWrite(int fd, void *data)
{
    CommWriteStateData *state = (CommWriteStateData *)data;
    int len = 0;
    int nleft;

    PROF_start(commHandleWrite);
    debug(5, 5) ("commHandleWrite: FD %d: off %ld, sz %ld.\n",
	fd, (long int) state->offset, (long int) state->size);

    nleft = state->size - state->offset;
    len = FD_WRITE_METHOD(fd, state->buf + state->offset, nleft);
    debug(5, 5) ("commHandleWrite: write() returns %d\n", len);
    fd_bytes(fd, len, FD_WRITE);
    statCounter.syscalls.sock.writes++;

    if (len == 0) {
	/* Note we even call write if nleft == 0 */
	/* We're done */
	if (nleft != 0)
	    debug(5, 1) ("commHandleWrite: FD %d: write failure: connection closed with %d bytes remaining.\n", fd, nleft);
	CommWriteStateCallbackAndFree(fd, nleft ? COMM_ERROR : COMM_OK);
    } else if (len < 0) {
	/* An error */
	if (fd_table[fd].flags.socket_eof) {
	    debug(50, 2) ("commHandleWrite: FD %d: write failure: %s.\n",
		fd, xstrerror());
	    CommWriteStateCallbackAndFree(fd, COMM_ERROR);
	} else if (ignoreErrno(errno)) {
	    debug(50, 10) ("commHandleWrite: FD %d: write failure: %s.\n",
		fd, xstrerror());
	    commSetSelect(fd,
		COMM_SELECT_WRITE,
		commHandleWrite,
		state,
		0);
	} else {
	    debug(50, 2) ("commHandleWrite: FD %d: write failure: %s.\n",
		fd, xstrerror());
	    CommWriteStateCallbackAndFree(fd, COMM_ERROR);
	}
    } else {
	/* A successful write, continue */
	state->offset += len;
	if (state->offset < (off_t)state->size) {
	    /* Not done, reinstall the write handler and write some more */
	    commSetSelect(fd,
		COMM_SELECT_WRITE,
		commHandleWrite,
		state,
		0);
	} else {
	    CommWriteStateCallbackAndFree(fd, COMM_OK);
	}
    }
    PROF_stop(commHandleWrite);
}



/*
 * Queue a write. handler/handler_data are called when the write
 * completes, on error, or on file descriptor close.
 *
 * free_func is used to free the passed buffer when the write has completed.
 */
void
comm_write(int fd, const char *buf, int size, CWCB * handler, void *handler_data, FREE * free_func)
{
    CommWriteStateData *state = fd_table[fd].rwstate;

    assert(!fd_table[fd].flags.closing);

    debug(5, 5) ("comm_write: FD %d: sz %d: hndl %p: data %p.\n",
	fd, size, handler, handler_data);
    if (NULL != state) {
	debug(5, 1) ("comm_write: fd_table[%d].rwstate != NULL\n", fd);
	memPoolFree(comm_write_pool, state);
	fd_table[fd].rwstate = NULL;
    }
    fd_table[fd].rwstate = state = (CommWriteStateData *)memPoolAlloc(comm_write_pool);
    state->buf = (char *) buf;
    state->size = size;
    state->offset = 0;
    state->handler = handler;
    state->handler_data = cbdataReference(handler_data);
    state->free_func = free_func;
    commSetSelect(fd, COMM_SELECT_WRITE, commHandleWrite, state, 0);
}

/* a wrapper around comm_write to allow for MemBuf to be comm_written in a snap */
void
comm_write_mbuf(int fd, MemBuf mb, CWCB * handler, void *handler_data)
{
    comm_write(fd, mb.buf, mb.size, handler, handler_data, memBufFreeFunc(&mb));
}


/*
 * hm, this might be too general-purpose for all the places we'd
 * like to use it.
 */
int
ignoreErrno(int ierrno)
{
    switch (ierrno) {
    case EINPROGRESS:
    case EWOULDBLOCK:
#if EAGAIN != EWOULDBLOCK
    case EAGAIN:
#endif
    case EALREADY:
    case EINTR:
#ifdef ERESTART
    case ERESTART:
#endif
	return 1;
    default:
	return 0;
    }
    /* NOTREACHED */
}

void
commCloseAllSockets(void)
{
    int fd;
    fde *F = NULL;
    for (fd = 0; fd <= Biggest_FD; fd++) {
	F = &fd_table[fd];
	if (!F->flags.open)
	    continue;
	if (F->type != FD_SOCKET)
	    continue;
	if (F->flags.ipc)	/* don't close inter-process sockets */
	    continue;
	if (F->timeout_handler) {
	    PF *callback = F->timeout_handler;
	    void *cbdata = NULL;
	    F->timeout_handler = NULL;
	    debug(5, 5) ("commCloseAllSockets: FD %d: Calling timeout handler\n",
		fd);
	    if (cbdataReferenceValidDone(F->timeout_data, &cbdata))
		callback(fd, cbdata);
	} else {
	    debug(5, 5) ("commCloseAllSockets: FD %d: calling comm_close()\n", fd);
	    comm_close(fd);
	}
    }
}

void
checkTimeouts(void)
{
    int fd;
    fde *F = NULL;
    PF *callback;
    for (fd = 0; fd <= Biggest_FD; fd++) {
	F = &fd_table[fd];
	if (!F->flags.open)
	    continue;
	if (F->timeout == 0)
	    continue;
	if (F->timeout > squid_curtime)
	    continue;
	debug(5, 5) ("checkTimeouts: FD %d Expired\n", fd);
	if (F->timeout_handler) {
	    debug(5, 5) ("checkTimeouts: FD %d: Call timeout handler\n", fd);
	    callback = F->timeout_handler;
	    F->timeout_handler = NULL;
	    callback(fd, F->timeout_data);
	} else {
	    debug(5, 5) ("checkTimeouts: FD %d: Forcing comm_close()\n", fd);
	    comm_close(fd);
	}
    }
}


int
commDeferRead(int fd)
{
    fde *F = &fd_table[fd];
    if (F->defer_check == NULL)
	return 0;
    return F->defer_check(fd, F->defer_data);
}


/*
 * New-style listen and accept routines
 *
 * Listen simply registers our interest in an FD for listening,
 * and accept takes a callback to call when an FD has been
 * accept()ed.
 */
int
comm_listen(int sock)
{
    int x;
    if ((x = listen(sock, Squid_MaxFD >> 2)) < 0) {
	debug(50, 0) ("comm_listen: listen(%d, %d): %s\n",
	    Squid_MaxFD >> 2,
	    sock, xstrerror());
	return x;
    }
    return sock;
}


/*
 * This callback is called whenever a filedescriptor is ready
 * to dupe itself and fob off an accept()ed connection
 */
static void
comm_accept_try(int fd, void *data)
{
	int newfd;
	fdc_t *Fc;

	assert(fdc_table[fd].active == 1);

	Fc = &(fdc_table[fd]);

	/* Accept a new connection */
	newfd = comm_old_accept(fd, &Fc->accept.pn, &Fc->accept.me);

	if (newfd < 0) {
		/* Issues - check them */
		if (newfd == COMM_NOMESSAGE) {
			/* register interest again */
			commSetSelect(fd, COMM_SELECT_READ, comm_accept_try, NULL, 0);
			return;
		}
		/* Problem! */
		comm_addacceptcallback(fd, -1, Fc->accept.handler, &Fc->accept.pn, &Fc->accept.me, COMM_ERROR, errno, Fc->accept.handler_data);
		Fc->accept.handler = NULL;
		Fc->accept.handler_data = NULL;
		return;
	}

	/* setup our new filedescriptor in fd_table */
	/* and set it up in fdc_table */

	/* queue a completed callback with the new FD */
        comm_addacceptcallback(fd, newfd, Fc->accept.handler, &Fc->accept.pn, &Fc->accept.me, COMM_OK, 0, Fc->accept.handler_data);
	Fc->accept.handler = NULL;
	Fc->accept.handler_data = NULL;

}


/*
 * Notes:
 * + the current interface will queue _one_ accept per io loop.
 *   this isn't very optimal and should be revisited at a later date.
 */
void
comm_accept(int fd, IOACB *handler, void *handler_data)
{
	fdc_t *Fc;

	assert(fd_table[fd].flags.open == 1);
	assert(fdc_table[fd].active == 1);

	/* make sure we're not pending! */
	assert(fdc_table[fd].accept.handler == NULL);

	/* Record our details */
	Fc = &fdc_table[fd];
	Fc->accept.handler = handler;
	Fc->accept.handler_data = handler_data;

	/* Kick off the accept */
#if OPTIMISTIC_IO
	comm_accept_try(fd, NULL);
#else
	commSetSelect(fd, COMM_SELECT_READ, comm_accept_try, NULL, 0);
#endif
}
