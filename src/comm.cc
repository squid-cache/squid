
/*
 * $Id: comm.cc,v 1.428 2006/10/31 23:30:57 wessels Exp $
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "StoreIOBuffer.h"
#include "comm.h"
#include "event.h"
#include "fde.h"
#include "CommIO.h"
#include "CommRead.h"
#include "ConnectionDetail.h"
#include "MemBuf.h"
#include "pconn.h"
#include "SquidTime.h"

#if defined(_SQUID_CYGWIN_)
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

/*
 * New C-like simple comm code. This stuff is a mess and doesn't really buy us anything.
 */

typedef enum {
	IOCB_NONE,
	IOCB_READ,
	IOCB_WRITE
} iocb_type;

struct _comm_io_callback {
	iocb_type type;
	int fd;
	IOCB *callback;
	void *callback_data;
	char *buf;
	FREE *freefunc;
	int size;
	int offset;
	bool active;
	bool completed;
	comm_err_t errcode;
	int xerrno;
	dlink_node node;
};
typedef struct _comm_io_callback comm_io_callback_t;

struct _comm_fd {
	int fd;
	comm_io_callback_t	readcb;
	comm_io_callback_t	writecb;
};
typedef struct _comm_fd comm_fd_t;
comm_fd_t *commfd_table;

dlink_list commfd_completed_events;

bool
commio_has_callback(int fd, iocb_type type, comm_io_callback_t *ccb)
{
	assert(ccb->fd == fd);
	assert(ccb->type == type);
	return ccb->active == true;
}

/*
 * Set the given handler and mark active
 *
 * @param fd		filedescriptor
 * @param ccb		comm io callback
 * @param cb		callback
 * @param cbdata	callback data (must be cbdata'ed)
 * @param buf		buffer, if applicable
 * @param freefunc	freefunc, if applicable
 * @param size		buffer size
 */
void
commio_set_callback(int fd, iocb_type type, comm_io_callback_t *ccb, IOCB *cb, void *cbdata, char *buf, FREE *freefunc, int size)
{
	assert(ccb->active == false);
	assert(ccb->type == type);
	ccb->fd = fd;
	ccb->callback = cb;
	ccb->callback_data = cbdataReference(cbdata);
	ccb->buf = buf;
	ccb->freefunc = freefunc;
	ccb->size = size;
	ccb->active = true;
	ccb->completed = false;
	ccb->offset = 0;
}


/*
 * Complete the callback
 *
 * Someone may have already called this function once on a non-completed callback.
 * This happens in the comm_close() routine - the IO may have completed
 * but comm_close() is called bfeore teh callback has been called.
 * In this case, leave the details the same (offset, for example) but just update
 * the error codes.
 */
void
commio_complete_callback(int fd, comm_io_callback_t *ccb, comm_err_t code, int xerrno)
{
	debug(5, 3) ("commio_complete_callback: called for %d (%d, %d)\n", fd, code, xerrno);
	assert(ccb->active == true);
	assert(ccb->fd == fd);
	ccb->errcode = code;
	ccb->xerrno = xerrno;
	if (! ccb->completed)
		dlinkAddTail(ccb, &ccb->node, &commfd_completed_events);
	ccb->completed = true;
}


/*
 * Cancel the given callback
 *
 * Remember that the data is cbdataRef'ed.
 */
void
commio_cancel_callback(int fd, comm_io_callback_t *ccb)
{
	debug(5, 3) ("commio_cancel_callback: called for %d\n", fd);
	assert(ccb->fd == fd);
	assert(ccb->active == true);

	if (ccb->completed == true) {
		dlinkDelete(&ccb->node, &commfd_completed_events);
	}
	if (ccb->callback_data)
		cbdataReferenceDone(ccb->callback_data);

	ccb->xerrno = 0;
	ccb->active = false;
	ccb->completed = false;
	ccb->callback = NULL;
	ccb->callback_data = NULL;
}

/*
 * Call the given comm callback; assumes the callback is valid.
 * 
 * @param ccb		io completion callback
 */
void
commio_call_callback(comm_io_callback_t *ccb)
{
	comm_io_callback_t cb = *ccb;
	void *cbdata;
	assert(cb.active == true);
	assert(cb.completed == true);
	debug(5, 3) ("commio_call_callback: called for %d\n", ccb->fd);

	/* We've got a copy; blow away the real one */
	/* XXX duplicate code from commio_cancel_callback! */
	dlinkDelete(&ccb->node, &commfd_completed_events);
	ccb->xerrno = 0;
	ccb->active = false;
	ccb->completed = false;
	ccb->callback = NULL;
	ccb->callback_data = NULL;

	/* free data */
	if (cb.freefunc) {
		cb.freefunc(cb.buf);
		cb.buf = NULL;
	}
	if (cb.callback && cbdataReferenceValidDone(cb.callback_data, &cbdata)) {
		/* XXX truely ugly for now! */
		cb.callback(cb.fd, cb.buf, cb.offset, cb.errcode, cb.xerrno, cbdata);
	}
}

void
commio_call_callbacks(void)
{
	comm_io_callback_t *ccb;
	while (commfd_completed_events.head != NULL) {
		ccb = (comm_io_callback_t *) commfd_completed_events.head->data;
		commio_call_callback(ccb);
	}
}


class ConnectStateData
{

public:
    void *operator new (size_t);
    void operator delete (void *);
    static void Connect (int fd, void *me);
    void connect();
    void callCallback(comm_err_t status, int xerrno);
    void defaults();
    char *host;
    u_short port;

    struct sockaddr_in S;
    CallBack<CNCB> callback;

    struct IN_ADDR in_addr;
    int fd;
    int tries;
    int addrcount;
    int connstart;

private:
    int commResetFD();
    int commRetryConnect();
    CBDATA_CLASS(ConnectStateData);
};

/* STATIC */

static comm_err_t commBind(int s, struct IN_ADDR, u_short port);
static void commSetReuseAddr(int);
static void commSetNoLinger(int);
#ifdef TCP_NODELAY
static void commSetTcpNoDelay(int);
#endif
static void commSetTcpRcvbuf(int, int);
static PF commConnectFree;
static PF commHandleWrite;
static IPH commConnectDnsHandle;
static void requireOpenAndActive(int const fd);

static PF comm_accept_try;

class AcceptFD
{

public:
    AcceptFD() : count(0), finished_(false){}

    void doCallback(int fd, int newfd, comm_err_t errcode, int xerrno, ConnectionDetail *);
    void nullCallback();
    void beginAccepting() {count = 0; finished(false);}

    size_t acceptCount() const { return count;}

    bool finishedAccepting() const;
    CallBack<IOACB> callback;
    bool finished() const;
    void finished(bool);

private:
    static size_t const MAX_ACCEPT_PER_LOOP;
    size_t count;
    bool finished_;
};

size_t const AcceptFD::MAX_ACCEPT_PER_LOOP(10);

class fdc_t
{

public:
    void acceptOne(int fd);
    void beginAccepting();
    int acceptCount() const;
    fdc_t() : active(0), fd(-1), half_closed (false){CommCallbackList.head = NULL;CommCallbackList.tail = NULL; }

    fdc_t(int anFD) : active(0), fd(anFD), half_closed(false)
    {
        CommCallbackList.head = NULL;
        CommCallbackList.tail = NULL;
    }

    int active;
    int fd;
    dlink_list CommCallbackList;

    template<class P>
    bool findCallback(P predicate);

    class Accept
    {

    public:
        AcceptFD accept;
        ConnectionDetail connDetails;
    };

    Accept accept;

    bool half_closed;
};

typedef enum {
    COMM_CB_READ = 1,
    COMM_CB_DERIVED,
} comm_callback_t;

static int CommCallbackSeqnum = 1;

class CommCommonCallback
{

public:
    CommCommonCallback() : fd (-1), errcode (COMM_OK), xerrno(0), seqnum (CommCallbackSeqnum){}

    CommCommonCallback(int anFD, comm_err_t errcode, int anErrno) : fd (anFD), errcode (errcode), xerrno(anErrno), seqnum (CommCallbackSeqnum){}

    int fd;
    comm_err_t errcode;
    int xerrno;
    int seqnum;
};

class CommCallbackData
{

public:
    MEMPROXY_CLASS(CommCallbackData);
    CommCallbackData(CommCommonCallback const &);
    virtual ~CommCallbackData() {}

    virtual comm_callback_t getType() const { return COMM_CB_DERIVED; }

    void callACallback();
    void fdClosing();
    virtual void callCallback() = 0;
    void registerSelf();
    void deRegisterSelf();
    char *buf;
    StoreIOBuffer sb;

protected:
    CommCommonCallback result;
    friend void _comm_close(int fd, char const *file, int line);
    friend void comm_calliocallback(void);

private:
    dlink_node fd_node;
    dlink_node h_node;
};

MEMPROXY_CLASS_INLINE(CommCallbackData)

class CommAcceptCallbackData : public CommCallbackData
{

public:
    MEMPROXY_CLASS(CommAcceptCallbackData);
    CommAcceptCallbackData(int const anFd, CallBack<IOACB>, comm_err_t, int, int, ConnectionDetail const &);
    virtual void callCallback();

private:
    CallBack<IOACB> callback;
    int newfd;
    ConnectionDetail details;
};

MEMPROXY_CLASS_INLINE(CommAcceptCallbackData)

class CommFillCallbackData : public CommCallbackData
{

public:
    MEMPROXY_CLASS(CommFillCallbackData);
    CommFillCallbackData(int const anFd, CallBack<IOFCB> aCallback, comm_err_t, int);
    virtual void callCallback();

private:
    CallBack<IOFCB> callback;
};

MEMPROXY_CLASS_INLINE(CommFillCallbackData)

struct _fd_debug_t
{
    char const *close_file;
    int close_line;
};

typedef struct _fd_debug_t fd_debug_t;

static MemAllocator *conn_close_pool = NULL;
fdc_t *fdc_table = NULL;
fd_debug_t *fdd_table = NULL;
dlink_list CommCallbackList;


/* New and improved stuff */

CommCallbackData::CommCallbackData(CommCommonCallback const &newResults) : result (newResults)
{
    assert(fdc_table[result.fd].active == 1);
    registerSelf();
}

CommAcceptCallbackData::CommAcceptCallbackData(int const anFd, CallBack<IOACB> aCallback, comm_err_t anErrcode, int anErrno, int aNewFD, ConnectionDetail const &newDetails) :CommCallbackData(CommCommonCallback(anFd, anErrcode, anErrno)), callback (aCallback), newfd(aNewFD), details(newDetails)
{}

void
CommCallbackData::registerSelf()
{
    /* Add it to the end of the list */
    dlinkAddTail(this, &h_node, &CommCallbackList);

    /* and add it to the end of the fd list */
    dlinkAddTail(this, &fd_node, &(fdc_table[result.fd].CommCallbackList));
}

void
CommCallbackData::deRegisterSelf()
{
    dlinkDelete(&h_node, &CommCallbackList);
    dlinkDelete(&fd_node, &(fdc_table[result.fd].CommCallbackList));
}

/*
 * add an IO callback
 *
 * IO callbacks are added when we want to notify someone that some IO
 * has finished but we don't want to risk re-entering a non-reentrant
 * code block.
 */
void
CommAcceptCallbackData::callCallback()
{
    PROF_start(CommAcceptCallbackData_callCallback);
    callback.handler(result.fd, newfd, &details, result.errcode, result.xerrno, callback.data);
    PROF_stop(CommAcceptCallbackData_callCallback);
}

void
CommCallbackData::fdClosing()
{
    result.errcode = COMM_ERR_CLOSING;
}

void
CommCallbackData::callACallback()
{
    assert(fdc_table[result.fd].active == 1);
    deRegisterSelf();
    callCallback();
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
    int oldseqnum = CommCallbackSeqnum++;

    /* Call our callbacks until we hit NULL or the seqnum changes */

    /* This will likely rap other counts - again, thats ok (for now)
     * What we should see is the total of the various callback subclasses
     * equaling this counter.
     * If they don't, someone has added a class but not profiled it.
     */
    PROF_start(comm_calliocallback);

    debug(5, 7) ("comm_calliocallback: %p\n", CommCallbackList.head);

    while (CommCallbackList.head != NULL && oldseqnum != ((CommCallbackData *)CommCallbackList.head->data)->result.seqnum) {
        dlink_node *node = (dlink_node *)CommCallbackList.head;
        cio = (CommCallbackData *)node->data;
        cio->callACallback();
        delete cio;
    }

    PROF_stop(comm_calliocallback);
}

bool
comm_iocallbackpending(void)
{
    debug(5, 7) ("comm_iocallbackpending: %p\n", CommCallbackList.head);
    return (CommCallbackList.head != NULL) || (commfd_completed_events.head != NULL);
}

/*
 * Attempt a read
 *
 * If the read attempt succeeds or fails, call the callback.
 * Else, wait for another IO notification.
 */
void
commHandleRead(int fd, void *data)
{
    comm_io_callback_t *ccb = (comm_io_callback_t *) data;
    
    assert(data == COMMIO_FD_READCB(fd));
    assert(commio_has_callback(fd, IOCB_READ, ccb));
    /* Attempt a read */
    statCounter.syscalls.sock.reads++;
    errno = 0;
    int retval;
    retval = FD_READ_METHOD(fd, ccb->buf, ccb->size);
    debug(5, 3) ("comm_read_try: FD %d, size %d, retval %d, errno %d\n",
                 fd, ccb->size, retval, errno);

    if (retval < 0 && !ignoreErrno(errno)) {
        debug(5, 3) ("comm_read_try: scheduling COMM_ERROR\n");
	ccb->offset = 0;
	commio_complete_callback(fd, ccb, COMM_ERROR, errno);
        return;
    };

    /* See if we read anything */
    /* Note - read 0 == socket EOF, which is a valid read */
    if (retval >= 0) {
        fd_bytes(fd, retval, FD_READ);
	ccb->offset = retval;
	commio_complete_callback(fd, ccb, COMM_OK, errno);
        return;
    }

    /* Nope, register for some more IO */
    commSetSelect(fd, COMM_SELECT_READ, commHandleRead, data, 0);
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
    assert(!fd_table[fd].flags.closing);

    debug(5,4)("comm_read, queueing read for FD %d\n",fd);

    /* Queue the read */
    /* XXX ugly */
    commio_set_callback(fd, IOCB_READ, COMMIO_FD_READCB(fd), handler, handler_data, (char *)buf, NULL, size);
    commSetSelect(fd, COMM_SELECT_READ, commHandleRead, COMMIO_FD_READCB(fd), 0);
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
        while (FD_READ_METHOD(fd, buf, SQUID_TCP_SO_RCVBUF) > 0)

            ;
#endif
}

static void
requireOpenAndActive(int const fd)
{
    assert(fd_table[fd].flags.open == 1);
    assert(fdc_table[fd].active == 1);
}

/*
 * Return whether the FD has a pending completed callback.
 */
int
comm_has_pending_read_callback(int fd)
{
    requireOpenAndActive(fd);
    return COMMIO_FD_READCB(fd)->active && COMMIO_FD_READCB(fd)->completed;
}

template <class P>
bool
fdc_t::findCallback(P predicate)
{
    /*
     * XXX I don't like having to walk the list!
     * Instead, if this routine is called often enough, we should
     * also maintain a linked list of _read_ events - we can just
     * check if the list head a HEAD..
     * - adrian
     */
    dlink_node *node = CommCallbackList.head;

    while (node != NULL) {
        if (predicate((CommCallbackData *)node->data))
            return true;

        node = node->next;
    }

    /* Not found */
    return false;
}

/*
 * return whether a file descriptor has a read handler
 *
 * Assumptions: the fd is open
 * 		the fd is a comm fd.
 *
 * Again - is this "pending read", or "pending completed event", or what?
 * I'll assume its pending read, not pending completed.
 *
 * This makes no sense though - if this is called to check whether there's
 * a pending read -before- submitting a read then it won't matter whether
 * its completed or not! Ie:
 *
 * + if there's no read and you want to schedule one; fine.
 * + if a read has completed then the callback block has been deactivated before
 *   the callback is called - if something decides to register for a read
 *   callback once again it should find !active and !completed.
 * + scheduling a read event when the fd is ! active -and- completed, thats
 *   a bug
 * + like, afaict, anything else is.
 */
bool
comm_has_pending_read(int fd)
{
    requireOpenAndActive(fd);
    return COMMIO_FD_READCB(fd)->active && (! COMMIO_FD_READCB(fd)->completed);
}

/*
 * Cancel a pending read. Assert that we have the right parameters,
 * and that there are no pending read events!
 *
 * AHC Don't call the comm handlers?
 */
void
comm_read_cancel(int fd, IOCB *callback, void *data)
{
    requireOpenAndActive(fd);

    /* Ok, we can be reasonably sure we won't lose any data here! */
    assert(COMMIO_FD_READCB(fd)->callback == callback);
    assert(COMMIO_FD_READCB(fd)->callback_data == data);

    /* Delete the callback */
    commio_cancel_callback(fd, COMMIO_FD_READCB(fd));

    /* And the IO event */
    commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
}


/*
 * Open a filedescriptor, set some sane defaults
 * XXX DPW 2006-05-30 what is the point of this?
 */
void
fdc_open(int fd, unsigned int type, char const *desc)
{
    assert(fdc_table[fd].active == 0);

    fdc_table[fd].active = 1;
    fdc_table[fd].fd = fd;
    fd_open(fd, type, desc);
}


/*
 * synchronous wrapper around udp socket functions
 */

int
comm_udp_recvfrom(int fd, void *buf, size_t len, int flags,

                  struct sockaddr *from, socklen_t *fromlen)
{
    statCounter.syscalls.sock.recvfroms++;
    return recvfrom(fd, buf, len, flags, from, fromlen);
}

int
comm_udp_recv(int fd, void *buf, size_t len, int flags)
{
    return comm_udp_recvfrom(fd, buf, len, flags, NULL, 0);
}

ssize_t
comm_udp_send(int s, const void *buf, size_t len, int flags)
{
    return send(s, buf, len, flags);
}


bool
comm_has_incomplete_write(int fd)
{
    requireOpenAndActive(fd);
    return COMMIO_FD_WRITECB(fd)->active;
}

/*
 * Queue a write. handler/handler_data are called when the write fully
 * completes, on error, or on file descriptor close.
 */

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

commBind(int s, struct IN_ADDR in_addr, u_short port)
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

          struct IN_ADDR addr,
          u_short port,
          int flags,
          const char *note)
{
    return comm_openex(sock_type, proto, addr, port, flags, 0, note);
}

static bool
limitError(int const anErrno)
{
    return anErrno == ENFILE || anErrno == EMFILE;
}

/* Create a socket. Default is blocking, stream (TCP) socket.  IO_TYPE
 * is OR of flags specified in defines.h:COMM_* */
int
comm_openex(int sock_type,
            int proto,

            struct IN_ADDR addr,
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

    if ((new_socket = socket(AF_INET, sock_type, proto)) < 0)
    {
        /* Increase the number of reserved fd's if calls to socket()
         * are failing because the open file table is full.  This
         * limits the number of simultaneous clients */

        if (limitError(errno)) {
            debug(50, 1) ("comm_open: socket failure: %s\n", xstrerror());
            fdAdjustReserved();
        } else {
            debug(50, 0) ("comm_open: socket failure: %s\n", xstrerror());
        }

        PROF_stop(comm_open);
        return -1;
    }

    /* set TOS if needed */
    if (TOS)
    {
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

    if (port > (u_short) 0)
    {
#ifdef _SQUID_MSWIN_

        if (sock_type != SOCK_DGRAM)
#endif

            commSetNoLinger(new_socket);

        if (opt_reuseaddr)
            commSetReuseAddr(new_socket);
    }

    if (addr.s_addr != no_addr.s_addr)
    {
        if (commBind(new_socket, addr, port) != COMM_OK) {
            comm_close(new_socket);
            return -1;
            PROF_stop(comm_open);
        }
    }

    F->local_port = port;

    if (flags & COMM_NONBLOCKING)
        if (commSetNonBlocking(new_socket) == COMM_ERROR)
        {
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

CBDATA_CLASS_INIT(ConnectStateData);

void *
ConnectStateData::operator new (size_t size)
{
    CBDATA_INIT_TYPE(ConnectStateData);
    return cbdataAlloc(ConnectStateData);
}

void
ConnectStateData::operator delete (void *address)
{
    cbdataFree(address);
}

void
commConnectStart(int fd, const char *host, u_short port, CNCB * callback, void *data)
{
    ConnectStateData *cs;
    debug(5, 3) ("commConnectStart: FD %d, data %p, %s:%d\n", fd, data, host, (int) port);
    cs = new ConnectStateData;
    cs->fd = fd;
    cs->host = xstrdup(host);
    cs->port = port;
    cs->callback = CallBack<CNCB>(callback, data);
    comm_add_close_handler(fd, commConnectFree, cs);
    ipcache_nbgethostbyname(host, commConnectDnsHandle, cs);
}

static void
commConnectDnsHandle(const ipcache_addrs * ia, void *data)
{
    ConnectStateData *cs = (ConnectStateData *)data;

    if (ia == NULL) {
        debug(5, 3) ("commConnectDnsHandle: Unknown host: %s\n", cs->host);

        if (!dns_error_message) {
            dns_error_message = "Unknown DNS error";
            debug(5, 1) ("commConnectDnsHandle: Bad dns_error_message\n");
        }

        assert(dns_error_message != NULL);
        cs->callCallback(COMM_ERR_DNS, 0);
        return;
    }

    assert(ia->cur < ia->count);
    cs->in_addr = ia->in_addrs[ia->cur];

    if (Config.onoff.balance_on_multiple_ip)
        ipcacheCycleAddr(cs->host, NULL);

    cs->addrcount = ia->count;

    cs->connstart = squid_curtime;

    cs->connect();
}

void
ConnectStateData::callCallback(comm_err_t status, int xerrno)
{
    debug(5, 3) ("commConnectCallback: FD %d, data %p\n", fd, callback.data);
    comm_remove_close_handler(fd, commConnectFree, this);
    CallBack<CNCB> aCallback = callback;
    callback = CallBack<CNCB>();
    commSetTimeout(fd, -1, NULL, NULL);

    if (aCallback.dataValid())
        aCallback.handler(fd, status, xerrno, aCallback.data);

    commConnectFree(fd, this);
}

static void
commConnectFree(int fd, void *data)
{
    ConnectStateData *cs = (ConnectStateData *)data;
    debug(5, 3) ("commConnectFree: FD %d\n", fd);
    cs->callback = CallBack<CNCB>();
    safe_free(cs->host);
    delete cs;
}

static void
copyFDFlags(int to, fde *F)
{
    if (F->flags.close_on_exec)
        commSetCloseOnExec(to);

    if (F->flags.nonblocking)
        commSetNonBlocking(to);

#ifdef TCP_NODELAY

    if (F->flags.nodelay)
        commSetTcpNoDelay(to);

#endif

    if (Config.tcpRcvBufsz > 0)
        commSetTcpRcvbuf(to, Config.tcpRcvBufsz);
}

/* Reset FD so that we can connect() again */
int
ConnectStateData::commResetFD()
{
    if (!cbdataReferenceValid(callback.data))
        return 0;

    statCounter.syscalls.sock.sockets++;

    int fd2 = socket(AF_INET, SOCK_STREAM, 0);

    if (fd2 < 0) {
        debug(5, 0) ("commResetFD: socket: %s\n", xstrerror());

        if (ENFILE == errno || EMFILE == errno)
            fdAdjustReserved();

        return 0;
    }

#ifdef _SQUID_MSWIN_

    /* On Windows dup2() can't work correctly on Sockets, the          */
    /* workaround is to close the destination Socket before call them. */
    close(fd);

#endif

    if (dup2(fd2, fd) < 0) {
        debug(5, 0) ("commResetFD: dup2: %s\n", xstrerror());

        if (ENFILE == errno || EMFILE == errno)
            fdAdjustReserved();

        close(fd2);

        return 0;
    }

    close(fd2);
    fde *F = &fd_table[fd];
    fd_table[fd].flags.called_connect = 0;
    /*
     * yuck, this has assumptions about comm_open() arguments for
     * the original socket
     */

    if (commBind(fd, F->local_addr, F->local_port) != COMM_OK) {
        debug(5, 0) ("commResetFD: bind: %s\n", xstrerror());
        return 0;
    }

#ifdef IP_TOS
    if (F->tos) {
        if (setsockopt(fd, IPPROTO_IP, IP_TOS, (char *) &F->tos, sizeof(int)) < 0)
            debug(50, 1) ("commResetFD: setsockopt(IP_TOS) on FD %d: %s\n", fd, xstrerror());
    }

#endif
    copyFDFlags (fd, F);

    return 1;
}

int
ConnectStateData::commRetryConnect()
{
    assert(addrcount > 0);

    if (addrcount == 1) {
        if (tries >= Config.retry.maxtries)
            return 0;

        if (squid_curtime - connstart > Config.Timeout.connect)
            return 0;
    } else {
        if (tries > addrcount)
            return 0;
    }

    return commResetFD();
}

static void
commReconnect(void *data)
{
    ConnectStateData *cs = (ConnectStateData *)data;
    ipcache_nbgethostbyname(cs->host, commConnectDnsHandle, cs);
}

/* Connect SOCK to specified DEST_PORT at DEST_HOST. */
void
ConnectStateData::Connect (int fd, void *me)
{
    ConnectStateData *cs = (ConnectStateData *)me;
    assert (cs->fd == fd);
    cs->connect();
}

void
ConnectStateData::defaults()
{
    S.sin_family = AF_INET;
    S.sin_addr = in_addr;
    S.sin_port = htons(port);
}

void
ConnectStateData::connect()
{
    if (S.sin_addr.s_addr == 0)
        defaults();

    switch (comm_connect_addr(fd, &S)) {

    case COMM_INPROGRESS:
        debug(5, 5) ("ConnectStateData::connect: FD %d: COMM_INPROGRESS\n", fd);
        commSetSelect(fd, COMM_SELECT_WRITE, ConnectStateData::Connect, this, 0);
        break;

    case COMM_OK:
        ipcacheMarkGoodAddr(host, S.sin_addr);
        callCallback(COMM_OK, 0);
        break;

    default:
        tries++;
        ipcacheMarkBadAddr(host, S.sin_addr);

        if (Config.onoff.test_reachability)
            netdbDeleteAddrNetwork(S.sin_addr);

        if (commRetryConnect()) {
            eventAdd("commReconnect", commReconnect, this, this->addrcount == 1 ? 0.05 : 0.0, 0);
        } else {
            callCallback(COMM_ERR_CONNECT, errno);
        }
    }
}

int
commSetTimeout(int fd, int timeout, PF * handler, void *data)
{
    debug(5, 3) ("commSetTimeout: FD %d timeout %d\n", fd, timeout);
    assert(fd >= 0);
    assert(fd < Squid_MaxFD);
    fde *F = &fd_table[fd];
    assert(F->flags.open);

    if (timeout < 0) {
        cbdataReferenceDone(F->timeout_data);
        F->timeout_handler = NULL;
        F->timeout = 0;
    } else {
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

    if (!F->flags.called_connect)
    {
        F->flags.called_connect = 1;
        statCounter.syscalls.sock.connects++;

        x = connect(sock, (struct sockaddr *) address, sizeof(*address));

        if (x < 0)
            debug(5, 9) ("connect FD %d: %s\n", sock, xstrerror());
    } else
    {
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

    if (status == COMM_OK)
    {
        debug(5, 10) ("comm_connect_addr: FD %d connected to %s:%d\n",
                      sock, F->ipaddr, F->remote_port);
    } else if (status == COMM_INPROGRESS)
    {
        debug(5, 10) ("comm_connect_addr: FD %d connection pending\n", sock);
    }

    return status;
}

/* Wait for an incoming connection on FD.  FD should be a socket returned
 * from comm_listen. */
static int
comm_old_accept(int fd, ConnectionDetail &details)
{
    PROF_start(comm_accept);
    statCounter.syscalls.sock.accepts++;
    int sock;
    socklen_t Slen = sizeof(details.peer);

    if ((sock = accept(fd, (struct sockaddr *) &details.peer, &Slen)) < 0) {
        PROF_stop(comm_accept);

        if (ignoreErrno(errno))
        {
            debug(50, 5) ("comm_old_accept: FD %d: %s\n", fd, xstrerror());
            return COMM_NOMESSAGE;
        } else if (ENFILE == errno || EMFILE == errno)
        {
            debug(50, 3) ("comm_old_accept: FD %d: %s\n", fd, xstrerror());
            return COMM_ERROR;
        } else
        {
            debug(50, 1) ("comm_old_accept: FD %d: %s\n", fd, xstrerror());
            return COMM_ERROR;
        }
    }

    Slen = sizeof(details.me);
    memset(&details.me, '\0', Slen);

    getsockname(sock, (struct sockaddr *) &details.me, &Slen);
    commSetCloseOnExec(sock);
    /* fdstat update */
    fd_open(sock, FD_SOCKET, "HTTP Request");
    fdd_table[sock].close_file = NULL;
    fdd_table[sock].close_line = 0;
    fdc_table[sock].active = 1;
    fde *F = &fd_table[sock];
    xstrncpy(F->ipaddr, inet_ntoa(details.peer.sin_addr), 16);
    F->remote_port = htons(details.peer.sin_port);
    F->local_port = htons(details.me.sin_port);
    commSetNonBlocking(sock);
    PROF_stop(comm_accept);
    return sock;
}

void
commCallCloseHandlers(int fd)
{
    fde *F = &fd_table[fd];
    debug(5, 5) ("commCallCloseHandlers: FD %d\n", fd);

    while (F->closeHandler != NULL) {
        close_handler ch = *F->closeHandler;
        conn_close_pool->free(F->closeHandler);	/* AAA */
        F->closeHandler = ch.next;
        ch.next = NULL;
        debug(5, 5) ("commCallCloseHandlers: ch->handler=%p data=%p\n", ch.handler, ch.data);

        if (cbdataReferenceValid(ch.data))
            ch.handler(fd, ch.data);

        cbdataReferenceDone(ch.data);
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

void
CommRead::nullCallback()
{
    callback = CallBack<IOCB>();
}

void
AcceptFD::nullCallback()
{
    callback = CallBack<IOACB>();
}

void
CommRead::doCallback(comm_err_t errcode, int xerrno)
{
    if (callback.handler)
        callback.handler(fd, buf, 0, errcode, xerrno, callback.data);

    nullCallback();
}

void
AcceptFD::doCallback(int fd, int newfd, comm_err_t errcode, int xerrno, ConnectionDetail *connDetails)
{
    if (callback.handler) {
        CallBack<IOACB> aCallback = callback;
        nullCallback();
        aCallback.handler(fd, newfd, connDetails, errcode, xerrno, aCallback.data);
    }
}

/*
 * Close the socket fd.
 *
 * + call write handlers with ERR_CLOSING
 * + call read handlers with ERR_CLOSING
 * + call closing handlers
 *
 * NOTE: COMM_ERR_CLOSING will NOT be called for CommReads' sitting in a 
 * DeferredReadManager.
 */
void
_comm_close(int fd, char const *file, int line)
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
    assert(fdc_table[fd].active == 1);

    assert(F->type != FD_FILE);

    PROF_start(comm_close);

    F->flags.closing = 1;

#if USE_SSL

    if (F->ssl)
        ssl_shutdown_method(fd);

#endif

    commSetTimeout(fd, -1, NULL, NULL);

    /* new-style read/write handler stuff */
    if (commio_has_callback(fd, IOCB_WRITE, COMMIO_FD_WRITECB(fd))) {
        commio_complete_callback(fd, COMMIO_FD_WRITECB(fd), COMM_ERR_CLOSING, errno);
        commio_call_callback(COMMIO_FD_WRITECB(fd));
    }
    if (commio_has_callback(fd, IOCB_READ, COMMIO_FD_READCB(fd))) {
        commio_complete_callback(fd, COMMIO_FD_READCB(fd), COMM_ERR_CLOSING, errno);
        commio_call_callback(COMMIO_FD_READCB(fd));
    }

    /* Do callbacks for read/accept routines, if any */
    fdc_table[fd].accept.accept.doCallback(fd, -1, COMM_ERR_CLOSING, 0, NULL);

    /* Complete (w/ COMM_ERR_CLOSING!) any pending io callbacks */
    while (fdc_table[fd].CommCallbackList.head != NULL) {
        node = fdc_table[fd].CommCallbackList.head;
        cio = (CommCallbackData *)node->data;
        assert(fd == cio->result.fd); /* just paranoid */
        /* We're closing! */
        cio->fdClosing();
        cio->callACallback();
        delete cio;
    }

    commCallCloseHandlers(fd);

    if (F->pconn.uses)
        F->pconn.pool->count(F->pconn.uses);

    comm_empty_os_read_buffers(fd);

#if USE_SSL

    if (F->ssl) {
        SSL_free(F->ssl);
        F->ssl = NULL;
    }

#endif
    fd_close(fd);		/* update fdstat */

    close(fd);

    fdc_table[fd].active = 0;

    if (fdc_table[fd].half_closed) {
        AbortChecker::Instance().stopMonitoring(fd);
        fdc_table[fd].half_closed = false;
    }

    fdc_table[fd] = fdc_t(fd);

    statCounter.syscalls.sock.closes++;

    PROF_stop(comm_close);
    /* When an fd closes, give accept() a chance, if need be */

    if (fdNFree() >= RESERVED_FD)
        AcceptLimiter::Instance().kick();
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

    if (x >= 0)
        return x;

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

void
comm_add_close_handler(int fd, PF * handler, void *data)
{
    close_handler *newHandler = (close_handler *)conn_close_pool->alloc();		/* AAA */
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
    assert (fdc_table[fd].active);
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

    conn_close_pool->free(p);
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
#ifndef _SQUID_MSWIN_
    int flags;
    int dummy = 0;
#endif
#ifdef _SQUID_WIN32_

    int nonblocking = TRUE;

#ifdef _SQUID_CYGWIN_

    if (fd_table[fd].type != FD_PIPE) {
#endif

        if (ioctl(fd, FIONBIO, &nonblocking) < 0) {
            debug(50, 0) ("commSetNonBlocking: FD %d: %s %d\n", fd, xstrerror(), fd_table[fd].type);
            return COMM_ERROR;
        }

#ifdef _SQUID_CYGWIN_

    } else {
#endif
#endif
#ifndef _SQUID_MSWIN_

        if ((flags = fcntl(fd, F_GETFL, dummy)) < 0) {
            debug(50, 0) ("FD %d: fcntl F_GETFL: %s\n", fd, xstrerror());
            return COMM_ERROR;
        }

        if (fcntl(fd, F_SETFL, flags | SQUID_NONBLOCK) < 0) {
            debug(50, 0) ("commSetNonBlocking: FD %d: %s\n", fd, xstrerror());
            return COMM_ERROR;
        }

#endif
#ifdef _SQUID_CYGWIN_

    }

#endif
    fd_table[fd].flags.nonblocking = 1;

    return 0;
}

int
commUnsetNonBlocking(int fd)
{
#ifdef _SQUID_MSWIN_
    int nonblocking = FALSE;

    if (ioctlsocket(fd, FIONBIO, (unsigned long *) &nonblocking) < 0) {
#else
    int flags;
    int dummy = 0;

    if ((flags = fcntl(fd, F_GETFL, dummy)) < 0) {
        debug(50, 0) ("FD %d: fcntl F_GETFL: %s\n", fd, xstrerror());
        return COMM_ERROR;
    }

    if (fcntl(fd, F_SETFL, flags & (~SQUID_NONBLOCK)) < 0) {
#endif
        debug(50, 0) ("commUnsetNonBlocking: FD %d: %s\n", fd, xstrerror());
        return COMM_ERROR;
    }

    fd_table[fd].flags.nonblocking = 0;
    return 0;
}

void
commSetCloseOnExec(int fd) {
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
commSetTcpNoDelay(int fd) {
    int on = 1;

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof(on)) < 0)
        debug(50, 1) ("commSetTcpNoDelay: FD %d: %s\n", fd, xstrerror());

    fd_table[fd].flags.nodelay = 1;
}

#endif


void
comm_init(void) {
    fd_table =(fde *) xcalloc(Squid_MaxFD, sizeof(fde));
    fdd_table = (fd_debug_t *)xcalloc(Squid_MaxFD, sizeof(fd_debug_t));
    fdc_table = new fdc_t[Squid_MaxFD];
    commfd_table = (comm_fd_t *) xcalloc(Squid_MaxFD, sizeof(comm_fd_t));

    for (int pos = 0; pos < Squid_MaxFD; ++pos) {
        fdc_table[pos] = fdc_t(pos);
    }
    for (int pos = 0; pos < Squid_MaxFD; pos++) {
	commfd_table[pos].fd = pos;
	commfd_table[pos].readcb.fd = pos;
	commfd_table[pos].readcb.type = IOCB_READ;
	commfd_table[pos].writecb.fd = pos;
	commfd_table[pos].writecb.type = IOCB_WRITE;
    }

    /* XXX account fd_table */
    /* Keep a few file descriptors free so that we don't run out of FD's
     * after accepting a client but before it opens a socket or a file.
     * Since Squid_MaxFD can be as high as several thousand, don't waste them */
    RESERVED_FD = XMIN(100, Squid_MaxFD / 4);

    conn_close_pool = memPoolCreate("close_handler", sizeof(close_handler));
}

/* Write to FD. */
static void
commHandleWrite(int fd, void *data) {
    comm_io_callback_t *state = (comm_io_callback_t *)data;
    int len = 0;
    int nleft;

    assert(state == COMMIO_FD_WRITECB(fd));

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

        commio_complete_callback(fd, COMMIO_FD_WRITECB(fd), nleft ? COMM_ERROR : COMM_OK, errno);
    } else if (len < 0) {
        /* An error */

        if (fd_table[fd].flags.socket_eof) {
            debug(50, 2) ("commHandleWrite: FD %d: write failure: %s.\n",
                          fd, xstrerror());
            commio_complete_callback(fd, COMMIO_FD_WRITECB(fd), nleft ? COMM_ERROR : COMM_OK, errno);
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
            commio_complete_callback(fd, COMMIO_FD_WRITECB(fd), nleft ? COMM_ERROR : COMM_OK, errno);
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
            commio_complete_callback(fd, COMMIO_FD_WRITECB(fd), nleft ? COMM_OK : COMM_ERROR, errno);
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
comm_write(int fd, const char *buf, int size, IOCB * handler, void *handler_data, FREE * free_func)
{
    assert(!fd_table[fd].flags.closing);

    debug(5, 5) ("comm_write: FD %d: sz %d: hndl %p: data %p.\n",
                 fd, size, handler, handler_data);

    if (commio_has_callback(fd, IOCB_WRITE, COMMIO_FD_WRITECB(fd))) {
        /* This means that the write has been scheduled, but has not
         * triggered yet 
         */
        fatalf ("comm_write: fd %d: pending callback!\n", fd);
    }
    /* XXX ugly */
    commio_set_callback(fd, IOCB_WRITE, COMMIO_FD_WRITECB(fd), handler, handler_data, (char *)buf, free_func, size);
    commSetSelect(fd, COMM_SELECT_WRITE, commHandleWrite, COMMIO_FD_WRITECB(fd), 0);
}

/* a wrapper around comm_write to allow for MemBuf to be comm_written in a snap */
void
comm_write_mbuf(int fd, MemBuf *mb, IOCB * handler, void *handler_data) {
    comm_write(fd, mb->buf, mb->size, handler, handler_data, mb->freeFunc());
}


/*
 * hm, this might be too general-purpose for all the places we'd
 * like to use it.
 */
int
ignoreErrno(int ierrno) {
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
commCloseAllSockets(void) {
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

static bool
AlreadyTimedOut(fde *F) {
    if (!F->flags.open)
        return true;

    if (F->timeout == 0)
        return true;

    if (F->timeout > squid_curtime)
        return true;

    return false;
}

void
checkTimeouts(void) {
    int fd;
    fde *F = NULL;
    PF *callback;

    for (fd = 0; fd <= Biggest_FD; fd++) {
        F = &fd_table[fd];

        if (AlreadyTimedOut(F))
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

/*
 * New-style listen and accept routines
 *
 * Listen simply registers our interest in an FD for listening,
 * and accept takes a callback to call when an FD has been
 * accept()ed.
 */
int
comm_listen(int sock) {
    int x;

    if ((x = listen(sock, Squid_MaxFD >> 2)) < 0) {
        debug(50, 0) ("comm_listen: listen(%d, %d): %s\n",
                      Squid_MaxFD >> 2,
                      sock, xstrerror());
        return x;
    }

    return sock;
}

void
fdc_t::beginAccepting() {
    accept.accept.beginAccepting();
}

int
fdc_t::acceptCount() const {
    return accept.accept.acceptCount();
}

void
fdc_t::acceptOne(int fd) {
    // If there is no callback and we accept, we will leak the accepted FD.
    // When we are running out of FDs, there is often no callback.
    if (!accept.accept.callback.handler) {
        debug (5,5) ("fdc_t::acceptOne orphaned: FD %d\n", fd);
        // XXX: can we remove this and similar "just in case" calls and 
        // either listen always or listen only when there is a callback?
        if (!AcceptLimiter::Instance().deferring())
            commSetSelect(fd, COMM_SELECT_READ, comm_accept_try, NULL, 0);
        accept.accept.finished(true);
        return;
    }

    /*
     * We don't worry about running low on FDs here.  Instead,
     * httpAccept() will use AcceptLimiter if we reach the limit
     * there.
     */

    /* Accept a new connection */
    int newfd = comm_old_accept(fd, accept.connDetails);

    /* Check for errors */

    if (newfd < 0) {
        if (newfd == COMM_NOMESSAGE) {
            /* register interest again */
            debug (5,5) ("fdc_t::acceptOne eof: FD %d handler: %p\n", fd, (void*)accept.accept.callback.handler);
            commSetSelect(fd, COMM_SELECT_READ, comm_accept_try, NULL, 0);
            accept.accept.finished(true);
            return;
        }

        /* A non-recoverable error - register an error callback */
        new CommAcceptCallbackData(fd, accept.accept.callback, COMM_ERROR, errno, -1, accept.connDetails);

        accept.accept.callback = CallBack<IOACB>();

        accept.accept.finished(true);

        return;
    }

    debug (5,5) ("fdc_t::acceptOne accepted: FD %d handler: %p newfd: %d\n", fd, (void*)accept.accept.callback.handler, newfd);

    assert(accept.accept.callback.handler);
    accept.accept.doCallback(fd, newfd, COMM_OK, 0, &accept.connDetails);

    /* If we weren't re-registed, don't bother trying again! */

    if (accept.accept.callback.handler == NULL)
        accept.accept.finished(true);
}

bool
AcceptFD::finished() const {
    return finished_;
}

void
AcceptFD::finished(bool newValue) {
    finished_ = newValue;
}

bool
AcceptFD::finishedAccepting() const {
    return acceptCount() >= MAX_ACCEPT_PER_LOOP || finished();
}

/*
 * This callback is called whenever a filedescriptor is ready
 * to dupe itself and fob off an accept()ed connection
 */
static void
comm_accept_try(int fd, void *data) {
    assert(fdc_table[fd].active == 1);

    fdc_table[fd].beginAccepting();

    while (!fdc_table[fd].accept.accept.finishedAccepting())
        fdc_table[fd].acceptOne(fd);
}

/*
 * Notes:
 * + the current interface will queue _one_ accept per io loop.
 *   this isn't very optimal and should be revisited at a later date.
 */
void
comm_accept(int fd, IOACB *handler, void *handler_data) {
    debug (5,5) ("comm_accept: FD %d handler: %p\n", fd, (void*)handler);
    requireOpenAndActive(fd);

    /* make sure we're not pending! */
    assert(fdc_table[fd].accept.accept.callback.handler == NULL);

    /* Record our details */
    fdc_table[fd].accept.accept.callback = CallBack<IOACB> (handler, handler_data);

    /* Kick off the accept */
#if OPTIMISTIC_IO

    comm_accept_try(fd, NULL);
#else

    commSetSelect(fd, COMM_SELECT_READ, comm_accept_try, NULL, 0);
#endif
}

void CommIO::Initialise() {
    /* Initialize done pipe signal */
    int DonePipe[2];
    pipe(DonePipe);
    DoneFD = DonePipe[1];
    DoneReadFD = DonePipe[0];
    fd_open(DoneReadFD, FD_PIPE, "async-io completetion event: main");
    fd_open(DoneFD, FD_PIPE, "async-io completetion event: threads");
    commSetNonBlocking(DoneReadFD);
    commSetNonBlocking(DoneFD);
    commSetSelect(DoneReadFD, COMM_SELECT_READ, NULLFDHandler, NULL, 0);
    Initialised = true;
}

void CommIO::NotifyIOClose() {
    /* Close done pipe signal */
    FlushPipe();
    close(DoneFD);
    close(DoneReadFD);
    fd_close(DoneFD);
    fd_close(DoneReadFD);
    Initialised = false;
}

bool CommIO::Initialised = false;
bool CommIO::DoneSignalled = false;
int CommIO::DoneFD = -1;
int CommIO::DoneReadFD = -1;

void
CommIO::FlushPipe() {
    char buf[256];
    FD_READ_METHOD(DoneReadFD, buf, sizeof(buf));
}

void
CommIO::NULLFDHandler(int fd, void *data) {
    FlushPipe();
    commSetSelect(fd, COMM_SELECT_READ, NULLFDHandler, NULL, 0);
}

void
CommIO::ResetNotifications() {
    if (DoneSignalled) {
        FlushPipe();
        DoneSignalled = false;
    }
}

AcceptLimiter AcceptLimiter::Instance_;

AcceptLimiter &AcceptLimiter::Instance() {
    return Instance_;
}

bool
AcceptLimiter::deferring() const {
    return deferred.size() > 0;
}

void
AcceptLimiter::defer (int fd, Acceptor::AcceptorFunction *aFunc, void *data) {
    debug (5,5) ("AcceptLimiter::defer: FD %d handler: %p\n", fd, (void*)aFunc);
    Acceptor temp;
    temp.theFunction = aFunc;
    temp.acceptFD = fd;
    temp.theData = data;
    deferred.push_back(temp);
}

void
AcceptLimiter::kick() {
    if (!deferring())
        return;

    /* Yes, this means the first on is the last off....
     * If the list container was a little more friendly, we could sensibly us it.
     */
    Acceptor temp = deferred.pop_back();

    comm_accept (temp.acceptFD, temp.theFunction, temp.theData);
}

void
commMarkHalfClosed(int fd) {
    assert (fdc_table[fd].active && !fdc_table[fd].half_closed);
    AbortChecker::Instance().monitor(fd);
    fdc_table[fd].half_closed = true;
}

int commIsHalfClosed(int fd) {
    assert (fdc_table[fd].active);

    return fdc_table[fd].half_closed;
}

void
commCheckHalfClosed(void *data) {
    AbortChecker::Instance().doIOLoop();
    eventAdd("commCheckHalfClosed", commCheckHalfClosed, NULL, 1.0, false);
}

AbortChecker &AbortChecker::Instance() {return Instance_;}

AbortChecker AbortChecker::Instance_;

void
AbortChecker::AbortCheckReader(int fd, char *, size_t size, comm_err_t flag, int xerrno, void *data) {
    assert (size == 0);
    /* sketch:
     * if the read is ok and 0, the conn is still open.
     * if the read is a fail, close the conn
     */

    if (flag != COMM_OK && flag != COMM_ERR_CLOSING) {
        debug (5,3) ("AbortChecker::AbortCheckReader: FD %d aborted\n", fd);
        comm_close(fd);
    }
}

void
AbortChecker::monitor(int fd) {
    assert (!contains(fd));

    add
        (fd);

    debug (5,3) ("AbortChecker::monitor: monitoring half closed FD %d for aborts\n", fd);
}

void
AbortChecker::stopMonitoring (int fd) {
    assert (contains (fd));

    remove
        (fd);

    debug (5,3) ("AbortChecker::stopMonitoring: stopped monitoring half closed FD %d for aborts\n", fd);
}

#include "splay.h"
void
AbortChecker::doIOLoop() {
    fds->walk(RemoveCheck, this);
    fds->walk(AddCheck, this);
}

void
AbortChecker::AddCheck (int const &fd, void *data) {
    AbortChecker *me = (AbortChecker *)data;
    me->addCheck(fd);
}

void
AbortChecker::RemoveCheck (int const &fd, void *data) {
    AbortChecker *me = (AbortChecker *)data;
    me->removeCheck(fd);
}


int
AbortChecker::IntCompare (int const &lhs, int const &rhs) {
    return lhs - rhs;
}

bool
AbortChecker::contains (int const fd) const {
    fds = fds->splay(fd, IntCompare);

    if (splayLastResult != 0)
        return false;

    return true;
}

void

AbortChecker::remove
    (int const fd) {

    fds = fds->remove
          (fd, IntCompare);
}

void

AbortChecker::add
    (int const fd) {
    fds = fds->insert (fd, IntCompare);
}

void
AbortChecker::addCheck (int const fd) {
    /* assert comm_is_open (fd); */
    comm_read(fd, NULL, 0, AbortCheckReader, NULL);
}

void
AbortChecker::removeCheck (int const fd) {
    /*
      comm_read_cancel(fd, AbortCheckReader, NULL);
    */
}

CommRead::CommRead() : fd(-1), buf(NULL), len(0) {}

CommRead::CommRead(int fd_, char *buf_, int len_, IOCB *handler_, void *data_)
        : fd(fd_), buf(buf_), len(len_), callback(handler_, data_) {}

DeferredRead::DeferredRead () : theReader(NULL), theContext(NULL), theRead(), cancelled(false) {}

DeferredRead::DeferredRead (DeferrableRead *aReader, void *data, CommRead const &aRead) : theReader(aReader), theContext (data), theRead(aRead), cancelled(false) {}

DeferredReadManager::~DeferredReadManager() {
    flushReads();
    assert (deferredReads.empty());
}

/* explicit instantiation required for some systems */

template cbdata_type List<DeferredRead>
::CBDATA_List;

void
DeferredReadManager::delayRead(DeferredRead const &aRead) {
    debug (5, 3)("Adding deferred read on FD %d\n", aRead.theRead.fd);
    List<DeferredRead> *temp = deferredReads.push_back(aRead);
    comm_add_close_handler (aRead.theRead.fd, CloseHandler, temp);
}

void
DeferredReadManager::CloseHandler(int fd, void *thecbdata) {
    if (!cbdataReferenceValid (thecbdata))
        return;

    List<DeferredRead> *temp = (List<DeferredRead> *)thecbdata;

    temp->element.markCancelled();
}

DeferredRead
DeferredReadManager::popHead(ListContainer<DeferredRead> &deferredReads) {
    assert (!deferredReads.empty());

    if (!deferredReads.head->element.cancelled)
        comm_remove_close_handler(deferredReads.head->element.theRead.fd, CloseHandler, deferredReads.head);

    DeferredRead result = deferredReads.pop_front();

    return result;
}

void
DeferredReadManager::kickReads(int const count) {
    /* if we had List::size() we could consolidate this and flushReads */

    if (count < 1) {
        flushReads();
        return;
    }

    size_t remaining = count;

    while (!deferredReads.empty() && remaining) {
        DeferredRead aRead = popHead(deferredReads);
        kickARead(aRead);

        if (!aRead.cancelled)
            --remaining;
    }
}

void
DeferredReadManager::flushReads() {
    ListContainer<DeferredRead> reads;
    reads = deferredReads;
    deferredReads = ListContainer<DeferredRead>();

    while (!reads.empty()) {
        DeferredRead aRead = popHead(reads);
        kickARead(aRead);
    }
}

void
DeferredReadManager::kickARead(DeferredRead const &aRead) {
    if (aRead.cancelled)
        return;

    debug (5,3)("Kicking deferred read on FD %d\n", aRead.theRead.fd);

    aRead.theReader(aRead.theContext, aRead.theRead);
}

void
DeferredRead::markCancelled() {
    cancelled = true;
}

ConnectionDetail::ConnectionDetail() {
    memset(&me, 0, sizeof(me));
    memset(&peer, 0, sizeof(peer));
}

bool
CommDispatcher::dispatch() {
    bool result = comm_iocallbackpending();
    comm_calliocallback();
    /* and again to deal with indirectly queued events
     * resulting from the first call. These are usually
     * callbacks and should be dealt with immediately.
     */
    comm_calliocallback();

    /* Adrian's *new* stuff */
    commio_call_callbacks();
    return result;
}

int
CommSelectEngine::checkEvents(int timeout) {
    static time_t last_timeout = 0;

    /* No, this shouldn't be here. But it shouldn't be in each comm handler. -adrian */
    if (squid_curtime > last_timeout) {
        last_timeout = squid_curtime;
        checkTimeouts();
    }

    switch (comm_select(timeout)) {

    case COMM_OK:

    case COMM_TIMEOUT:
        return 0;

    case COMM_IDLE:

    case COMM_SHUTDOWN:
        return EVENT_IDLE;

    case COMM_ERROR:
        return EVENT_ERROR;

    default:
        fatal_dump("comm.cc: Internal error -- this should never happen.");
        return EVENT_ERROR;
    };
}
