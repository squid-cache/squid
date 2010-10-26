/*
 * DEBUG: section 05    Socket Functions
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
#include "comm/AcceptLimiter.h"
#include "comm/comm_internal.h"
#include "comm/ListenStateData.h"
#include "CommIO.h"
#include "CommRead.h"
#include "ConnectionDetail.h"
#include "MemBuf.h"
#include "pconn.h"
#include "SquidTime.h"
#include "CommCalls.h"
#include "DescriptorSet.h"
#include "icmp/net_db.h"
#include "ip/Address.h"
#include "ip/Intercept.h"
#include "ip/QosConfig.h"
#include "ip/tools.h"
#include "ClientInfo.h"

#include "cbdata.h"
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

static void commStopHalfClosedMonitor(int fd);
static IOCB commHalfClosedReader;
static void comm_init_opened(int new_socket, Ip::Address &addr, tos_t tos, nfmark_t nfmark, const char *note, struct addrinfo *AI);
static int comm_apply_flags(int new_socket, Ip::Address &addr, int flags, struct addrinfo *AI);

#if DELAY_POOLS
CBDATA_CLASS_INIT(CommQuotaQueue);

static void commHandleWriteHelper(void * data);
#endif

static void commSelectOrQueueWrite(const int fd);

struct comm_io_callback_t {
    iocb_type type;
    int fd;
    AsyncCall::Pointer callback;
    char *buf;
    FREE *freefunc;
    int size;
    int offset;
    comm_err_t errcode;
    int xerrno;
#if DELAY_POOLS
    unsigned int quotaQueueReserv; ///< reservation ID from CommQuotaQueue
#endif


    bool active() const { return callback != NULL; }
};

struct _comm_fd {
    int fd;
    comm_io_callback_t	readcb;
    comm_io_callback_t	writecb;
};
typedef struct _comm_fd comm_fd_t;
comm_fd_t *commfd_table;

// TODO: make this a comm_io_callback_t method?
bool
commio_has_callback(int fd, iocb_type type, comm_io_callback_t *ccb)
{
    assert(ccb->fd == fd);
    assert(ccb->type == type);
    return ccb->active();
}

/*
 * Configure comm_io_callback_t for I/O
 *
 * @param fd		filedescriptor
 * @param ccb		comm io callback
 * @param cb		callback
 * @param cbdata	callback data (must be cbdata'ed)
 * @param buf		buffer, if applicable
 * @param freefunc	freefunc, if applicable
 * @param size		buffer size
 */
static void
commio_set_callback(int fd, iocb_type type, comm_io_callback_t *ccb,
                    AsyncCall::Pointer &cb, char *buf, FREE *freefunc, int size)
{
    assert(!ccb->active());
    assert(ccb->type == type);
    assert(cb != NULL);
    ccb->fd = fd;
    ccb->callback = cb;
    ccb->buf = buf;
    ccb->freefunc = freefunc;
    ccb->size = size;
    ccb->offset = 0;
}


// Schedule the callback call and clear the callback
static void
commio_finish_callback(int fd, comm_io_callback_t *ccb, comm_err_t code, int xerrno)
{
    debugs(5, 3, "commio_finish_callback: called for FD " << fd << " (" <<
           code << ", " << xerrno << ")");
    assert(ccb->active());
    assert(ccb->fd == fd);
    ccb->errcode = code;
    ccb->xerrno = xerrno;

#if DELAY_POOLS
    ccb->quotaQueueReserv = 0;
#endif

    comm_io_callback_t cb = *ccb;

    /* We've got a copy; blow away the real one */
    /* XXX duplicate code from commio_cancel_callback! */
    ccb->xerrno = 0;
    ccb->callback = NULL; // cb has it

    /* free data */
    if (cb.freefunc) {
        cb.freefunc(cb.buf);
        cb.buf = NULL;
    }

    if (cb.callback != NULL) {
        typedef CommIoCbParams Params;
        Params &params = GetCommParams<Params>(cb.callback);
        params.fd = cb.fd;
        params.buf = cb.buf;
        params.size = cb.offset;
        params.flag = cb.errcode;
        params.xerrno = cb.xerrno;
        ScheduleCallHere(cb.callback);
    }
}


/*
 * Cancel the given callback
 *
 * Remember that the data is cbdataRef'ed.
 */
// TODO: make this a comm_io_callback_t method
static void
commio_cancel_callback(int fd, comm_io_callback_t *ccb)
{
    debugs(5, 3, "commio_cancel_callback: called for FD " << fd);
    assert(ccb->fd == fd);
    assert(ccb->active());

    ccb->xerrno = 0;
    ccb->callback = NULL;

#if DELAY_POOLS
    ccb->quotaQueueReserv = 0;
#endif
}

/*
 * Call the given comm callback; assumes the callback is valid.
 *
 * @param ccb		io completion callback
 */
void
commio_call_callback(comm_io_callback_t *ccb)
{
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

// defaults given by client
    char *host;
    u_short default_port;
    Ip::Address default_addr;
    // NP: CANNOT store the default addr:port together as it gets set/reset differently.

    DnsLookupDetails dns; ///< host lookup details
    Ip::Address S;
    AsyncCall::Pointer callback;

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

static DescriptorSet *TheHalfClosed = NULL; /// the set of half-closed FDs
static bool WillCheckHalfClosed = false; /// true if check is scheduled
static EVH commHalfClosedCheck;
static void commPlanHalfClosedCheck();

static comm_err_t commBind(int s, struct addrinfo &);
static void commSetReuseAddr(int);
static void commSetNoLinger(int);
#ifdef TCP_NODELAY
static void commSetTcpNoDelay(int);
#endif
static void commSetTcpRcvbuf(int, int);
static PF commConnectFree;
static PF commHandleWrite;
static IPH commConnectDnsHandle;

typedef enum {
    COMM_CB_READ = 1,
    COMM_CB_DERIVED
} comm_callback_t;

static MemAllocator *conn_close_pool = NULL;
fd_debug_t *fdd_table = NULL;

bool
isOpen(const int fd)
{
    return fd_table[fd].flags.open != 0;
}

/**
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
    debugs(5, 3, "comm_read_try: FD " << fd << ", size " << ccb->size << ", retval " << retval << ", errno " << errno);

    if (retval < 0 && !ignoreErrno(errno)) {
        debugs(5, 3, "comm_read_try: scheduling COMM_ERROR");
        ccb->offset = 0;
        commio_finish_callback(fd, ccb, COMM_ERROR, errno);
        return;
    };

    /* See if we read anything */
    /* Note - read 0 == socket EOF, which is a valid read */
    if (retval >= 0) {
        fd_bytes(fd, retval, FD_READ);
        ccb->offset = retval;
        commio_finish_callback(fd, ccb, COMM_OK, errno);
        return;
    }

    /* Nope, register for some more IO */
    commSetSelect(fd, COMM_SELECT_READ, commHandleRead, data, 0);
}

/**
 * Queue a read. handler/handler_data are called when the read
 * completes, on error, or on file descriptor close.
 */
void
comm_read(int fd, char *buf, int size, IOCB *handler, void *handler_data)
{
    AsyncCall::Pointer call = commCbCall(5,4, "SomeCommReadHandler",
                                         CommIoCbPtrFun(handler, handler_data));
    comm_read(fd, buf, size, call);
}

void
comm_read(int fd, char *buf, int size, AsyncCall::Pointer &callback)
{
    debugs(5, 5, "comm_read, queueing read for FD " << fd << "; asynCall " << callback);

    /* Make sure we are open and not closing */
    assert(isOpen(fd));
    assert(!fd_table[fd].closing());
    comm_io_callback_t *ccb = COMMIO_FD_READCB(fd);

    // Make sure we are either not reading or just passively monitoring.
    // Active/passive conflicts are OK and simply cancel passive monitoring.
    if (ccb->active()) {
        // if the assertion below fails, we have an active comm_read conflict
        assert(fd_table[fd].halfClosedReader != NULL);
        commStopHalfClosedMonitor(fd);
        assert(!ccb->active());
    }

    /* Queue the read */
    commio_set_callback(fd, IOCB_READ, ccb, callback, (char *)buf, NULL, size);
    commSetSelect(fd, COMM_SELECT_READ, commHandleRead, ccb, 0);
}

/**
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

    if (fd_table[fd].flags.nonblocking == 1) {
        while (FD_READ_METHOD(fd, buf, SQUID_TCP_SO_RCVBUF) > 0) {};
    }
#endif
}


/**
 * Return whether the FD has a pending completed callback.
 */
int
comm_has_pending_read_callback(int fd)
{
    assert(isOpen(fd));
    // XXX: We do not know whether there is a read callback scheduled.
    // This is used for pconn management that should probably be more
    // tightly integrated into comm to minimize the chance that a
    // closing pconn socket will be used for a new transaction.
    return false;
}

// Does comm check this fd for read readiness?
// Note that when comm is not monitoring, there can be a pending callback
// call, which may resume comm monitoring once fired.
bool
comm_monitors_read(int fd)
{
    assert(isOpen(fd));
    // Being active is usually the same as monitoring because we always
    // start monitoring the FD when we configure comm_io_callback_t for I/O
    // and we usually configure comm_io_callback_t for I/O when we starting
    // monitoring a FD for reading. TODO: replace with commio_has_callback
    return COMMIO_FD_READCB(fd)->active();
}

/**
 * Cancel a pending read. Assert that we have the right parameters,
 * and that there are no pending read events!
 *
 * XXX: We do not assert that there are no pending read events and
 * with async calls it becomes even more difficult.
 * The whole interface should be reworked to do callback->cancel()
 * instead of searching for places where the callback may be stored and
 * updating the state of those places.
 *
 * AHC Don't call the comm handlers?
 */
void
comm_read_cancel(int fd, IOCB *callback, void *data)
{
    if (!isOpen(fd)) {
        debugs(5, 4, "comm_read_cancel fails: FD " << fd << " closed");
        return;
    }

    comm_io_callback_t *cb = COMMIO_FD_READCB(fd);
    // TODO: is "active" == "monitors FD"?
    if (!cb->active()) {
        debugs(5, 4, "comm_read_cancel fails: FD " << fd << " inactive");
        return;
    }

    typedef CommCbFunPtrCallT<CommIoCbPtrFun> Call;
    Call *call = dynamic_cast<Call*>(cb->callback.getRaw());
    if (!call) {
        debugs(5, 4, "comm_read_cancel fails: FD " << fd << " lacks callback");
        return;
    }

    call->cancel("old comm_read_cancel");

    typedef CommIoCbParams Params;
    const Params &params = GetCommParams<Params>(cb->callback);

    /* Ok, we can be reasonably sure we won't lose any data here! */
    assert(call->dialer.handler == callback);
    assert(params.data == data);

    /* Delete the callback */
    commio_cancel_callback(fd, cb);

    /* And the IO event */
    commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
}

void
comm_read_cancel(int fd, AsyncCall::Pointer &callback)
{
    callback->cancel("comm_read_cancel");

    if (!isOpen(fd)) {
        debugs(5, 4, "comm_read_cancel fails: FD " << fd << " closed");
        return;
    }

    comm_io_callback_t *cb = COMMIO_FD_READCB(fd);

    if (!cb->active()) {
        debugs(5, 4, "comm_read_cancel fails: FD " << fd << " inactive");
        return;
    }

    AsyncCall::Pointer call = cb->callback;
    assert(call != NULL); // XXX: should never fail (active() checks for callback==NULL)

    /* Ok, we can be reasonably sure we won't lose any data here! */
    assert(call == callback);

    /* Delete the callback */
    commio_cancel_callback(fd, cb);

    /* And the IO event */
    commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
}


/**
 * synchronous wrapper around udp socket functions
 */
int
comm_udp_recvfrom(int fd, void *buf, size_t len, int flags, Ip::Address &from)
{
    statCounter.syscalls.sock.recvfroms++;
    int x = 0;
    struct addrinfo *AI = NULL;

    debugs(5,8, "comm_udp_recvfrom: FD " << fd << " from " << from);

    assert( NULL == AI );

    from.InitAddrInfo(AI);

    x = recvfrom(fd, buf, len, flags, AI->ai_addr, &AI->ai_addrlen);

    from = *AI;

    from.FreeAddrInfo(AI);

    return x;
}

int
comm_udp_recv(int fd, void *buf, size_t len, int flags)
{
    Ip::Address nul;
    return comm_udp_recvfrom(fd, buf, len, flags, nul);
}

ssize_t
comm_udp_send(int s, const void *buf, size_t len, int flags)
{
    return send(s, buf, len, flags);
}


bool
comm_has_incomplete_write(int fd)
{
    assert(isOpen(fd));
    return COMMIO_FD_WRITECB(fd)->active();
}

/**
 * Queue a write. handler/handler_data are called when the write fully
 * completes, on error, or on file descriptor close.
 */

/* Return the local port associated with fd. */
u_short
comm_local_port(int fd)
{
    Ip::Address temp;
    struct addrinfo *addr = NULL;
    fde *F = &fd_table[fd];

    /* If the fd is closed already, just return */

    if (!F->flags.open) {
        debugs(5, 0, "comm_local_port: FD " << fd << " has been closed.");
        return 0;
    }

    if (F->local_addr.GetPort())
        return F->local_addr.GetPort();

    if (F->sock_family == AF_INET)
        temp.SetIPv4();

    temp.InitAddrInfo(addr);

    if (getsockname(fd, addr->ai_addr, &(addr->ai_addrlen)) ) {
        debugs(50, 1, "comm_local_port: Failed to retrieve TCP/UDP port number for socket: FD " << fd << ": " << xstrerror());
        temp.FreeAddrInfo(addr);
        return 0;
    }
    temp = *addr;

    temp.FreeAddrInfo(addr);

    F->local_addr.SetPort(temp.GetPort());

#if 0 // seems to undo comm_open actions on the FD ...
    // grab default socket information for this address
    temp.GetAddrInfo(addr);

    F->sock_family = addr->ai_family;

    temp.FreeAddrInfo(addr);
#endif

    debugs(5, 6, "comm_local_port: FD " << fd << ": port " << F->local_addr.GetPort() << "(family=" << F->sock_family << ")");
    return F->local_addr.GetPort();
}

static comm_err_t
commBind(int s, struct addrinfo &inaddr)
{
    statCounter.syscalls.sock.binds++;

    if (bind(s, inaddr.ai_addr, inaddr.ai_addrlen) == 0) {
        debugs(50, 6, "commBind: bind socket FD " << s << " to " << fd_table[s].local_addr);
        return COMM_OK;
    }

    debugs(50, 0, "commBind: Cannot bind socket FD " << s << " to " << fd_table[s].local_addr << ": " << xstrerror());

    return COMM_ERROR;
}

/**
 * Create a socket. Default is blocking, stream (TCP) socket.  IO_TYPE
 * is OR of flags specified in comm.h. Defaults TOS
 */
int
comm_open(int sock_type,
          int proto,
          Ip::Address &addr,
          int flags,
          const char *note)
{
    return comm_openex(sock_type, proto, addr, flags, 0, 0, note);
}

int
comm_open_listener(int sock_type,
                   int proto,
                   Ip::Address &addr,
                   int flags,
                   const char *note)
{
    int sock = -1;

    /* all listener sockets require bind() */
    flags |= COMM_DOBIND;

    /* attempt native enabled port. */
    sock = comm_openex(sock_type, proto, addr, flags, 0, 0, note);

    return sock;
}

static bool
limitError(int const anErrno)
{
    return anErrno == ENFILE || anErrno == EMFILE;
}

void
comm_set_v6only(int fd, int tos)
{
#ifdef IPV6_V6ONLY
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &tos, sizeof(int)) < 0) {
        debugs(50, 1, "comm_open: setsockopt(IPV6_V6ONLY) " << (tos?"ON":"OFF") << " for FD " << fd << ": " << xstrerror());
    }
#else
    debugs(50, 0, "WARNING: comm_open: setsockopt(IPV6_V6ONLY) not supported on this platform");
#endif /* sockopt */
}

/**
 * Set the socket IP_TRANSPARENT option for Linux TPROXY v4 support.
 */
void
comm_set_transparent(int fd)
{
#if defined(IP_TRANSPARENT)
    int tos = 1;
    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, (char *) &tos, sizeof(int)) < 0) {
        debugs(50, DBG_IMPORTANT, "comm_open: setsockopt(IP_TRANSPARENT) on FD " << fd << ": " << xstrerror());
    } else {
        /* mark the socket as having transparent options */
        fd_table[fd].flags.transparent = 1;
    }
#else
    debugs(50, DBG_CRITICAL, "WARNING: comm_open: setsockopt(IP_TRANSPARENT) not supported on this platform");
#endif /* sockopt */
}

/**
 * Create a socket. Default is blocking, stream (TCP) socket.  IO_TYPE
 * is OR of flags specified in defines.h:COMM_*
 */
int
comm_openex(int sock_type,
            int proto,
            Ip::Address &addr,
            int flags,
            tos_t tos,
            nfmark_t nfmark,
            const char *note)
{
    int new_socket;
    struct addrinfo *AI = NULL;

    PROF_start(comm_open);
    /* Create socket for accepting new connections. */
    statCounter.syscalls.sock.sockets++;

    /* Setup the socket addrinfo details for use */
    addr.GetAddrInfo(AI);
    AI->ai_socktype = sock_type;
    AI->ai_protocol = proto;

    debugs(50, 3, "comm_openex: Attempt open socket for: " << addr );

    new_socket = socket(AI->ai_family, AI->ai_socktype, AI->ai_protocol);

    /* under IPv6 there is the possibility IPv6 is present but disabled. */
    /* try again as IPv4-native if possible */
    if ( new_socket < 0 && Ip::EnableIpv6 && addr.IsIPv6() && addr.SetIPv4() ) {
        /* attempt to open this IPv4-only. */
        addr.FreeAddrInfo(AI);
        /* Setup the socket addrinfo details for use */
        addr.GetAddrInfo(AI);
        AI->ai_socktype = sock_type;
        AI->ai_protocol = proto;
        debugs(50, 3, "comm_openex: Attempt fallback open socket for: " << addr );
        new_socket = socket(AI->ai_family, AI->ai_socktype, AI->ai_protocol);
        debugs(50, 2, HERE << "attempt open " << note << " socket on: " << addr);
    }

    if (new_socket < 0) {
        /* Increase the number of reserved fd's if calls to socket()
         * are failing because the open file table is full.  This
         * limits the number of simultaneous clients */

        if (limitError(errno)) {
            debugs(50, DBG_IMPORTANT, "comm_open: socket failure: " << xstrerror());
            fdAdjustReserved();
        } else {
            debugs(50, DBG_CRITICAL, "comm_open: socket failure: " << xstrerror());
        }

        addr.FreeAddrInfo(AI);

        PROF_stop(comm_open);
        return -1;
    }

    debugs(50, 3, "comm_openex: Opened socket FD " << new_socket << " : family=" << AI->ai_family << ", type=" << AI->ai_socktype << ", protocol=" << AI->ai_protocol );

    /* set TOS if needed */
    if (tos)
        Ip::Qos::setSockTos(new_socket, tos);

    /* set netfilter mark if needed */
    if (nfmark)
        Ip::Qos::setSockNfmark(new_socket, nfmark);

    if ( Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK && addr.IsIPv6() )
        comm_set_v6only(new_socket, 1);

    /* Windows Vista supports Dual-Sockets. BUT defaults them to V6ONLY. Turn it OFF. */
    /* Other OS may have this administratively disabled for general use. Same deal. */
    if ( Ip::EnableIpv6&IPV6_SPECIAL_V4MAPPING && addr.IsIPv6() )
        comm_set_v6only(new_socket, 0);

    comm_init_opened(new_socket, addr, tos, nfmark, note, AI);
    new_socket = comm_apply_flags(new_socket, addr, flags, AI);

    addr.FreeAddrInfo(AI);

    PROF_stop(comm_open);

    return new_socket;
}

/// update FD tables after a local or remote (IPC) comm_openex();
void
comm_init_opened(int new_socket,
                 Ip::Address &addr,
                 tos_t tos,
                 nfmark_t nfmark,
                 const char *note,
                 struct addrinfo *AI)
{
    assert(new_socket >= 0);
    assert(AI);

    fde *F = NULL;

    /* update fdstat */
    debugs(5, 5, "comm_open: FD " << new_socket << " is a new socket");

    assert(!isOpen(new_socket));
    fd_open(new_socket, FD_SOCKET, note);

    fdd_table[new_socket].close_file = NULL;

    fdd_table[new_socket].close_line = 0;

    F = &fd_table[new_socket];

    F->local_addr = addr;

    F->tosToServer = tos;

    F->nfmarkToServer = nfmark;

    F->sock_family = AI->ai_family;
}

/// apply flags after a local comm_open*() call;
/// returns new_socket or -1 on error
static int
comm_apply_flags(int new_socket,
                 Ip::Address &addr,
                 int flags,
                 struct addrinfo *AI)
{
    assert(new_socket >= 0);
    assert(AI);
    const int sock_type = AI->ai_socktype;

    if (!(flags & COMM_NOCLOEXEC))
        commSetCloseOnExec(new_socket);

    if ((flags & COMM_REUSEADDR))
        commSetReuseAddr(new_socket);

    if (addr.GetPort() > (u_short) 0) {
#ifdef _SQUID_MSWIN_
        if (sock_type != SOCK_DGRAM)
#endif
            commSetNoLinger(new_socket);

        if (opt_reuseaddr)
            commSetReuseAddr(new_socket);
    }

    /* MUST be done before binding or face OS Error: "(99) Cannot assign requested address"... */
    if ((flags & COMM_TRANSPARENT)) {
        comm_set_transparent(new_socket);
    }

    if ( (flags & COMM_DOBIND) || addr.GetPort() > 0 || !addr.IsAnyAddr() ) {
        if ( !(flags & COMM_DOBIND) && addr.IsAnyAddr() )
            debugs(5,1,"WARNING: Squid is attempting to bind() port " << addr << " without being a listener.");
        if ( addr.IsNoAddr() )
            debugs(5,0,"CRITICAL: Squid is attempting to bind() port " << addr << "!!");

        if (commBind(new_socket, *AI) != COMM_OK) {
            comm_close(new_socket);
            return -1;
        }
    }

    if (flags & COMM_NONBLOCKING)
        if (commSetNonBlocking(new_socket) == COMM_ERROR) {
            comm_close(new_socket);
            return -1;
        }

#ifdef TCP_NODELAY
    if (sock_type == SOCK_STREAM)
        commSetTcpNoDelay(new_socket);

#endif

    if (Config.tcpRcvBufsz > 0 && sock_type == SOCK_STREAM)
        commSetTcpRcvbuf(new_socket, Config.tcpRcvBufsz);

    return new_socket;
}

void
comm_import_opened(int fd,
                   Ip::Address &addr,
                   int flags,
                   const char *note,
                   struct addrinfo *AI)
{
    debugs(5, 2, HERE << " FD " << fd << " at " << addr);
    assert(fd >= 0);
    assert(AI);

    comm_init_opened(fd, addr, 0, 0, note, AI);

    if (!(flags & COMM_NOCLOEXEC))
        fd_table[fd].flags.close_on_exec = 1;

    if (addr.GetPort() > (u_short) 0) {
#ifdef _SQUID_MSWIN_
        if (sock_type != SOCK_DGRAM)
#endif
            fd_table[fd].flags.nolinger = 1;
    }

    if ((flags & COMM_TRANSPARENT))
        fd_table[fd].flags.transparent = 1;

    if (flags & COMM_NONBLOCKING)
        fd_table[fd].flags.nonblocking = 1;

#ifdef TCP_NODELAY
    if (AI->ai_socktype == SOCK_STREAM)
        fd_table[fd].flags.nodelay = 1;
#endif

    /* no fd_table[fd].flags. updates needed for these conditions:
     * if ((flags & COMM_REUSEADDR)) ...
     * if ((flags & COMM_DOBIND) ...) ...
     */
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
commConnectStart(int fd, const char *host, u_short port, AsyncCall::Pointer &cb)
{
    debugs(cb->debugSection, cb->debugLevel, "commConnectStart: FD " << fd <<
           ", cb " << cb << ", " << host << ":" << port); // TODO: just print *cb

    ConnectStateData *cs;
    cs = new ConnectStateData;
    cs->fd = fd;
    cs->host = xstrdup(host);
    cs->default_port = port;
    cs->callback = cb;

    comm_add_close_handler(fd, commConnectFree, cs);
    ipcache_nbgethostbyname(host, commConnectDnsHandle, cs);
}

// TODO: Remove this and similar callback registration functions by replacing
// (callback,data) parameters with an AsyncCall so that we do not have to use
// a generic call name and debug level when creating an AsyncCall. This will
// also cut the number of callback registration routines in half.
void
commConnectStart(int fd, const char *host, u_short port, CNCB * callback, void *data)
{
    debugs(5, 5, "commConnectStart: FD " << fd << ", data " << data << ", " << host << ":" << port);
    AsyncCall::Pointer call = commCbCall(5,3,
                                         "SomeCommConnectHandler", CommConnectCbPtrFun(callback, data));
    commConnectStart(fd, host, port, call);
}

static void
commConnectDnsHandle(const ipcache_addrs *ia, const DnsLookupDetails &details, void *data)
{
    ConnectStateData *cs = (ConnectStateData *)data;
    cs->dns = details;

    if (ia == NULL) {
        debugs(5, 3, "commConnectDnsHandle: Unknown host: " << cs->host);
        cs->callCallback(COMM_ERR_DNS, 0);
        return;
    }

    assert(ia->cur < ia->count);

    cs->default_addr = ia->in_addrs[ia->cur];

    if (Config.onoff.balance_on_multiple_ip)
        ipcacheCycleAddr(cs->host, NULL);

    cs->addrcount = ia->count;

    cs->connstart = squid_curtime;

    cs->connect();
}

void
ConnectStateData::callCallback(comm_err_t status, int xerrno)
{
    debugs(5, 3, "commConnectCallback: FD " << fd);

    comm_remove_close_handler(fd, commConnectFree, this);
    commSetTimeout(fd, -1, NULL, NULL);

    typedef CommConnectCbParams Params;
    Params &params = GetCommParams<Params>(callback);
    params.fd = fd;
    params.dns = dns;
    params.flag = status;
    params.xerrno = xerrno;
    ScheduleCallHere(callback);
    callback = NULL;

    commConnectFree(fd, this);
}

static void
commConnectFree(int fd, void *data)
{
    ConnectStateData *cs = (ConnectStateData *)data;
    debugs(5, 3, "commConnectFree: FD " << fd);
//    delete cs->callback;
    cs->callback = NULL;
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

// XXX: do we have to check this?
//
//    if (!cbdataReferenceValid(callback.data))
//        return 0;

    statCounter.syscalls.sock.sockets++;

    fde *F = &fd_table[fd];

    struct addrinfo *AI = NULL;
    F->local_addr.GetAddrInfo(AI);
    int new_family = AI->ai_family;

    int fd2 = socket(new_family, AI->ai_socktype, AI->ai_protocol);

    if (fd2 < 0) {
        debugs(5, DBG_CRITICAL, HERE << "WARNING: FD " << fd2 << " socket failed to allocate: " << xstrerror());

        if (ENFILE == errno || EMFILE == errno)
            fdAdjustReserved();

        F->local_addr.FreeAddrInfo(AI);
        return 0;
    }

#ifdef _SQUID_MSWIN_

    /* On Windows dup2() can't work correctly on Sockets, the          */
    /* workaround is to close the destination Socket before call them. */
    close(fd);

#endif

    if (dup2(fd2, fd) < 0) {
        debugs(5, DBG_CRITICAL, HERE << "WARNING: dup2(FD " << fd2 << ", FD " << fd << ") failed: " << xstrerror());

        if (ENFILE == errno || EMFILE == errno)
            fdAdjustReserved();

        close(fd2);

        F->local_addr.FreeAddrInfo(AI);
        return 0;
    }
    commResetSelect(fd);

    close(fd2);

    debugs(50, 3, "commResetFD: Reset socket FD " << fd << "->" << fd2 << " : family=" << new_family );

    /* INET6: copy the new sockets family type to the FDE table */
    F->sock_family = new_family;

    F->flags.called_connect = 0;

    /*
     * yuck, this has assumptions about comm_open() arguments for
     * the original socket
     */

    /* MUST be done before binding or face OS Error: "(99) Cannot assign requested address"... */
    if ( F->flags.transparent ) {
        comm_set_transparent(fd);
    }

    if (commBind(fd, *AI) != COMM_OK) {
        debugs(5, DBG_CRITICAL, "WARNING: Reset of FD " << fd << " for " << F->local_addr << " failed to bind: " << xstrerror());
        F->local_addr.FreeAddrInfo(AI);
        return 0;
    }
    F->local_addr.FreeAddrInfo(AI);

    if (F->tosToServer)
        Ip::Qos::setSockTos(fd, F->tosToServer);

    if (F->nfmarkToServer)
        Ip::Qos::setSockNfmark(fd, F->nfmarkToServer);

    if ( Ip::EnableIpv6&IPV6_SPECIAL_SPLITSTACK && F->local_addr.IsIPv6() )
        comm_set_v6only(fd, 1);

    copyFDFlags(fd, F);

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
        if (tries > addrcount) {
            /* Flush bad address count in case we are
             * skipping over incompatible protocol
             */
            ipcacheMarkAllGood(host);
            return 0;
        }
    }

    return commResetFD();
}

static void
commReconnect(void *data)
{
    ConnectStateData *cs = (ConnectStateData *)data;
    ipcache_nbgethostbyname(cs->host, commConnectDnsHandle, cs);
}

/** Connect SOCK to specified DEST_PORT at DEST_HOST. */
void
ConnectStateData::Connect(int fd, void *me)
{
    ConnectStateData *cs = (ConnectStateData *)me;
    assert (cs->fd == fd);
    cs->connect();
}

void
ConnectStateData::defaults()
{
    S = default_addr;
    S.SetPort(default_port);
}

void
ConnectStateData::connect()
{
    defaults();

    debugs(5,5, HERE << "to " << S);

    switch (comm_connect_addr(fd, S) ) {

    case COMM_INPROGRESS:
        debugs(5, 5, HERE << "FD " << fd << ": COMM_INPROGRESS");
        commSetSelect(fd, COMM_SELECT_WRITE, ConnectStateData::Connect, this, 0);
        break;

    case COMM_OK:
        debugs(5, 5, HERE << "FD " << fd << ": COMM_OK - connected");
        ipcacheMarkGoodAddr(host, S);
        callCallback(COMM_OK, 0);
        break;

    case COMM_ERR_PROTOCOL:
        debugs(5, 5, HERE "FD " << fd << ": COMM_ERR_PROTOCOL - try again");
        /* problem using the desired protocol over this socket.
         * skip to the next address and hope it's more compatible
         * but do not mark the current address as bad
         */
        tries++;
        if (commRetryConnect()) {
            /* Force an addr cycle to move forward to the next possible address */
            ipcacheCycleAddr(host, NULL);
            eventAdd("commReconnect", commReconnect, this, this->addrcount == 1 ? 0.05 : 0.0, 0);
        } else {
            debugs(5, 5, HERE << "FD " << fd << ": COMM_ERR_PROTOCOL - ERR tried too many times already.");
            callCallback(COMM_ERR_CONNECT, errno);
        }
        break;

    default:
        debugs(5, 5, HERE "FD " << fd << ": * - try again");
        tries++;
        ipcacheMarkBadAddr(host, S);

#if USE_ICMP
        if (Config.onoff.test_reachability)
            netdbDeleteAddrNetwork(S);
#endif

        if (commRetryConnect()) {
            eventAdd("commReconnect", commReconnect, this, this->addrcount == 1 ? 0.05 : 0.0, 0);
        } else {
            debugs(5, 5, HERE << "FD " << fd << ": * - ERR tried too many times already.");
            callCallback(COMM_ERR_CONNECT, errno);
        }
    }
}
/*
int
commSetTimeout_old(int fd, int timeout, PF * handler, void *data)
{
    debugs(5, 3, HERE << "FD " << fd << " timeout " << timeout);
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
*/

int
commSetTimeout(int fd, int timeout, PF * handler, void *data)
{
    AsyncCall::Pointer call;
    debugs(5, 3, HERE << "FD " << fd << " timeout " << timeout);
    if (handler != NULL)
        call=commCbCall(5,4, "SomeTimeoutHandler", CommTimeoutCbPtrFun(handler, data));
    else
        call = NULL;
    return commSetTimeout(fd, timeout, call);
}


int commSetTimeout(int fd, int timeout, AsyncCall::Pointer &callback)
{
    debugs(5, 3, HERE << "FD " << fd << " timeout " << timeout);
    assert(fd >= 0);
    assert(fd < Squid_MaxFD);
    fde *F = &fd_table[fd];
    assert(F->flags.open);

    if (timeout < 0) {
        F->timeoutHandler = NULL;
        F->timeout = 0;
    } else {
        if (callback != NULL) {
            typedef CommTimeoutCbParams Params;
            Params &params = GetCommParams<Params>(callback);
            params.fd = fd;
            F->timeoutHandler = callback;
        }

        F->timeout = squid_curtime + (time_t) timeout;
    }

    return F->timeout;

}

int
comm_connect_addr(int sock, const Ip::Address &address)
{
    comm_err_t status = COMM_OK;
    fde *F = &fd_table[sock];
    int x = 0;
    int err = 0;
    socklen_t errlen;
    struct addrinfo *AI = NULL;
    PROF_start(comm_connect_addr);

    assert(address.GetPort() != 0);

    debugs(5, 9, HERE << "connecting socket FD " << sock << " to " << address << " (want family: " << F->sock_family << ")");

    /* Handle IPv6 over IPv4-only socket case.
     * this case must presently be handled here since the GetAddrInfo asserts on bad mappings.
     * NP: because commResetFD is private to ConnStateData we have to return an error and
     *     trust its handled properly.
     */
    if (F->sock_family == AF_INET && !address.IsIPv4()) {
        errno = ENETUNREACH;
        return COMM_ERR_PROTOCOL;
    }

    /* Handle IPv4 over IPv6-only socket case.
     * This case is presently handled here as it's both a known case and it's
     * uncertain what error will be returned by the IPv6 stack in such case. It's
     * possible this will also be handled by the errno checks below after connect()
     * but needs carefull cross-platform verification, and verifying the address
     * condition here is simple.
     */
    if (!F->local_addr.IsIPv4() && address.IsIPv4()) {
        errno = ENETUNREACH;
        return COMM_ERR_PROTOCOL;
    }

    address.GetAddrInfo(AI, F->sock_family);

    /* Establish connection. */
    errno = 0;

    if (!F->flags.called_connect) {
        F->flags.called_connect = 1;
        statCounter.syscalls.sock.connects++;

        x = connect(sock, AI->ai_addr, AI->ai_addrlen);

        // XXX: ICAP code refuses callbacks during a pending comm_ call
        // Async calls development will fix this.
        if (x == 0) {
            x = -1;
            errno = EINPROGRESS;
        }

        if (x < 0) {
            debugs(5,5, "comm_connect_addr: sock=" << sock << ", addrinfo( " <<
                   " flags=" << AI->ai_flags <<
                   ", family=" << AI->ai_family <<
                   ", socktype=" << AI->ai_socktype <<
                   ", protocol=" << AI->ai_protocol <<
                   ", &addr=" << AI->ai_addr <<
                   ", addrlen=" << AI->ai_addrlen <<
                   " )" );
            debugs(5, 9, "connect FD " << sock << ": (" << x << ") " << xstrerror());
            debugs(14,9, "connecting to: " << address );
        }
    } else {
#if defined(_SQUID_NEWSOS6_)
        /* Makoto MATSUSHITA <matusita@ics.es.osaka-u.ac.jp> */

        connect(sock, AI->ai_addr, AI->ai_addrlen);

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

    /* Squid seems to be working fine without this code. With this code,
     * we leak memory on many connect requests because of EINPROGRESS.
     * If you find that this code is needed, please file a bug report. */
#if 0
#ifdef _SQUID_LINUX_
    /* 2007-11-27:
     * Linux Debian replaces our allocated AI pointer with garbage when
     * connect() fails. This leads to segmentation faults deallocating
     * the system-allocated memory when we go to clean up our pointer.
     * HACK: is to leak the memory returned since we can't deallocate.
     */
    if (errno != 0) {
        AI = NULL;
    }
#endif
#endif

    address.FreeAddrInfo(AI);

    PROF_stop(comm_connect_addr);

    if (errno == 0 || errno == EISCONN)
        status = COMM_OK;
    else if (ignoreErrno(errno))
        status = COMM_INPROGRESS;
    else if (errno == EAFNOSUPPORT || errno == EINVAL)
        return COMM_ERR_PROTOCOL;
    else
        return COMM_ERROR;

    address.NtoA(F->ipaddr, MAX_IPSTRLEN);

    F->remote_port = address.GetPort(); /* remote_port is HS */

    if (status == COMM_OK) {
        debugs(5, 10, "comm_connect_addr: FD " << sock << " connected to " << address);
    } else if (status == COMM_INPROGRESS) {
        debugs(5, 10, "comm_connect_addr: FD " << sock << " connection pending");
    }

    return status;
}

void
commCallCloseHandlers(int fd)
{
    fde *F = &fd_table[fd];
    debugs(5, 5, "commCallCloseHandlers: FD " << fd);

    while (F->closeHandler != NULL) {
        AsyncCall::Pointer call = F->closeHandler;
        F->closeHandler = call->Next();
        call->setNext(NULL);
        // If call is not canceled schedule it for execution else ignore it
        if (!call->canceled()) {
            debugs(5, 5, "commCallCloseHandlers: ch->handler=" << call);
            typedef CommCloseCbParams Params;
            Params &params = GetCommParams<Params>(call);
            params.fd = fd;
            ScheduleCallHere(call);
        }
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
        debugs(5, 3, "commLingerClose: FD " << fd << " read: " << xstrerror());

    comm_close(fd);
}

static void
commLingerTimeout(int fd, void *unused)
{
    debugs(5, 3, "commLingerTimeout: FD " << fd);
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
        debugs(50, DBG_CRITICAL, "ERROR: Closing FD " << fd << " with TCP RST: " << xstrerror());

    comm_close(fd);
}

void
comm_close_start(int fd, void *data)
{
#if USE_SSL
    fde *F = &fd_table[fd];
    if (F->ssl)
        ssl_shutdown_method(fd);

#endif

}

void
comm_close_complete(int fd, void *data)
{
#if USE_SSL
    fde *F = &fd_table[fd];

    if (F->ssl) {
        SSL_free(F->ssl);
        F->ssl = NULL;
    }

#endif
    fd_close(fd);		/* update fdstat */

    close(fd);

    statCounter.syscalls.sock.closes++;

    /* When an fd closes, give accept() a chance, if need be */
    Comm::AcceptLimiter::Instance().kick();
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
    debugs(5, 3, "comm_close: start closing FD " << fd);
    assert(fd >= 0);
    assert(fd < Squid_MaxFD);

    fde *F = &fd_table[fd];
    fdd_table[fd].close_file = file;
    fdd_table[fd].close_line = line;

    if (F->closing())
        return;

    /* XXX: is this obsolete behind F->closing() ? */
    if ( (shutting_down || reconfiguring) && (!F->flags.open || F->type == FD_FILE))
        return;

    /* The following fails because ipc.c is doing calls to pipe() to create sockets! */
    assert(isOpen(fd));

    assert(F->type != FD_FILE);

    PROF_start(comm_close);

    F->flags.close_request = 1;

    AsyncCall::Pointer startCall=commCbCall(5,4, "comm_close_start",
                                            CommCloseCbPtrFun(comm_close_start, NULL));
    typedef CommCloseCbParams Params;
    Params &startParams = GetCommParams<Params>(startCall);
    startParams.fd = fd;
    ScheduleCallHere(startCall);

    // a half-closed fd may lack a reader, so we stop monitoring explicitly
    if (commHasHalfClosedMonitor(fd))
        commStopHalfClosedMonitor(fd);
    commSetTimeout(fd, -1, NULL, NULL);

    // notify read/write handlers after canceling select reservations, if any
    if (commio_has_callback(fd, IOCB_WRITE, COMMIO_FD_WRITECB(fd))) {
        commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
        commio_finish_callback(fd, COMMIO_FD_WRITECB(fd), COMM_ERR_CLOSING, errno);
    }
    if (commio_has_callback(fd, IOCB_READ, COMMIO_FD_READCB(fd))) {
        commSetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
        commio_finish_callback(fd, COMMIO_FD_READCB(fd), COMM_ERR_CLOSING, errno);
    }

#if DELAY_POOLS
    if (ClientInfo *clientInfo = F->clientInfo) {
        if (clientInfo->selectWaiting) {
            clientInfo->selectWaiting = false;
            // kick queue or it will get stuck as commWriteHandle is not called
            clientInfo->kickQuotaQueue();
        }
    }
#endif

    commCallCloseHandlers(fd);

    if (F->pconn.uses)
        F->pconn.pool->count(F->pconn.uses);

    comm_empty_os_read_buffers(fd);


    AsyncCall::Pointer completeCall=commCbCall(5,4, "comm_close_complete",
                                    CommCloseCbPtrFun(comm_close_complete, NULL));
    Params &completeParams = GetCommParams<Params>(completeCall);
    completeParams.fd = fd;
    // must use async call to wait for all callbacks
    // scheduled before comm_close() to finish
    ScheduleCallHere(completeCall);

    PROF_stop(comm_close);
}

/* Send a udp datagram to specified TO_ADDR. */
int
comm_udp_sendto(int fd,
                const Ip::Address &to_addr,
                const void *buf,
                int len)
{
    int x = 0;
    struct addrinfo *AI = NULL;

    PROF_start(comm_udp_sendto);
    statCounter.syscalls.sock.sendtos++;

    debugs(50, 3, "comm_udp_sendto: Attempt to send UDP packet to " << to_addr <<
           " using FD " << fd << " using Port " << comm_local_port(fd) );

    /* BUG: something in the above macro appears to occasionally be setting AI to garbage. */
    /* AYJ: 2007-08-27 : or was it because I wasn't then setting 'fd_table[fd].sock_family' to fill properly. */
    assert( NULL == AI );

    to_addr.GetAddrInfo(AI, fd_table[fd].sock_family);

    x = sendto(fd, buf, len, 0, AI->ai_addr, AI->ai_addrlen);

    to_addr.FreeAddrInfo(AI);

    PROF_stop(comm_udp_sendto);

    if (x >= 0)
        return x;

#ifdef _SQUID_LINUX_

    if (ECONNREFUSED != errno)
#endif

        debugs(50, 1, "comm_udp_sendto: FD " << fd << ", (family=" << fd_table[fd].sock_family << ") " << to_addr << ": " << xstrerror());

    return COMM_ERROR;
}

void
comm_add_close_handler(int fd, PF * handler, void *data)
{
    debugs(5, 5, "comm_add_close_handler: FD " << fd << ", handler=" <<
           handler << ", data=" << data);

    AsyncCall::Pointer call=commCbCall(5,4, "SomeCloseHandler",
                                       CommCloseCbPtrFun(handler, data));
    comm_add_close_handler(fd, call);
}

void
comm_add_close_handler(int fd, AsyncCall::Pointer &call)
{
    debugs(5, 5, "comm_add_close_handler: FD " << fd << ", AsyncCall=" << call);

    /*TODO:Check for a similar scheduled AsyncCall*/
//    for (c = fd_table[fd].closeHandler; c; c = c->next)
//        assert(c->handler != handler || c->data != data);

    call->setNext(fd_table[fd].closeHandler);

    fd_table[fd].closeHandler = call;
}


// remove function-based close handler
void
comm_remove_close_handler(int fd, PF * handler, void *data)
{
    assert (isOpen(fd));
    /* Find handler in list */
    debugs(5, 5, "comm_remove_close_handler: FD " << fd << ", handler=" <<
           handler << ", data=" << data);

    AsyncCall::Pointer p;
    for (p = fd_table[fd].closeHandler; p != NULL; p = p->Next()) {
        typedef CommCbFunPtrCallT<CommCloseCbPtrFun> Call;
        const Call *call = dynamic_cast<const Call*>(p.getRaw());
        if (!call) // method callbacks have their own comm_remove_close_handler
            continue;

        typedef CommCloseCbParams Params;
        const Params &params = GetCommParams<Params>(p);
        if (call->dialer.handler == handler && params.data == data)
            break;		/* This is our handler */
    }

    // comm_close removes all close handlers so our handler may be gone
    if (p != NULL)
        p->cancel("comm_remove_close_handler");
    // TODO: should we remove the handler from the close handlers list?
}

// remove method-based close handler
void
comm_remove_close_handler(int fd, AsyncCall::Pointer &call)
{
    assert (isOpen(fd));
    debugs(5, 5, "comm_remove_close_handler: FD " << fd << ", AsyncCall=" << call);

    // comm_close removes all close handlers so our handler may be gone
    // TODO: should we remove the handler from the close handlers list?
#if 0
    // Check to see if really exist  the given AsyncCall in comm_close handlers
    // TODO: optimize: this slow code is only needed for the assert() below
    AsyncCall::Pointer p;
    for (p = fd_table[fd].closeHandler; p != NULL && p != call; p = p->Next());
    assert(p == call);
#endif

    call->cancel("comm_remove_close_handler");
}

static void
commSetNoLinger(int fd)
{

    struct linger L;
    L.l_onoff = 0;		/* off */
    L.l_linger = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &L, sizeof(L)) < 0)
        debugs(50, 0, "commSetNoLinger: FD " << fd << ": " << xstrerror());

    fd_table[fd].flags.nolinger = 1;
}

static void
commSetReuseAddr(int fd)
{
    int on = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0)
        debugs(50, 1, "commSetReuseAddr: FD " << fd << ": " << xstrerror());
}

static void
commSetTcpRcvbuf(int fd, int size)
{
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &size, sizeof(size)) < 0)
        debugs(50, 1, "commSetTcpRcvbuf: FD " << fd << ", SIZE " << size << ": " << xstrerror());
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &size, sizeof(size)) < 0)
        debugs(50, 1, "commSetTcpRcvbuf: FD " << fd << ", SIZE " << size << ": " << xstrerror());
#ifdef TCP_WINDOW_CLAMP
    if (setsockopt(fd, SOL_TCP, TCP_WINDOW_CLAMP, (char *) &size, sizeof(size)) < 0)
        debugs(50, 1, "commSetTcpRcvbuf: FD " << fd << ", SIZE " << size << ": " << xstrerror());
#endif
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
            debugs(50, 0, "commSetNonBlocking: FD " << fd << ": " << xstrerror() << " " << fd_table[fd].type);
            return COMM_ERROR;
        }

#ifdef _SQUID_CYGWIN_

    } else {
#endif
#endif
#ifndef _SQUID_MSWIN_

        if ((flags = fcntl(fd, F_GETFL, dummy)) < 0) {
            debugs(50, 0, "FD " << fd << ": fcntl F_GETFL: " << xstrerror());
            return COMM_ERROR;
        }

        if (fcntl(fd, F_SETFL, flags | SQUID_NONBLOCK) < 0) {
            debugs(50, 0, "commSetNonBlocking: FD " << fd << ": " << xstrerror());
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
        debugs(50, 0, "FD " << fd << ": fcntl F_GETFL: " << xstrerror());
        return COMM_ERROR;
    }

    if (fcntl(fd, F_SETFL, flags & (~SQUID_NONBLOCK)) < 0) {
#endif
        debugs(50, 0, "commUnsetNonBlocking: FD " << fd << ": " << xstrerror());
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

    if ((flags = fcntl(fd, F_GETFD, dummy)) < 0) {
        debugs(50, 0, "FD " << fd << ": fcntl F_GETFD: " << xstrerror());
        return;
    }

    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
        debugs(50, 0, "FD " << fd << ": set close-on-exec failed: " << xstrerror());

    fd_table[fd].flags.close_on_exec = 1;

#endif
}

#ifdef TCP_NODELAY
static void
commSetTcpNoDelay(int fd)
{
    int on = 1;

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof(on)) < 0)
        debugs(50, 1, "commSetTcpNoDelay: FD " << fd << ": " << xstrerror());

    fd_table[fd].flags.nodelay = 1;
}

#endif

void
commSetTcpKeepalive(int fd, int idle, int interval, int timeout)
{
    int on = 1;
#ifdef TCP_KEEPCNT
    if (timeout && interval) {
        int count = (timeout + interval - 1) / interval;
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(on)) < 0)
            debugs(5, 1, "commSetKeepalive: FD " << fd << ": " << xstrerror());
    }
#endif
#ifdef TCP_KEEPIDLE
    if (idle) {
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(on)) < 0)
            debugs(5, 1, "commSetKeepalive: FD " << fd << ": " << xstrerror());
    }
#endif
#ifdef TCP_KEEPINTVL
    if (interval) {
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(on)) < 0)
            debugs(5, 1, "commSetKeepalive: FD " << fd << ": " << xstrerror());
    }
#endif
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on)) < 0)
        debugs(5, 1, "commSetKeepalive: FD " << fd << ": " << xstrerror());
}

void
comm_init(void)
{
    fd_table =(fde *) xcalloc(Squid_MaxFD, sizeof(fde));
    fdd_table = (fd_debug_t *)xcalloc(Squid_MaxFD, sizeof(fd_debug_t));

    /* make sure the accept() socket FIFO delay queue exists */
    Comm::AcceptLimiter::Instance();

    commfd_table = (comm_fd_t *) xcalloc(Squid_MaxFD, sizeof(comm_fd_t));
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
    RESERVED_FD = min(100, Squid_MaxFD / 4);

    conn_close_pool = memPoolCreate("close_handler", sizeof(close_handler));

    TheHalfClosed = new DescriptorSet;
}

void
comm_exit(void)
{
    delete TheHalfClosed;
    TheHalfClosed = NULL;

    safe_free(fd_table);
    safe_free(fdd_table);
    safe_free(commfd_table);
}

#if DELAY_POOLS
// called when the queue is done waiting for the client bucket to fill
static void
commHandleWriteHelper(void * data)
{
    CommQuotaQueue *queue = static_cast<CommQuotaQueue*>(data);
    assert(queue);

    ClientInfo *clientInfo = queue->clientInfo;
    // ClientInfo invalidates queue if freed, so if we got here through,
    // evenAdd cbdata protections, everything should be valid and consistent
    assert(clientInfo);
    assert(clientInfo->hasQueue());
    assert(clientInfo->hasQueue(queue));
    assert(!clientInfo->selectWaiting);
    assert(clientInfo->eventWaiting);
    clientInfo->eventWaiting = false;

    do {
        // check that the head descriptor is still relevant
        const int head = clientInfo->quotaPeekFd();
        comm_io_callback_t *ccb = COMMIO_FD_WRITECB(head);

        if (fd_table[head].clientInfo == clientInfo &&
                clientInfo->quotaPeekReserv() == ccb->quotaQueueReserv &&
                !fd_table[head].closing()) {

            // wait for the head descriptor to become ready for writing
            commSetSelect(head, COMM_SELECT_WRITE, commHandleWrite, ccb, 0);
            clientInfo->selectWaiting = true;
            return;
        }

        clientInfo->quotaDequeue(); // remove the no longer relevant descriptor
        // and continue looking for a relevant one
    } while (clientInfo->hasQueue());

    debugs(77,3, HERE << "emptied queue");
}

bool
ClientInfo::hasQueue() const
{
    assert(quotaQueue);
    return !quotaQueue->empty();
}

bool
ClientInfo::hasQueue(const CommQuotaQueue *q) const
{
    assert(quotaQueue);
    return quotaQueue == q;
}

/// returns the first descriptor to be dequeued
int
ClientInfo::quotaPeekFd() const
{
    assert(quotaQueue);
    return quotaQueue->front();
}

/// returns the reservation ID of the first descriptor to be dequeued
unsigned int
ClientInfo::quotaPeekReserv() const
{
    assert(quotaQueue);
    return quotaQueue->outs + 1;
}

/// queues a given fd, creating the queue if necessary; returns reservation ID
unsigned int
ClientInfo::quotaEnqueue(int fd)
{
    assert(quotaQueue);
    return quotaQueue->enqueue(fd);
}

/// removes queue head
void
ClientInfo::quotaDequeue()
{
    assert(quotaQueue);
    quotaQueue->dequeue();
}

void
ClientInfo::kickQuotaQueue()
{
    if (!eventWaiting && !selectWaiting && hasQueue()) {
        // wait at least a second if the bucket is empty
        const double delay = (bucketSize < 1.0) ? 1.0 : 0.0;
        eventAdd("commHandleWriteHelper", &commHandleWriteHelper,
                 quotaQueue, delay, 0, true);
        eventWaiting = true;
    }
}

/// calculates how much to write for a single dequeued client
int
ClientInfo::quotaForDequed()
{
    /* If we have multiple clients and give full bucketSize to each client then
     * clt1 may often get a lot more because clt1->clt2 time distance in the
     * select(2) callback order may be a lot smaller than cltN->clt1 distance.
     * We divide quota evenly to be more fair. */

    if (!rationedCount) {
        rationedCount = quotaQueue->size() + 1;

        // The delay in ration recalculation _temporary_ deprives clients from
        // bytes that should have trickled in while rationedCount was positive.
        refillBucket();

        // Rounding errors do not accumulate here, but we round down to avoid
        // negative bucket sizes after write with rationedCount=1.
        rationedQuota = static_cast<int>(floor(bucketSize/rationedCount));
        debugs(77,5, HERE << "new rationedQuota: " << rationedQuota <<
               '*' << rationedCount);
    }

    --rationedCount;
    debugs(77,7, HERE << "rationedQuota: " << rationedQuota <<
           " rations remaining: " << rationedCount);

    // update 'last seen' time to prevent clientdb GC from dropping us
    last_seen = squid_curtime;
    return rationedQuota;
}

///< adds bytes to the quota bucket based on the rate and passed time
void
ClientInfo::refillBucket()
{
    // all these times are in seconds, with double precision
    const double currTime = current_dtime;
    const double timePassed = currTime - prevTime;

    // Calculate allowance for the time passed. Use double to avoid
    // accumulating rounding errors for small intervals. For example, always
    // adding 1 byte instead of 1.4 results in 29% bandwidth allocation error.
    const double gain = timePassed * writeSpeedLimit;

    debugs(77,5, HERE << currTime << " clt" << (const char*)hash.key << ": " <<
           bucketSize << " + (" << timePassed << " * " << writeSpeedLimit <<
           " = " << gain << ')');

    // to further combat error accumulation during micro updates,
    // quit before updating time if we cannot add at least one byte
    if (gain < 1.0)
        return;

    prevTime = currTime;

    // for "first" connections, drain initial fat before refilling but keep
    // updating prevTime to avoid bursts after the fat is gone
    if (bucketSize > bucketSizeLimit) {
        debugs(77,4, HERE << "not refilling while draining initial fat");
        return;
    }

    bucketSize += gain;

    // obey quota limits
    if (bucketSize > bucketSizeLimit)
        bucketSize = bucketSizeLimit;
}

void
ClientInfo::setWriteLimiter(const int aWriteSpeedLimit, const double anInitialBurst, const double aHighWatermark)
{
    debugs(77,5, HERE << "Write limits for " << (const char*)hash.key <<
           " speed=" << aWriteSpeedLimit << " burst=" << anInitialBurst <<
           " highwatermark=" << aHighWatermark);

    // set or possibly update traffic shaping parameters
    writeLimitingActive = true;
    writeSpeedLimit = aWriteSpeedLimit;
    bucketSizeLimit = aHighWatermark;

    // but some members should only be set once for a newly activated bucket
    if (firstTimeConnection) {
        firstTimeConnection = false;

        assert(!selectWaiting);
        assert(!quotaQueue);
        quotaQueue = new CommQuotaQueue(this);
        cbdataReference(quotaQueue);

        bucketSize = anInitialBurst;
        prevTime = current_dtime;
    }
}

CommQuotaQueue::CommQuotaQueue(ClientInfo *info): clientInfo(info),
        ins(0), outs(0)
{
    assert(clientInfo);
}

CommQuotaQueue::~CommQuotaQueue()
{
    assert(!clientInfo); // ClientInfo should clear this before destroying us
}

/// places the given fd at the end of the queue; returns reservation ID
unsigned int
CommQuotaQueue::enqueue(int fd)
{
    debugs(77,5, HERE << "clt" << (const char*)clientInfo->hash.key <<
           ": FD " << fd << " with qqid" << (ins+1) << ' ' << fds.size());
    fds.push_back(fd);
    return ++ins;
}

/// removes queue head
void
CommQuotaQueue::dequeue()
{
    assert(!fds.empty());
    debugs(77,5, HERE << "clt" << (const char*)clientInfo->hash.key <<
           ": FD " << fds.front() << " with qqid" << (outs+1) << ' ' <<
           fds.size());
    fds.pop_front();
    ++outs;
}

#endif

/* Write to FD. */
static void
commHandleWrite(int fd, void *data)
{
    comm_io_callback_t *state = (comm_io_callback_t *)data;
    int len = 0;
    int nleft;

    assert(state == COMMIO_FD_WRITECB(fd));

    PROF_start(commHandleWrite);
    debugs(5, 5, "commHandleWrite: FD " << fd << ": off " <<
           (long int) state->offset << ", sz " << (long int) state->size << ".");

    nleft = state->size - state->offset;

#if DELAY_POOLS
    ClientInfo * clientInfo=fd_table[fd].clientInfo;

    if (clientInfo && !clientInfo->writeLimitingActive)
        clientInfo = NULL; // we only care about quota limits here

    if (clientInfo) {
        assert(clientInfo->selectWaiting);
        clientInfo->selectWaiting = false;

        assert(clientInfo->hasQueue());
        assert(clientInfo->quotaPeekFd() == fd);
        clientInfo->quotaDequeue(); // we will write or requeue below

        if (nleft > 0) {
            const int quota = clientInfo->quotaForDequed();
            if (!quota) {  // if no write quota left, queue this fd
                state->quotaQueueReserv = clientInfo->quotaEnqueue(fd);
                clientInfo->kickQuotaQueue();
                PROF_stop(commHandleWrite);
                return;
            }

            const int nleft_corrected = min(nleft, quota);
            if (nleft != nleft_corrected) {
                debugs(5, 5, HERE << "FD " << fd << " writes only " <<
                       nleft_corrected << " out of " << nleft);
                nleft = nleft_corrected;
            }

        }
    }

#endif

    /* actually WRITE data */
    len = FD_WRITE_METHOD(fd, state->buf + state->offset, nleft);
    debugs(5, 5, "commHandleWrite: write() returns " << len);

#if DELAY_POOLS
    if (clientInfo) {
        if (len > 0) {
            /* we wrote data - drain them from bucket */
            clientInfo->bucketSize -= len;
            if (clientInfo->bucketSize < 0.0) {
                debugs(5,1, HERE << "drained too much"); // should not happen
                clientInfo->bucketSize = 0;
            }
        }

        // even if we wrote nothing, we were served; give others a chance
        clientInfo->kickQuotaQueue();
    }
#endif

    fd_bytes(fd, len, FD_WRITE);
    statCounter.syscalls.sock.writes++;
    // After each successful partial write,
    // reset fde::writeStart to the current time.
    fd_table[fd].writeStart = squid_curtime;

    if (len == 0) {
        /* Note we even call write if nleft == 0 */
        /* We're done */

        if (nleft != 0)
            debugs(5, 1, "commHandleWrite: FD " << fd << ": write failure: connection closed with " << nleft << " bytes remaining.");

        commio_finish_callback(fd, COMMIO_FD_WRITECB(fd), nleft ? COMM_ERROR : COMM_OK, errno);
    } else if (len < 0) {
        /* An error */

        if (fd_table[fd].flags.socket_eof) {
            debugs(50, 2, "commHandleWrite: FD " << fd << ": write failure: " << xstrerror() << ".");
            commio_finish_callback(fd, COMMIO_FD_WRITECB(fd), nleft ? COMM_ERROR : COMM_OK, errno);
        } else if (ignoreErrno(errno)) {
            debugs(50, 10, "commHandleWrite: FD " << fd << ": write failure: " << xstrerror() << ".");
            commSelectOrQueueWrite(fd);
        } else {
            debugs(50, 2, "commHandleWrite: FD " << fd << ": write failure: " << xstrerror() << ".");
            commio_finish_callback(fd, COMMIO_FD_WRITECB(fd), nleft ? COMM_ERROR : COMM_OK, errno);
        }
    } else {
        /* A successful write, continue */
        state->offset += len;

        if (state->offset < state->size) {
            /* Not done, reinstall the write handler and write some more */
            commSelectOrQueueWrite(fd);
        } else {
            commio_finish_callback(fd, COMMIO_FD_WRITECB(fd), nleft ? COMM_OK : COMM_ERROR, errno);
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
    AsyncCall::Pointer call = commCbCall(5,5, "SomeCommWriteHander",
                                         CommIoCbPtrFun(handler, handler_data));

    comm_write(fd, buf, size, call, free_func);
}

void
comm_write(int fd, const char *buf, int size, AsyncCall::Pointer &callback, FREE * free_func)
{
    debugs(5, 5, "comm_write: FD " << fd << ": sz " << size << ": asynCall " << callback);

    /* Make sure we are open, not closing, and not writing */
    assert(isOpen(fd));
    assert(!fd_table[fd].closing());
    comm_io_callback_t *ccb = COMMIO_FD_WRITECB(fd);
    assert(!ccb->active());

    fd_table[fd].writeStart = squid_curtime;
    /* Queue the write */
    commio_set_callback(fd, IOCB_WRITE, ccb, callback,
                        (char *)buf, free_func, size);

    commSelectOrQueueWrite(fd);
}

// called when fd needs to write but may need to wait in line for its quota
static void
commSelectOrQueueWrite(const int fd)
{
    comm_io_callback_t *ccb = COMMIO_FD_WRITECB(fd);

#if DELAY_POOLS
    // stand in line if there is one
    if (ClientInfo *clientInfo = fd_table[fd].clientInfo) {
        if (clientInfo->writeLimitingActive) {
            ccb->quotaQueueReserv = clientInfo->quotaEnqueue(fd);
            clientInfo->kickQuotaQueue();
            return;
        }
    }
#endif

    commSetSelect(fd, COMM_SELECT_WRITE, commHandleWrite, ccb, 0);
}


/* a wrapper around comm_write to allow for MemBuf to be comm_written in a snap */
void
comm_write_mbuf(int fd, MemBuf *mb, IOCB * handler, void *handler_data)
{
    comm_write(fd, mb->buf, mb->size, handler, handler_data, mb->freeFunc());
}

void
comm_write_mbuf(int fd, MemBuf *mb, AsyncCall::Pointer &callback)
{
    comm_write(fd, mb->buf, mb->size, callback, mb->freeFunc());
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

        if (F->timeoutHandler != NULL) {
            AsyncCall::Pointer callback = F->timeoutHandler;
            F->timeoutHandler = NULL;
            debugs(5, 5, "commCloseAllSockets: FD " << fd << ": Calling timeout handler");
            ScheduleCallHere(callback);
        } else {
            debugs(5, 5, "commCloseAllSockets: FD " << fd << ": calling comm_reset_close()");
            comm_reset_close(fd);
        }
    }
}

static bool
AlreadyTimedOut(fde *F)
{
    if (!F->flags.open)
        return true;

    if (F->timeout == 0)
        return true;

    if (F->timeout > squid_curtime)
        return true;

    return false;
}

static bool
writeTimedOut(int fd)
{
    if (!commio_has_callback(fd, IOCB_WRITE, COMMIO_FD_WRITECB(fd)))
        return false;

    if ((squid_curtime - fd_table[fd].writeStart) < Config.Timeout.write)
        return false;

    return true;
}

void
checkTimeouts(void)
{
    int fd;
    fde *F = NULL;
    AsyncCall::Pointer callback;

    for (fd = 0; fd <= Biggest_FD; fd++) {
        F = &fd_table[fd];

        if (writeTimedOut(fd)) {
            // We have an active write callback and we are timed out
            debugs(5, 5, "checkTimeouts: FD " << fd << " auto write timeout");
            commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
            commio_finish_callback(fd, COMMIO_FD_WRITECB(fd), COMM_ERROR, ETIMEDOUT);
        } else if (AlreadyTimedOut(F))
            continue;

        debugs(5, 5, "checkTimeouts: FD " << fd << " Expired");

        if (F->timeoutHandler != NULL) {
            debugs(5, 5, "checkTimeouts: FD " << fd << ": Call timeout handler");
            callback = F->timeoutHandler;
            F->timeoutHandler = NULL;
            ScheduleCallHere(callback);
        } else {
            debugs(5, 5, "checkTimeouts: FD " << fd << ": Forcing comm_close()");
            comm_close(fd);
        }
    }
}

void CommIO::Initialise()
{
    /* Initialize done pipe signal */
    int DonePipe[2];
    if (pipe(DonePipe)) {}
    DoneFD = DonePipe[1];
    DoneReadFD = DonePipe[0];
    fd_open(DoneReadFD, FD_PIPE, "async-io completetion event: main");
    fd_open(DoneFD, FD_PIPE, "async-io completetion event: threads");
    commSetNonBlocking(DoneReadFD);
    commSetNonBlocking(DoneFD);
    commSetSelect(DoneReadFD, COMM_SELECT_READ, NULLFDHandler, NULL, 0);
    Initialised = true;
}

void CommIO::NotifyIOClose()
{
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
CommIO::FlushPipe()
{
    char buf[256];
    FD_READ_METHOD(DoneReadFD, buf, sizeof(buf));
}

void
CommIO::NULLFDHandler(int fd, void *data)
{
    FlushPipe();
    commSetSelect(fd, COMM_SELECT_READ, NULLFDHandler, NULL, 0);
}

void
CommIO::ResetNotifications()
{
    if (DoneSignalled) {
        FlushPipe();
        DoneSignalled = false;
    }
}

/// Start waiting for a possibly half-closed connection to close
// by scheduling a read callback to a monitoring handler that
// will close the connection on read errors.
void
commStartHalfClosedMonitor(int fd)
{
    debugs(5, 5, HERE << "adding FD " << fd << " to " << *TheHalfClosed);
    assert(isOpen(fd));
    assert(!commHasHalfClosedMonitor(fd));
    (void)TheHalfClosed->add(fd); // could also assert the result
    commPlanHalfClosedCheck(); // may schedule check if we added the first FD
}

static
void
commPlanHalfClosedCheck()
{
    if (!WillCheckHalfClosed && !TheHalfClosed->empty()) {
        eventAdd("commHalfClosedCheck", &commHalfClosedCheck, NULL, 1.0, 1);
        WillCheckHalfClosed = true;
    }
}

/// iterates over all descriptors that may need half-closed tests and
/// calls comm_read for those that do; re-schedules the check if needed
static
void
commHalfClosedCheck(void *)
{
    debugs(5, 5, HERE << "checking " << *TheHalfClosed);

    typedef DescriptorSet::const_iterator DSCI;
    const DSCI end = TheHalfClosed->end();
    for (DSCI i = TheHalfClosed->begin(); i != end; ++i) {
        const int fd = *i;
        if (!fd_table[fd].halfClosedReader) { // not reading already
            AsyncCall::Pointer call = commCbCall(5,4, "commHalfClosedReader",
                                                 CommIoCbPtrFun(&commHalfClosedReader, NULL));
            comm_read(fd, NULL, 0, call);
            fd_table[fd].halfClosedReader = call;
        }
    }

    WillCheckHalfClosed = false; // as far as we know
    commPlanHalfClosedCheck(); // may need to check again
}

/// checks whether we are waiting for possibly half-closed connection to close
// We are monitoring if the read handler for the fd is the monitoring handler.
bool
commHasHalfClosedMonitor(int fd)
{
    return TheHalfClosed->has(fd);
}

/// stop waiting for possibly half-closed connection to close
static void
commStopHalfClosedMonitor(int const fd)
{
    debugs(5, 5, HERE << "removing FD " << fd << " from " << *TheHalfClosed);

    // cancel the read if one was scheduled
    AsyncCall::Pointer reader = fd_table[fd].halfClosedReader;
    if (reader != NULL)
        comm_read_cancel(fd, reader);
    fd_table[fd].halfClosedReader = NULL;

    TheHalfClosed->del(fd);
}

/// I/O handler for the possibly half-closed connection monitoring code
static void
commHalfClosedReader(int fd, char *, size_t size, comm_err_t flag, int, void *)
{
    // there cannot be more data coming in on half-closed connections
    assert(size == 0);
    assert(commHasHalfClosedMonitor(fd)); // or we would have canceled the read

    fd_table[fd].halfClosedReader = NULL; // done reading, for now

    // nothing to do if fd is being closed
    if (flag == COMM_ERR_CLOSING)
        return;

    // if read failed, close the connection
    if (flag != COMM_OK) {
        debugs(5, 3, "commHalfClosedReader: closing FD " << fd);
        comm_close(fd);
        return;
    }

    // continue waiting for close or error
    commPlanHalfClosedCheck(); // make sure this fd will be checked again
}


CommRead::CommRead() : fd(-1), buf(NULL), len(0), callback(NULL) {}

CommRead::CommRead(int fd_, char *buf_, int len_, AsyncCall::Pointer &callback_)
        : fd(fd_), buf(buf_), len(len_), callback(callback_) {}

DeferredRead::DeferredRead () : theReader(NULL), theContext(NULL), theRead(), cancelled(false) {}

DeferredRead::DeferredRead (DeferrableRead *aReader, void *data, CommRead const &aRead) : theReader(aReader), theContext (data), theRead(aRead), cancelled(false) {}

DeferredReadManager::~DeferredReadManager()
{
    flushReads();
    assert (deferredReads.empty());
}

/* explicit instantiation required for some systems */

/// \cond AUTODOCS-IGNORE
template cbdata_type CbDataList<DeferredRead>::CBDATA_CbDataList;
/// \endcond

void
DeferredReadManager::delayRead(DeferredRead const &aRead)
{
    debugs(5, 3, "Adding deferred read on FD " << aRead.theRead.fd);
    CbDataList<DeferredRead> *temp = deferredReads.push_back(aRead);

    // We have to use a global function as a closer and point to temp
    // instead of "this" because DeferredReadManager is not a job and
    // is not even cbdata protected
    AsyncCall::Pointer closer = commCbCall(5,4,
                                           "DeferredReadManager::CloseHandler",
                                           CommCloseCbPtrFun(&CloseHandler, temp));
    comm_add_close_handler(aRead.theRead.fd, closer);
    temp->element.closer = closer; // remeber so that we can cancel
}

void
DeferredReadManager::CloseHandler(int fd, void *thecbdata)
{
    if (!cbdataReferenceValid (thecbdata))
        return;

    CbDataList<DeferredRead> *temp = (CbDataList<DeferredRead> *)thecbdata;

    temp->element.closer = NULL;
    temp->element.markCancelled();
}

DeferredRead
DeferredReadManager::popHead(CbDataListContainer<DeferredRead> &deferredReads)
{
    assert (!deferredReads.empty());

    DeferredRead &read = deferredReads.head->element;
    if (!read.cancelled) {
        comm_remove_close_handler(read.theRead.fd, read.closer);
        read.closer = NULL;
    }

    DeferredRead result = deferredReads.pop_front();

    return result;
}

void
DeferredReadManager::kickReads(int const count)
{
    /* if we had CbDataList::size() we could consolidate this and flushReads */

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
DeferredReadManager::flushReads()
{
    CbDataListContainer<DeferredRead> reads;
    reads = deferredReads;
    deferredReads = CbDataListContainer<DeferredRead>();

    // XXX: For fairness this SHOULD randomize the order
    while (!reads.empty()) {
        DeferredRead aRead = popHead(reads);
        kickARead(aRead);
    }
}

void
DeferredReadManager::kickARead(DeferredRead const &aRead)
{
    if (aRead.cancelled)
        return;

    if (aRead.theRead.fd>=0 && fd_table[aRead.theRead.fd].closing())
        return;

    debugs(5, 3, "Kicking deferred read on FD " << aRead.theRead.fd);

    aRead.theReader(aRead.theContext, aRead.theRead);
}

void
DeferredRead::markCancelled()
{
    cancelled = true;
}

ConnectionDetail::ConnectionDetail() : me(), peer()
{
}

int
CommSelectEngine::checkEvents(int timeout)
{
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

/// Create a unix-domain socket (UDS) that only supports FD_MSGHDR I/O.
int
comm_open_uds(int sock_type,
              int proto,
              struct sockaddr_un* addr,
              int flags)
{
    // TODO: merge with comm_openex() when Ip::Address becomes NetAddress

    int new_socket;

    PROF_start(comm_open);
    /* Create socket for accepting new connections. */
    statCounter.syscalls.sock.sockets++;

    /* Setup the socket addrinfo details for use */
    struct addrinfo AI;
    AI.ai_flags = 0;
    AI.ai_family = PF_UNIX;
    AI.ai_socktype = sock_type;
    AI.ai_protocol = proto;
    AI.ai_addrlen = SUN_LEN(addr);
    AI.ai_addr = (sockaddr*)addr;
    AI.ai_canonname = NULL;
    AI.ai_next = NULL;

    debugs(50, 3, HERE << "Attempt open socket for: " << addr->sun_path);

    if ((new_socket = socket(AI.ai_family, AI.ai_socktype, AI.ai_protocol)) < 0) {
        /* Increase the number of reserved fd's if calls to socket()
         * are failing because the open file table is full.  This
         * limits the number of simultaneous clients */

        if (limitError(errno)) {
            debugs(50, DBG_IMPORTANT, HERE << "socket failure: " << xstrerror());
            fdAdjustReserved();
        } else {
            debugs(50, DBG_CRITICAL, HERE << "socket failure: " << xstrerror());
        }

        PROF_stop(comm_open);
        return -1;
    }

    debugs(50, 3, HERE "Opened UDS FD " << new_socket << " : family=" << AI.ai_family << ", type=" << AI.ai_socktype << ", protocol=" << AI.ai_protocol);

    /* update fdstat */
    debugs(50, 5, HERE << "FD " << new_socket << " is a new socket");

    assert(!isOpen(new_socket));
    fd_open(new_socket, FD_MSGHDR, NULL);

    fdd_table[new_socket].close_file = NULL;

    fdd_table[new_socket].close_line = 0;

    fd_table[new_socket].sock_family = AI.ai_family;

    if (!(flags & COMM_NOCLOEXEC))
        commSetCloseOnExec(new_socket);

    if (flags & COMM_REUSEADDR)
        commSetReuseAddr(new_socket);

    if (flags & COMM_NONBLOCKING) {
        if (commSetNonBlocking(new_socket) != COMM_OK) {
            comm_close(new_socket);
            PROF_stop(comm_open);
            return -1;
        }
    }

    if (flags & COMM_DOBIND) {
        if (commBind(new_socket, AI) != COMM_OK) {
            comm_close(new_socket);
            PROF_stop(comm_open);
            return -1;
        }
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
