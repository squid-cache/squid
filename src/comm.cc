

/*
 * $Id: comm.cc,v 1.284 1998/08/18 22:42:17 wessels Exp $
 *
 * DEBUG: section 5     Socket Functions
 * AUTHOR: Harvest Derived
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

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#if USE_ASYNC_IO
#define MAX_POLL_TIME 10
#else
#define MAX_POLL_TIME 1000
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
static int commBind(int s, struct in_addr, u_short port);
static void commSetReuseAddr(int);
static void commSetNoLinger(int);
static void CommWriteStateCallbackAndFree(int fd, int code);
#ifdef TCP_NODELAY
static void commSetTcpNoDelay(int);
#endif
static void commSetTcpRcvbuf(int, int);
static PF commConnectFree;
static PF commConnectHandle;
static PF commHandleWrite;
static IPH commConnectDnsHandle;
static void commConnectCallback(ConnectStateData * cs, int status);
static int commResetFD(ConnectStateData * cs);
static int commRetryConnect(ConnectStateData * cs);

static void
CommWriteStateCallbackAndFree(int fd, int code)
{
    CommWriteStateData *CommWriteState = fd_table[fd].rwstate;
    CWCB *callback = NULL;
    void *data;
    fd_table[fd].rwstate = NULL;
    if (CommWriteState == NULL)
	return;
    if (CommWriteState->free_func) {
	CommWriteState->free_func(CommWriteState->buf);
	CommWriteState->buf = NULL;
    }
    callback = CommWriteState->handler;
    data = CommWriteState->handler_data;
    CommWriteState->handler = NULL;
    if (callback && cbdataValid(data))
	callback(fd, CommWriteState->buf, CommWriteState->offset, code, data);
    cbdataUnlock(data);
    safe_free(CommWriteState);
}

/* Return the local port associated with fd. */
u_short
comm_local_port(int fd)
{
    struct sockaddr_in addr;
    socklen_t addr_len = 0;
    fde *F = &fd_table[fd];

    /* If the fd is closed already, just return */
    if (!F->open) {
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

static int
commBind(int s, struct in_addr in_addr, u_short port)
{
    struct sockaddr_in S;

    memset(&S, '\0', sizeof(S));
    S.sin_family = AF_INET;
    S.sin_port = htons(port);
    S.sin_addr = in_addr;
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
 * is OR of flags specified in comm.h. */
int
comm_open(int sock_type,
    int proto,
    struct in_addr addr,
    u_short port,
    int flags,
    const char *note)
{
    int new_socket;
    fde *F = NULL;
    int tcp_rcv_bufsz = Config.tcpRcvBufsz;

    /* Create socket for accepting new connections. */
    if ((new_socket = socket(AF_INET, sock_type, proto)) < 0) {
	/* Increase the number of reserved fd's if calls to socket()
	 * are failing because the open file table is full.  This
	 * limits the number of simultaneous clients */
	switch (errno) {
	case ENFILE:
	case EMFILE:
	    debug(50, 1) ("comm_open: socket failure: %s\n", xstrerror());
	    break;
	default:
	    debug(50, 0) ("comm_open: socket failure: %s\n", xstrerror());
	}
	fdAdjustReserved();
	return -1;
    }
    /* update fdstat */
    debug(5, 5) ("comm_open: FD %d is a new socket\n", new_socket);
    fd_open(new_socket, FD_SOCKET, note);
    F = &fd_table[new_socket];
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
	}
    }
    F->local_port = port;

    if (flags & COMM_NONBLOCKING)
	if (commSetNonBlocking(new_socket) == COMM_ERROR)
	    return -1;
#ifdef TCP_NODELAY
    if (sock_type == SOCK_STREAM)
	commSetTcpNoDelay(new_socket);
#endif
    if (tcp_rcv_bufsz > 0 && sock_type == SOCK_STREAM)
	commSetTcpRcvbuf(new_socket, tcp_rcv_bufsz);
    return new_socket;
}

/*
 * NOTE: set the listen queue to Squid_MaxFD/4 and rely on the kernel to      
 * impose an upper limit.  Solaris' listen(3n) page says it has   
 * no limit on this parameter, but sys/socket.h sets SOMAXCONN 
 * to 5.  HP-UX currently has a limit of 20.  SunOS is 5 and
 * OSF 3.0 is 8.
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

void
commConnectStart(int fd, const char *host, u_short port, CNCB * callback, void *data)
{
    ConnectStateData *cs = xcalloc(1, sizeof(ConnectStateData));
    debug(5, 3) ("commConnectStart: FD %d, %s:%d\n", fd, host, (int) port);
    cbdataAdd(cs, MEM_NONE);
    cs->fd = fd;
    cs->host = xstrdup(host);
    cs->port = port;
    cs->callback = callback;
    cs->data = data;
    cbdataLock(cs->data);
    comm_add_close_handler(fd, commConnectFree, cs);
    cs->locks++;
    ipcache_nbgethostbyname(host, commConnectDnsHandle, cs);
}

static void
commConnectDnsHandle(const ipcache_addrs * ia, void *data)
{
    ConnectStateData *cs = data;
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
commConnectCallback(ConnectStateData * cs, int status)
{
    CNCB *callback = cs->callback;
    void *data = cs->data;
    int fd = cs->fd;
    comm_remove_close_handler(fd, commConnectFree, cs);
    cs->callback = NULL;
    cs->data = NULL;
    commSetTimeout(fd, -1, NULL, NULL);
    commConnectFree(fd, cs);
    if (cbdataValid(data))
	callback(fd, status, data);
    cbdataUnlock(data);
}

static void
commConnectFree(int fd, void *data)
{
    ConnectStateData *cs = data;
    debug(5, 3) ("commConnectFree: FD %d\n", fd);
    if (cs->locks)
	ipcacheUnregister(cs->host, cs);
    if (cs->data)
	cbdataUnlock(cs->data);
    safe_free(cs->host);
    cbdataFree(cs);
}

/* Reset FD so that we can connect() again */
static int
commResetFD(ConnectStateData * cs)
{
    int fd2;
    if (!cbdataValid(cs->data))
	return 0;
    fd2 = socket(AF_INET, SOCK_STREAM, 0);
    if (fd2 < 0) {
	debug(5, 0) ("commResetFD: socket: %s\n", xstrerror());
	fdAdjustReserved();
	return 0;
    }
    if (dup2(fd2, cs->fd) < 0) {
	debug(5, 0) ("commResetFD: dup2: %s\n", xstrerror());
	fdAdjustReserved();
	return 0;
    }
    close(fd2);
    commSetNonBlocking(cs->fd);
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
    ConnectStateData *cs = data;
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
    assert(F->open);
    if (timeout < 0) {
	F->timeout_handler = NULL;
	F->timeout_data = NULL;
	return F->timeout = 0;
    }
    assert(handler || F->timeout_handler);
    if (handler || data) {
	F->timeout_handler = handler;
	F->timeout_data = data;
    }
    return F->timeout = squid_curtime + (time_t) timeout;
}

int
comm_connect_addr(int sock, const struct sockaddr_in *address)
{
    int status = COMM_OK;
    fde *F = &fd_table[sock];
    socklen_t len;
    int x;
    assert(ntohs(address->sin_port) != 0);
    /* Establish connection. */
    if (connect(sock, (struct sockaddr *) address, sizeof(struct sockaddr_in)) < 0) {
	debug(5, 9) ("connect FD %d: %s\n", sock, xstrerror());
#ifdef _SQUID_HPUX_
	if (EALREADY == errno) {
	    /*
	     * On my HP-UX box (HP-UX tirana B.10.10 A 9000/851), 
	     * we get into fast loops on EALREADY.  select(2) continually
	     * says the FD is ready for writing, but connect always
	     * returns EALREADY. I applied a patch (PHNE_12906) but
	     * it didn't help.  -DW Dec 1, 1997
	     */
	    debug(50, 1) ("connect: %s:%d: %s.\n",
		fqdnFromAddr(address->sin_addr),
		ntohs(address->sin_port),
		xstrerror());
	    return COMM_ERROR;
	} else
#endif
	if (ignoreErrno(errno)) {
	    status = COMM_INPROGRESS;
	} else if (EISCONN == errno) {
	    status = COMM_OK;
	} else {
	    if (EINVAL == errno) {
		len = sizeof(x);
		if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *) &x, &len) >= 0)
		    errno = x;
	    }
	    debug(50, 2) ("connect: %s:%d: %s.\n",
		fqdnFromAddr(address->sin_addr),
		ntohs(address->sin_port),
		xstrerror());
	    return COMM_ERROR;
	}
    }
    xstrncpy(F->ipaddr, inet_ntoa(address->sin_addr), 16);
    F->remote_port = ntohs(address->sin_port);
    if (status == COMM_OK) {
	debug(5, 10) ("comm_connect_addr: FD %d connected to %s:%d\n",
	    sock, F->ipaddr, F->remote_port);
    } else if (status == COMM_INPROGRESS) {
	debug(5, 10) ("comm_connect_addr: FD %d connection pending\n", sock);
    }
    /* Add new socket to list of open sockets. */
    return status;
}

/* Wait for an incoming connection on FD.  FD should be a socket returned
 * from comm_listen. */
int
comm_accept(int fd, struct sockaddr_in *peer, struct sockaddr_in *me)
{
    int sock;
    struct sockaddr_in P;
    struct sockaddr_in M;
    socklen_t Slen;
    fde *F = NULL;
    Slen = sizeof(P);
    if ((sock = accept(fd, (struct sockaddr *) &P, &Slen)) < 0) {
	if (ignoreErrno(errno)) {
	    debug(50, 5) ("comm_accept: FD %d: %s\n", fd, xstrerror());
	    return COMM_NOMESSAGE;
	} else if (ENFILE == errno || EMFILE == errno) {
	    debug(50, 3) ("comm_accept: FD %d: %s\n", fd, xstrerror());
	    return COMM_ERROR;
	} else {
	    debug(50, 1) ("comm_accept: FD %d: %s\n", fd, xstrerror());
	    return COMM_ERROR;
	}
    }
    if (peer)
	*peer = P;
    Slen = sizeof(M);
    memset(&M, '\0', Slen);
    getsockname(sock, (struct sockaddr *) &M, &Slen);
    if (me)
	*me = M;
    commSetCloseOnExec(sock);
    /* fdstat update */
    fd_open(sock, FD_SOCKET, "HTTP Request");
    F = &fd_table[sock];
    xstrncpy(F->ipaddr, inet_ntoa(P.sin_addr), 16);
    F->remote_port = htons(P.sin_port);
    F->local_port = htons(M.sin_port);
    commSetNonBlocking(sock);
    return sock;
}

void
commCallCloseHandlers(int fd)
{
    fde *F = &fd_table[fd];
    close_handler *ch;
    debug(5, 5) ("commCallCloseHandlers: FD %d\n", fd);
    while ((ch = F->close_handler) != NULL) {
	F->close_handler = ch->next;
	debug(5, 5) ("commCallCloseHandlers: ch->handler=%p\n", ch->handler);
	if (cbdataValid(ch->data))
	    ch->handler(fd, ch->data);
	cbdataUnlock(ch->data);
	safe_free(ch);
    }
}

#if LINGERING_CLOSE
static void
commLingerClose(int fd, void *unused)
{
    LOCAL_ARRAY(char, buf, 1024);
    int n;
    n = read(fd, buf, 1024);
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
    if (shutdown(fd, 1) < 0) {
	comm_close(fd);
	return;
    }
    fd_note(fd, "lingering close");
    commSetTimeout(fd, 10, commLingerTimeout, NULL);
    commSetSelect(fd, COMM_SELECT_READ, commLingerClose, NULL, 0);
}
#endif

void
comm_close(int fd)
{
    fde *F = NULL;
#if USE_ASYNC_IO
    int doaioclose = 1;
#endif
    debug(5, 5) ("comm_close: FD %d\n", fd);
    assert(fd >= 0);
    assert(fd < Squid_MaxFD);
    F = &fd_table[fd];
    if (F->flags.closing)
	return;
    if (shutting_down && (!F->open || F->type == FD_FILE))
	return;
    assert(F->open);
    assert(F->type != FD_FILE);
#ifdef USE_ASYNC_IO
    if (F->flags.nolinger && F->flags.nonblocking)
	doaioclose = 0;
#endif
    F->flags.closing = 1;
    CommWriteStateCallbackAndFree(fd, COMM_ERR_CLOSING);
    commCallCloseHandlers(fd);
    if (F->uses)		/* assume persistent connect count */
	pconnHistCount(1, F->uses);
    fd_close(fd);		/* update fdstat */
#if defined(_SQUID_LINUX_)
    /*
     * michael@metal.iinet.net.au sez close() on
     * network sockets never blocks.
     */
    close(fd);
#elif USE_ASYNC_IO
    if (doaioclose)
	aioClose(fd);
    else
	close(fd);
#else
    close(fd);
#endif
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
    x = sendto(fd, buf, len, 0, (struct sockaddr *) to_addr, addr_len);
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
commSetSelect(int fd, unsigned int type, PF * handler, void *client_data, time_t timeout)
{
    fde *F = &fd_table[fd];
    assert(fd >= 0);
    assert(F->open == FD_OPEN);
    debug(5, 5) ("commSetSelect: FD %d type %d\n", fd, type);
    if (type & COMM_SELECT_READ) {
	F->read_handler = handler;
	F->read_data = client_data;
    }
    if (type & COMM_SELECT_WRITE) {
	F->write_handler = handler;
	F->write_data = client_data;
    }
    if (timeout)
	F->timeout = squid_curtime + timeout;
}

void
comm_add_close_handler(int fd, PF * handler, void *data)
{
    close_handler *new = xmalloc(sizeof(*new));
    close_handler *c;
    debug(5, 5) ("comm_add_close_handler: FD %d, handler=%p, data=%p\n",
	fd, handler, data);
    for (c = fd_table[fd].close_handler; c; c = c->next)
	assert(c->handler != handler || c->data != data);
    new->handler = handler;
    new->data = data;
    new->next = fd_table[fd].close_handler;
    fd_table[fd].close_handler = new;
    cbdataLock(data);
}

void
comm_remove_close_handler(int fd, PF * handler, void *data)
{
    close_handler *p;
    close_handler *last = NULL;
    /* Find handler in list */
    debug(5, 5) ("comm_remove_close_handler: FD %d, handler=%p, data=%p\n",
	fd, handler, data);
    for (p = fd_table[fd].close_handler; p != NULL; last = p, p = p->next)
	if (p->handler == handler && p->data == data)
	    break;		/* This is our handler */
    assert(p != NULL);
    /* Remove list entry */
    if (last)
	last->next = p->next;
    else
	fd_table[fd].close_handler = p->next;
    cbdataUnlock(p->data);
    safe_free(p);
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
    if ((flags = fcntl(fd, F_GETFL, dummy)) < 0) {
	debug(50, 0) ("FD %d: fcntl F_GETFL: %s\n", fd, xstrerror());
	return COMM_ERROR;
    }
    if (fcntl(fd, F_SETFL, flags | SQUID_NONBLOCK) < 0) {
	debug(50, 0) ("commSetNonBlocking: FD %d: %s\n", fd, xstrerror());
	return COMM_ERROR;
    }
    fd_table[fd].flags.nonblocking = 1;
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
#endif
}

#ifdef TCP_NODELAY
static void
commSetTcpNoDelay(int fd)
{
    int on = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof(on)) < 0)
	debug(50, 1) ("commSetTcpNoDelay: FD %d: %s\n", fd, xstrerror());
}
#endif


void
comm_init(void)
{
    fd_table = xcalloc(Squid_MaxFD, sizeof(fde));
    /* XXX account fd_table */
    /* Keep a few file descriptors free so that we don't run out of FD's
     * after accepting a client but before it opens a socket or a file.
     * Since Squid_MaxFD can be as high as several thousand, don't waste them */
    RESERVED_FD = XMIN(100, Squid_MaxFD / 4);
}

/* Write to FD. */
static void
commHandleWrite(int fd, void *data)
{
    CommWriteStateData *state = data;
    int len = 0;
    int nleft;

    debug(5, 5) ("commHandleWrite: FD %d: off %d, sz %d.\n",
	fd, (int) state->offset, state->size);

    nleft = state->size - state->offset;
    len = write(fd, state->buf + state->offset, nleft);
    debug(5, 5) ("commHandleWrite: write() returns %d\n", len);
    fd_bytes(fd, len, FD_WRITE);

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
	if (state->offset < state->size) {
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
}



/* Select for Writing on FD, until SIZE bytes are sent.  Call
 * * HANDLER when complete. */
void
comm_write(int fd, char *buf, int size, CWCB * handler, void *handler_data, FREE * free_func)
{
    CommWriteStateData *state = fd_table[fd].rwstate;
    debug(5, 5) ("comm_write: FD %d: sz %d: hndl %p: data %p.\n",
	fd, size, handler, handler_data);
    if (NULL != state) {
	debug(5, 1) ("comm_write: fd_table[%d].rwstate != NULL\n", fd);
	safe_free(state);
	fd_table[fd].rwstate = NULL;
    }
    assert(state == NULL);
    fd_table[fd].rwstate = state = xcalloc(1, sizeof(CommWriteStateData));
    state->buf = buf;
    state->size = size;
    state->offset = 0;
    state->handler = handler;
    state->handler_data = handler_data;
    state->free_func = free_func;
    cbdataLock(handler_data);
#ifdef OPTIMISTIC_IO
    commHandleWrite(fd, state);
#else
    commSetSelect(fd, COMM_SELECT_WRITE, commHandleWrite, state, 0);
#endif
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
    PF *callback;
    for (fd = 0; fd <= Biggest_FD; fd++) {
	F = &fd_table[fd];
	if (F->open != FD_OPEN)
	    continue;
	if (F->type != FD_SOCKET)
	    continue;
	if (F->flags.ipc)	/* don't close inter-process sockets */
	    continue;
	if (F->timeout_handler) {
	    debug(5, 5) ("commCloseAllSockets: FD %d: Calling timeout handler\n",
		fd);
	    callback = F->timeout_handler;
	    F->timeout_handler = NULL;
	    callback(fd, F->timeout_data);
	} else {
	    debug(5, 5) ("commCloseAllSockets: FD %d: calling comm_close()\n", fd);
	    comm_close(fd);
	}
    }
}
