
/*
 * $Id: comm.cc,v 1.148 1997/04/30 20:06:25 wessels Exp $
 *
 * DEBUG: section 5     Socket Functions
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
#include <errno.h>

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

/* Block processing new client requests (accepts on ascii port) when we start
 * running shy of free file descriptors.  For example, under SunOS, we'll keep
 * 64 file descriptors free for disk-i/o and connections to remote servers */

int RESERVED_FD = 64;

#define min(x,y) ((x)<(y)? (x) : (y))
#define max(a,b) ((a)>(b)? (a) : (b))

typedef struct _RWStateData {
    char *buf;
    long size;
    long offset;
    RWCB *handler;
    void *handler_data;
    void (*free) (void *);
} RWStateData;

/* GLOBAL */
FD_ENTRY *fd_table = NULL;	/* also used in disk.c */

/* STATIC */
static int commBind _PARAMS((int s, struct in_addr, u_short port));
static int comm_cleanup_fd_entry _PARAMS((int));
#ifndef USE_POLL
static int examine_select _PARAMS((fd_set *, fd_set *));
#endif
static void checkTimeouts _PARAMS((void));
static void Reserve_More_FDs _PARAMS((void));
static void commSetReuseAddr _PARAMS((int));
static void commSetNoLinger _PARAMS((int));
static void comm_select_incoming _PARAMS((void));
static void RWStateCallbackAndFree _PARAMS((int fd, int code));
#ifdef TCP_NODELAY
static void commSetTcpNoDelay _PARAMS((int));
#endif
static void commSetTcpRcvbuf _PARAMS((int, int));
static void commConnectFree _PARAMS((int fd, void *data));
static void commConnectHandle _PARAMS((int fd, void *data));
static void commHandleWrite _PARAMS((int fd, void *data));

static struct timeval zero_tv;

void
commCancelRWHandler(int fd)
{
    RWStateData *RWState = fd_table[fd].rwstate;
    if (RWState) {
	RWState->handler = NULL;
	RWState->handler_data = NULL;
    }
}


static void
RWStateCallbackAndFree(int fd, int code)
{
    RWStateData *RWState = fd_table[fd].rwstate;
    RWCB *callback = NULL;
    fd_table[fd].rwstate = NULL;
    if (RWState == NULL)
	return;
    if (RWState->free) {
	RWState->free(RWState->buf);
	RWState->buf = NULL;
    }
    callback = RWState->handler;
    RWState->handler = NULL;
    if (callback) {
	callback(fd,
	    RWState->buf,
	    RWState->offset,
	    code,
	    RWState->handler_data);
    }
    safe_free(RWState);
}

/* Return the local port associated with fd. */
u_short
comm_local_port(int fd)
{
    struct sockaddr_in addr;
    int addr_len = 0;
    FD_ENTRY *fde = &fd_table[fd];

    /* If the fd is closed already, just return */
    if (!fde->open) {
	debug(5, 0, "comm_local_port: FD %d has been closed.\n", fd);
	return 0;
    }
    if (fde->local_port)
	return fde->local_port;
    addr_len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *) &addr, &addr_len)) {
	debug(50, 1, "comm_local_port: Failed to retrieve TCP/UDP port number for socket: FD %d: %s\n", fd, xstrerror());
	return 0;
    }
    debug(5, 6, "comm_local_port: FD %d: sockaddr %u.\n", fd, addr.sin_addr.s_addr);
    fde->local_port = ntohs(addr.sin_port);
    return fde->local_port;
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
    debug(50, 0, "commBind: Cannot bind socket FD %d to %s:%d: %s\n",
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
    FD_ENTRY *fde = NULL;
    int tcp_rcv_bufsz = Config.tcpRcvBufsz;

    /* Create socket for accepting new connections. */
    if ((new_socket = socket(AF_INET, sock_type, proto)) < 0) {
	/* Increase the number of reserved fd's if calls to socket()
	 * are failing because the open file table is full.  This
	 * limits the number of simultaneous clients */
	switch (errno) {
	case ENFILE:
	case EMFILE:
	    debug(50, 1, "comm_open: socket failure: %s\n", xstrerror());
	    Reserve_More_FDs();
	    break;
	default:
	    debug(50, 0, "comm_open: socket failure: %s\n", xstrerror());
	}
	return (COMM_ERROR);
    }
    /* update fdstat */
    fd_open(new_socket, FD_SOCKET, note);
    fde = &fd_table[new_socket];
    if (!BIT_TEST(flags, COMM_NOCLOEXEC))
	commSetCloseOnExec(new_socket);
    if (port > (u_short) 0) {
	commSetNoLinger(new_socket);
	if (do_reuse)
	    commSetReuseAddr(new_socket);
    }
    if (addr.s_addr != no_addr.s_addr)
	if (commBind(new_socket, addr, port) != COMM_OK)
	    return COMM_ERROR;
    fde->local_port = port;

    if (BIT_TEST(flags, COMM_NONBLOCKING))
	if (commSetNonBlocking(new_socket) == COMM_ERROR)
	    return COMM_ERROR;
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
	debug(50, 0, "comm_listen: listen(%d, %d): %s\n",
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
    cs->host = xstrdup(host);
    cs->port = port;
    cs->callback = callback;
    cs->data = data;
    comm_add_close_handler(fd, commConnectFree, cs);
    commConnectHandle(fd, cs);
}

static void
commConnectFree(int fd, void *data)
{
    ConnectStateData *cs = data;
    xfree(cs->host);
    xfree(cs);
}

/* Connect SOCK to specified DEST_PORT at DEST_HOST. */
static void
commConnectHandle(int fd, void *data)
{
    ConnectStateData *connectState = data;
    const ipcache_addrs *ia = NULL;
    if (connectState->S.sin_addr.s_addr == 0) {
	ia = ipcache_gethostbyname(connectState->host, IP_BLOCKING_LOOKUP);
	if (ia == NULL) {
	    debug(5, 3, "commConnectHandle: Unknown host: %s\n",
		connectState->host);
	    connectState->callback(fd,
		COMM_ERROR,
		connectState->data);
	    return;
	}
	connectState->S.sin_family = AF_INET;
	connectState->S.sin_addr = ia->in_addrs[ia->cur];
	connectState->S.sin_port = htons(connectState->port);
	if (Config.Log.log_fqdn)
	    fqdncache_gethostbyaddr(connectState->S.sin_addr, FQDN_LOOKUP_IF_MISS);
    }
    switch (comm_connect_addr(fd, &connectState->S)) {
    case COMM_INPROGRESS:
	commSetSelect(fd,
	    COMM_SELECT_WRITE,
	    commConnectHandle,
	    (void *) connectState,
	    0);
	break;
    case COMM_OK:
	if (vizSock > -1)
	    vizHackSendPkt(&connectState->S, 2);
	ipcacheCycleAddr(connectState->host);
	connectState->callback(fd, COMM_OK, connectState->data);
	break;
    default:
	ipcacheRemoveBadAddr(connectState->host, connectState->S.sin_addr);
	connectState->callback(fd, COMM_ERROR, connectState->data);
	break;
    }
}
int
commSetTimeout(int fd, int timeout, PF * handler, void *data)
{
    FD_ENTRY *fde;
    debug(5, 3, "commSetTimeout: FD %d timeout %d\n", fd, timeout);
    if (fd < 0 || fd > Squid_MaxFD)
	fatal_dump("commSetTimeout: bad FD");
    fde = &fd_table[fd];
    if (timeout < 0) {
	fde->timeout_handler = NULL;
	fde->timeout_data = NULL;
	return fde->timeout = 0;
    }
    if (shutdown_pending || reread_pending) {
	/* don't increase the timeout if something pending */
	if (fde->timeout > 0 && (int) (fde->timeout - squid_curtime) < timeout)
	    return fde->timeout;
    }
    if (handler || data) {
	fde->timeout_handler = handler;
	fde->timeout_data = data;
    } else if (fde->timeout_handler == NULL) {
	debug_trap("commSetTimeout: setting timeout, but no handler");
    }
    return fde->timeout = squid_curtime + (time_t) timeout;
}

int
comm_connect_addr(int sock, const struct sockaddr_in *address)
{
    int status = COMM_OK;
    FD_ENTRY *fde = &fd_table[sock];
    int len;
    int x;
    /* sanity check */
    if (ntohs(address->sin_port) == 0) {
	debug(5, 10, "comm_connect_addr: %s:%d: URL uses port 0?\n",
	    inet_ntoa(address->sin_addr), ntohs(address->sin_port));
	errno = 0;
	return COMM_ERROR;
    }
    /* Establish connection. */
    if (connect(sock, (struct sockaddr *) address, sizeof(struct sockaddr_in)) < 0) {
	switch (errno) {
	case EALREADY:
	    return COMM_ERROR;
	    /* NOTREACHED */
#if EAGAIN != EWOULDBLOCK
	case EAGAIN:
#endif
	case EINTR:
	case EWOULDBLOCK:
	case EINPROGRESS:
	    status = COMM_INPROGRESS;
	    break;
	case EISCONN:
	    status = COMM_OK;
	    break;
	case EINVAL:
	    len = sizeof(x);
	    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *) &x, &len) >= 0)
		errno = x;
	default:
	    debug(50, 2, "connect: %s:%d: %s.\n",
		fqdnFromAddr(address->sin_addr),
		ntohs(address->sin_port),
		xstrerror());
	    return COMM_ERROR;
	}
    }
    xstrncpy(fde->ipaddr, inet_ntoa(address->sin_addr), 16);
    fde->remote_port = ntohs(address->sin_port);
    if (status == COMM_OK) {
	debug(5, 10, "comm_connect_addr: FD %d connected to %s:%d\n",
	    sock, fde->ipaddr, fde->remote_port);
    } else if (status == COMM_INPROGRESS) {
	debug(5, 10, "comm_connect_addr: FD %d connection pending\n", sock);
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
    int Slen;
    FD_ENTRY *fde = NULL;

    Slen = sizeof(P);
    while ((sock = accept(fd, (struct sockaddr *) &P, &Slen)) < 0) {
	switch (errno) {
#if EAGAIN != EWOULDBLOCK
	case EAGAIN:
#endif
	case EWOULDBLOCK:
	case EINTR:
	    return COMM_NOMESSAGE;
	case ENFILE:
	case EMFILE:
	    Reserve_More_FDs();
	    return COMM_ERROR;
	default:
	    debug(50, 1, "comm_accept: FD %d: accept failure: %s\n",
		fd, xstrerror());
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
    fde = &fd_table[sock];
    strcpy(fde->ipaddr, inet_ntoa(P.sin_addr));
    fde->remote_port = htons(P.sin_port);
    fde->local_port = htons(M.sin_port);
    commSetNonBlocking(sock);
    return sock;
}

void
commCallCloseHandlers(int fd)
{
    FD_ENTRY *fde = &fd_table[fd];
    struct close_handler *ch;
    debug(5, 5, "commCallCloseHandlers: FD %d\n", fd);
    while ((ch = fde->close_handler) != NULL) {
	fde->close_handler = ch->next;
	ch->handler(fd, ch->data);
	safe_free(ch);
    }
}

void
comm_close(int fd)
{
    FD_ENTRY *fde = NULL;
    debug(5, 5, "comm_close: FD %d\n", fd);
    if (fd < 0)
	fatal_dump("comm_close: bad FD");
    if (fd >= Squid_MaxFD)
	fatal_dump("comm_close: bad FD");
    fde = &fd_table[fd];
    if (!fde->open)
	return;
    if (fd_table[fd].type == FD_FILE)
	fatal_dump("comm_close: not a SOCKET");
    fde->open = 0;
    RWStateCallbackAndFree(fd, COMM_ERROR);
    commCallCloseHandlers(fd);
    fd_close(fd);		/* update fdstat */
#if USE_ASYNC_IO
    aioClose(fd);
#else
    close(fd);
#endif
}

/* use to clean up fdtable when socket is closed without
 * using comm_close */
static int
comm_cleanup_fd_entry(int fd)
{
    RWStateCallbackAndFree(fd, COMM_ERROR);
    fd_close(fd);
    return 0;
}


/* Send a udp datagram to specified PORT at HOST. */
int
comm_udp_send(int fd, const char *host, u_short port, const char *buf, int len)
{
    const ipcache_addrs *ia = NULL;
    static struct sockaddr_in to_addr;
    int bytes_sent;

    /* Set up the destination socket address for message to send to. */
    to_addr.sin_family = AF_INET;

    if ((ia = ipcache_gethostbyname(host, IP_BLOCKING_LOOKUP)) == 0) {
	debug(50, 1, "comm_udp_send: gethostbyname failure: %s: %s\n",
	    host, xstrerror());
	return (COMM_ERROR);
    }
    to_addr.sin_addr = ia->in_addrs[ia->cur];
    to_addr.sin_port = htons(port);
    if ((bytes_sent = sendto(fd, buf, len, 0, (struct sockaddr *) &to_addr,
		sizeof(to_addr))) < 0) {
	debug(50, 1, "comm_udp_send: sendto failure: FD %d: %s\n",
	    fd, xstrerror());
	return COMM_ERROR;
    }
    return bytes_sent;
}

/* Send a udp datagram to specified TO_ADDR. */
int
comm_udp_sendto(int fd,
    const struct sockaddr_in *to_addr,
    int addr_len,
    const char *buf,
    int len)
{
    int x;
    x = sendto(fd, buf, len, 0, (struct sockaddr *) to_addr, addr_len);
    if (x < 0) {
	debug(50, 1, "comm_udp_sendto: FD %d, %s, port %d: %s\n",
	    fd,
	    inet_ntoa(to_addr->sin_addr),
	    (int) htons(to_addr->sin_port),
	    xstrerror());
	return COMM_ERROR;
    }
    return x;
}

void
comm_set_stall(int fd, int delta)
{
    if (fd < 0)
	return;
    fd_table[fd].stall_until = squid_curtime + delta;
}


#ifdef USE_POLL

/* poll() version by:
 * Stewart Forster <slf@connect.com.au>, and
 * Anthony Baxter <arb@connect.com.au> */

static void
comm_select_incoming(void)
{
    int fd;
    int fds[4];
    struct pollfd pfds[4];
    unsigned long N = 0;
    unsigned long i, nfds;
    int dopoll = 0;
    PF *hdl = NULL;
    if (theInIcpConnection >= 0)
	fds[N++] = theInIcpConnection;
    if (theInIcpConnection != theOutIcpConnection)
	if (theOutIcpConnection >= 0)
	    fds[N++] = theOutIcpConnection;
    if (theHttpConnection >= 0 && fdstat_are_n_free_fd(RESERVED_FD))
	fds[N++] = theHttpConnection;
    for (i = nfds = 0; i < N; i++) {
	int events;
	fd = fds[i];
	events = 0;
	if (fd_table[fd].read_handler)
	    events |= POLLRDNORM;
	if (fd_table[fd].write_handler)
	    events |= POLLWRNORM;
	if (events) {
	    pfds[nfds].fd = fd;
	    pfds[nfds].events = events;
	    pfds[nfds].revents = 0;
	    nfds++;
	}
    }
    if (!nfds)
	return;
    if (poll(pfds, nfds, 0) < 1)
	return;
#ifndef LESS_TIMING
    getCurrentTime();
#endif
    for (i = 0; i < nfds; i++) {
	int revents;
	if (((revents = pfds[i].revents) == 0) || ((fd = pfds[i].fd) == -1))
	    continue;
	if (revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR)) {
	    hdl = fd_table[fd].read_handler;
	    fd_table[fd].read_handler = 0;
	    hdl(fd, fd_table[fd].read_data);
	}
	if (revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR)) {
	    hdl = fd_table[fd].write_handler;
	    fd_table[fd].write_handler = 0;
	    hdl(fd, fd_table[fd].write_data);
	}
    }
    /* TO FIX: repoll ICP connection here */
}

#else

static void
comm_select_incoming(void)
{
    fd_set read_mask;
    fd_set write_mask;
    int maxfd = 0;
    int fd = 0;
    int fds[4];
    int N = 0;
    int i = 0;
    PF *hdl = NULL;
    FD_ZERO(&read_mask);
    FD_ZERO(&write_mask);
    if (theHttpConnection >= 0 && fdstat_are_n_free_fd(RESERVED_FD))
	fds[N++] = theHttpConnection;
    if (theInIcpConnection >= 0)
	fds[N++] = theInIcpConnection;
    if (theInIcpConnection != theOutIcpConnection)
	if (theOutIcpConnection >= 0)
	    fds[N++] = theOutIcpConnection;
    fds[N++] = 0;
    for (i = 0; i < N; i++) {
	fd = fds[i];
	if (fd_table[fd].read_handler) {
	    FD_SET(fd, &read_mask);
	    if (fd > maxfd)
		maxfd = fd;
	}
	if (fd_table[fd].write_handler) {
	    FD_SET(fd, &write_mask);
	    if (fd > maxfd)
		maxfd = fd;
	}
    }
    if (maxfd++ == 0)
	return;
    if (select(maxfd, &read_mask, &write_mask, NULL, &zero_tv) < 1)
	return;
#ifndef LESS_TIMING
    getCurrentTime();
#endif
    for (i = 0; i < N; i++) {
	fd = fds[i];
	if (FD_ISSET(fd, &read_mask)) {
	    hdl = fd_table[fd].read_handler;
	    fd_table[fd].read_handler = 0;
	    hdl(fd, fd_table[fd].read_data);
	}
	if (FD_ISSET(fd, &write_mask)) {
	    hdl = fd_table[fd].write_handler;
	    fd_table[fd].write_handler = 0;
	    hdl(fd, fd_table[fd].write_data);
	}
    }
}
#endif

#ifdef USE_POLL
/* poll all sockets; call handlers for those that are ready. */
int
comm_select(time_t sec)
{
    struct pollfd pfds[SQUID_MAXFD];
    PF *hdl = NULL;
    int fd;
    int i;
    int maxfd;
    unsigned long nfds;
    int num;
    static time_t last_timeout = 0;
    static time_t pending_time;
    int poll_time;
    time_t timeout;
    /* assume all process are very fast (less than 1 second). Call
     * time() only once */
    getCurrentTime();
    /* use only 1 second granularity */
    timeout = squid_curtime + sec;
    do {
	if (sec > 60)
	    fatal_dump(NULL);
	if (shutdown_pending || reread_pending) {
	    serverConnectionsClose();
	    ftpServerClose();
	    dnsShutdownServers();
	    redirectShutdownServers();
	    /* shutdown_pending will be set to
	     * +1 for SIGTERM
	     * -1 for SIGINT */
	    /* reread_pending always == 1 when SIGHUP received */
	    if (shutdown_pending > 0 || reread_pending > 0)
		setSocketShutdownLifetimes(Config.shutdownLifetime);
	    else
		setSocketShutdownLifetimes(0);
	}
	nfds = 0;
	maxfd = Biggest_FD + 1;
	httpindex = -1;
	for (i = 0; i < maxfd; i++) {
	    int events;
	    events = 0;
	    /* Check each open socket for a handler. */
	    if (fd_table[i].read_handler && fd_table[i].stall_until <= squid_curtime)
		events |= POLLRDNORM;
	    if (fd_table[i].write_handler)
		events |= POLLWRNORM;
	    if (events) {
		if (i == theHttpConnection)
		    httpindex = nfds;
		pfds[nfds].fd = i;
		pfds[nfds].events = events;
		pfds[nfds].revents = 0;
		nfds++;
		if (pfds[i].events == 0)
		    pfds[i].fd = -1;
	    }
	    /* If we're out of free fd's, don't poll the http incoming fd */
	    if (!fdstat_are_n_free_fd(RESERVED_FD) && httpindex >= 0) {
		pfds[httpindex].fd = -1;
		pfds[httpindex].events = 0;
	    }
	    if (shutdown_pending || reread_pending)
		debug(5, 2, "comm_select: Still waiting on %d FDs\n", nfds);
	    if (pending_time == 0)
		pending_time = squid_curtime;
	    if ((squid_curtime - pending_time) > (Config.shutdownLifetime + 5)) {
		pending_time = 0;
		for (i = 1; i < maxfd; i++) {
		    if ((fd = pfds[i].fd) < 0)
			continue;
		    if (fd_table[fd].type == FD_FILE)
			file_must_close(fd);
		    else
			comm_close(fd);
		    pfds[fd].fd = -1;
		}
	    }
	}
	pending_time = 0;
	if (nfds == 0)
	    return COMM_SHUTDOWN;
	poll_time = sec > 0 ? 100 : 0;
#if USE_ASYNC_IO
	aioCheckCallbacks();
#endif
	for (;;) {
	    poll_time = sec > 0 ? 1000 : 0;
	    num = poll(pfds, nfds, poll_time);
	    select_loops++;
	    getCurrentTime();
	    if (num >= 0)
		break;
	    if (errno == EINTR)
		continue;
	    debug(5, 0, "comm_select: poll failure: %s\n",
		xstrerror());
	    if (errno == EINVAL) {
		/* nfds greater than OPEN_MAX?? How possible? Time */
		/* to bail - write out nfds to cache.log and start */
		/* emergency shutdown by sending SIGTERM to self */
		debug(20, 1, "Poll returned EINVAL. Polled %d FD's\n", nfds);
		kill(getpid(), SIGTERM);
	    }
	    return COMM_ERROR;
	    /* NOTREACHED */
	}
	getCurrentTime();
	debug(5, num ? 5 : 8, "comm_select: %d sockets ready at %d\n",
	    num, (int) squid_curtime);
	/* Check timeout handlers ONCE each second. */
	if (squid_curtime > last_timeout) {
	    last_timeout = squid_curtime;
	    checkTimeouts();
	}
	if (num == 0)
	    continue;
	/* scan each socket but the accept socket. Poll this 
	 * more frequently to minimize losses due to the 5 connect 
	 * limit in SunOS */
	for (i = 0; i < nfds; i++) {
	    int revents;
	    if (((revents = pfds[i].revents) == 0) || ((fd = pfds[i].fd) == -1))
		continue;
	    /*
	     * Admit more connections quickly until we hit the hard limit.
	     * Don't forget to keep the UDP acks coming and going.
	     */
	    if ((i % 2) == 0)
		comm_select_incoming();
	    if ((fd == theInIcpConnection) || (fd == theHttpConnection) || (fd == theOutIcpConnection) || (fd == 0))
		continue;
	    if (revents & (POLLRDNORM | POLLIN | POLLHUP | POLLERR)) {
		debug(5, 6, "comm_select: FD %d ready for reading\n", fd);
		hdl = fd_table[fd].read_handler;
		fd_table[fd].read_handler = 0;
		hdl(fd, fd_table[fd].read_data);
	    }
	    if (revents & (POLLWRNORM | POLLOUT | POLLHUP | POLLERR)) {
		debug(5, 5, "comm_select: FD %d ready for writing\n", fd);
		hdl = fd_table[fd].write_handler;
		fd_table[fd].write_handler = 0;
		hdl(fd, fd_table[fd].write_data);
	    }
	    if (revents & POLLNVAL) {
		struct close_handler *ch;
		struct close_handler *next;
		FD_ENTRY *fde = &fd_table[fd];
		debug(5, 0, "WARNING: FD %d has handlers, but it's invalid.\n", fd);
		debug(5, 0, "FD %d is a %s\n", fd, fdstatTypeStr[fd_table[fd].type]);
		debug(5, 0, "--> %s\n", fd_note(fd, NULL));
		debug(5, 0, "tmout:%p read:%p write:%p\n",
		    fde->timeout_handler,
		    fde->read_handler,
		    fde->write_handler);
		for (ch = fde->close_handler; ch; ch = ch->next)
		    debug(5, 0, " close handler: %p\n", ch->handler);
		if (fde->close_handler) {
		    for (ch = fde->close_handler; ch; ch = next) {
			next = ch->next;
			ch->handler(fd, ch->data);
			safe_free(ch);
		    }
		} else if (fde->timeout_handler) {
		    debug(5, 0, "examine_select: Calling Timeout Handler\n");
		    fde->timeout_handler(fd, fde->timeout_data);
		}
		fde->close_handler = NULL;
		fde->timeout_handler = NULL;
		fde->read_handler = NULL;
		fde->write_handler = NULL;
	    }
	}
	return COMM_OK;
    } while (timeout > getCurrentTime());
    debug(5, 8, "comm_select: time out: %d.\n", squid_curtime);
    return COMM_TIMEOUT;
}

#else

/* Select on all sockets; call handlers for those that are ready. */
int
comm_select(time_t sec)
{
    fd_set readfds;
    fd_set writefds;
    PF *hdl = NULL;
    int fd;
    int i;
    int maxfd;
    int nfds;
    int num;
    static time_t last_timeout = 0;
    struct timeval poll_time;
    time_t timeout;

    /* assume all process are very fast (less than 1 second). Call
     * time() only once */
    getCurrentTime();
    /* use only 1 second granularity */
    timeout = squid_curtime + sec;

    do {
	if (sec > 60)
	    fatal_dump(NULL);
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	if (shutdown_pending || reread_pending) {
	    serverConnectionsClose();
	    ftpServerClose();
	    dnsShutdownServers();
	    redirectShutdownServers();
	    /* shutdown_pending will be set to
	     * +1 for SIGTERM
	     * -1 for SIGINT */
	    /* reread_pending always == 1 when SIGHUP received */
	    if (shutdown_pending > 0 || reread_pending > 0)
		setSocketShutdownLifetimes(Config.shutdownLifetime);
	    else
		setSocketShutdownLifetimes(0);
	}
	nfds = 0;
	maxfd = Biggest_FD + 1;
	for (i = 0; i < maxfd; i++) {
	    /* Check each open socket for a handler. */
	    if (fd_table[i].stall_until > squid_curtime)
		continue;
	    if (fd_table[i].read_handler) {
		nfds++;
		FD_SET(i, &readfds);
	    }
	    if (fd_table[i].write_handler) {
		nfds++;
		FD_SET(i, &writefds);
	    }
	}
	if (!fdstat_are_n_free_fd(RESERVED_FD) && theHttpConnection >= 0) {
	    FD_CLR(theHttpConnection, &readfds);
	}
	if (shutdown_pending || reread_pending)
	    debug(5, 2, "comm_select: Still waiting on %d FDs\n", nfds);
	if (nfds == 0)
	    return COMM_SHUTDOWN;
#if USE_ASYNC_IO
	aioCheckCallbacks();
#endif
	for (;;) {
	    poll_time.tv_sec = sec > 0 ? 1 : 0;
	    poll_time.tv_usec = 0;
	    num = select(maxfd, &readfds, &writefds, NULL, &poll_time);
	    select_loops++;
	    getCurrentTime();
	    if (num >= 0)
		break;
	    if (errno == EINTR)
		break;
	    debug(50, 0, "comm_select: select failure: %s\n",
		xstrerror());
	    examine_select(&readfds, &writefds);
	    return COMM_ERROR;
	    /* NOTREACHED */
	}
	if (num < 0)
	    continue;
	debug(5, num ? 5 : 8, "comm_select: %d sockets ready at %d\n",
	    num, (int) squid_curtime);

	/* Check lifetime and timeout handlers ONCE each second.
	 * Replaces brain-dead check every time through the loop! */
	if (squid_curtime > last_timeout) {
	    last_timeout = squid_curtime;
	    checkTimeouts();
	}
	if (num == 0)
	    continue;

	/* scan each socket but the accept socket. Poll this 
	 * more frequently to minimize losses due to the 5 connect 
	 * limit in SunOS */

	for (fd = 0; fd < maxfd; fd++) {
	    if (!FD_ISSET(fd, &readfds) && !FD_ISSET(fd, &writefds))
		continue;
	    /*
	     * Admit more connections quickly until we hit the hard limit.
	     * Don't forget to keep the UDP acks coming and going.
	     */
	    comm_select_incoming();
	    if (fd == theInIcpConnection)
		continue;
	    if (fd == theOutIcpConnection)
		continue;
	    if (fd == theHttpConnection)
		continue;
	    if (FD_ISSET(fd, &readfds)) {
		debug(5, 6, "comm_select: FD %d ready for reading\n", fd);
		if (fd_table[fd].read_handler) {
		    hdl = fd_table[fd].read_handler;
		    fd_table[fd].read_handler = 0;
		    hdl(fd, fd_table[fd].read_data);
		    comm_select_incoming();
		}
	    }
	    if (FD_ISSET(fd, &writefds)) {
		debug(5, 5, "comm_select: FD %d ready for writing\n", fd);
		if (fd_table[fd].write_handler) {
		    hdl = fd_table[fd].write_handler;
		    fd_table[fd].write_handler = 0;
		    hdl(fd, fd_table[fd].write_data);
		    comm_select_incoming();
		}
	    }
	}
	return COMM_OK;
    } while (timeout > getCurrentTime());

    debug(5, 8, "comm_select: time out: %d.\n", squid_curtime);
    return COMM_TIMEOUT;
}
#endif

void
commSetSelect(int fd, unsigned int type, PF * handler, void *client_data, time_t timeout)
{
    FD_ENTRY *fde;
    if (fd < 0)
	fatal_dump("commSetSelect: bad FD");
    fde = &fd_table[fd];
    if (type & COMM_SELECT_READ) {
	fde->read_handler = handler;
	fde->read_data = client_data;
    }
    if (type & COMM_SELECT_WRITE) {
	fde->write_handler = handler;
	fde->write_data = client_data;
    }
    if (timeout)
	fde->timeout = squid_curtime + timeout;
}

void
comm_add_close_handler(int fd, PF * handler, void *data)
{
    struct close_handler *new = xmalloc(sizeof(*new));
    debug(5, 5, "comm_add_close_handler: FD %d, handler=%p, data=%p\n",
	fd, handler, data);
    new->handler = handler;
    new->data = data;
    new->next = fd_table[fd].close_handler;
    fd_table[fd].close_handler = new;
}

void
comm_remove_close_handler(int fd, PF * handler, void *data)
{
    struct close_handler *p, *last = NULL;

    /* Find handler in list */
    for (p = fd_table[fd].close_handler; p != NULL; last = p, p = p->next)
	if (p->handler == handler && p->data == data)
	    break;		/* This is our handler */
    if (!p)
	fatal_dump("comm_remove_close_handler: Handler not found!\n");

    /* Remove list entry */
    if (last)
	last->next = p->next;
    else
	fd_table[fd].close_handler = p->next;
    safe_free(p);
}

int
comm_set_mcast_ttl(int fd, int mcast_ttl)
{
#ifdef IP_MULTICAST_TTL
    char ttl = (char) mcast_ttl;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, 1) < 0)
	debug(50, 1, "comm_set_mcast_ttl: FD %d, TTL: %d: %s\n",
	    fd, mcast_ttl, xstrerror());
#endif
    return 0;
}

int
comm_join_mcast_groups(int fd)
{
#ifdef IP_MULTICAST_TTL
    struct ip_mreq mr;
    wordlist *s = NULL;
    const ipcache_addrs *ia = NULL;
    int i;
    int x;
    char c = 0;
    for (s = Config.mcast_group_list; s; s = s->next) {
	debug(5, 10, "comm_join_mcast_groups: joining group %s on FD %d\n",
	    s->key, fd);
	ia = ipcache_gethostbyname(s->key, IP_BLOCKING_LOOKUP);
	if (ia == NULL) {
	    debug(5, 0, "Unknown host: %s\n", s->key);
	    continue;
	}
	for (i = 0; i < (int) ia->count; i++) {
	    mr.imr_multiaddr.s_addr = (ia->in_addrs + i)->s_addr;
	    mr.imr_interface.s_addr = INADDR_ANY;
	    x = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		(char *) &mr, sizeof(struct ip_mreq));
	    if (x < 0)
		debug(5, 1, "comm_join_mcast_groups: FD %d, addr: %s [%s]\n",
		    fd, s->key, inet_ntoa(*(ia->in_addrs + i)));
	    x = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &c, 1);
	    if (x < 0)
		debug(5, 1,
		    "comm_join_mcast_groups: can't disable m'cast loopback: %s\n",
		    xstrerror());

	}
    }
#endif
    return 0;
}

static void
commSetNoLinger(int fd)
{
    struct linger L;
    L.l_onoff = 0;		/* off */
    L.l_linger = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &L, sizeof(L)) < 0)
	debug(50, 0, "commSetNoLinger: FD %d: %s\n", fd, xstrerror());
}

static void
commSetReuseAddr(int fd)
{
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0)
	debug(50, 1, "commSetReuseAddr: FD %d: %s\n", fd, xstrerror());
}

static void
commSetTcpRcvbuf(int fd, int size)
{
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &size, sizeof(size)) < 0)
	debug(50, 1, "commSetTcpRcvbuf: FD %d, SIZE %d: %s\n",
	    fd, size, xstrerror());
}

int
commSetNonBlocking(int fd)
{
    int flags;
    int dummy = 0;
    if ((flags = fcntl(fd, F_GETFL, dummy)) < 0) {
	debug(50, 0, "FD %d: fcntl F_GETFL: %s\n", fd, xstrerror());
	return COMM_ERROR;
    }
    if (fcntl(fd, F_SETFL, flags | SQUID_NONBLOCK) < 0) {
	debug(50, 0, "commSetNonBlocking: FD %d: %s\n", fd, xstrerror());
	return COMM_ERROR;
    }
    return 0;
}

void
commSetCloseOnExec(int fd)
{
#ifdef FD_CLOEXEC
    int flags;
    if ((flags = fcntl(fd, F_GETFL)) < 0) {
	debug(50, 0, "FD %d: fcntl F_GETFL: %s\n", fd, xstrerror());
	return;
    }
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
	debug(50, 0, "FD %d: set close-on-exec failed: %s\n", fd, xstrerror());
#endif
}

#ifdef TCP_NODELAY
static void
commSetTcpNoDelay(int fd)
{
    int on = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof(on)) < 0)
	debug(50, 1, "commSetTcpNoDelay: FD %d: %s\n", fd, xstrerror());
}
#endif

int
comm_init(void)
{
    fd_table = xcalloc(Squid_MaxFD, sizeof(FD_ENTRY));
    meta_data.misc += Squid_MaxFD * sizeof(FD_ENTRY);
    /* Keep a few file descriptors free so that we don't run out of FD's
     * after accepting a client but before it opens a socket or a file.
     * Since Squid_MaxFD can be as high as several thousand, don't waste them */
    RESERVED_FD = min(100, Squid_MaxFD / 4);
    /* hardwired lifetimes */
    meta_data.misc += Squid_MaxFD * sizeof(int);
    zero_tv.tv_sec = 0;
    zero_tv.tv_usec = 0;
    return 0;
}


#ifndef USE_POLL
/*
 * examine_select - debug routine.
 *
 * I spend the day chasing this core dump that occurs when both the client
 * and the server side of a cache fetch simultaneoulsy abort the
 * connection.  While I haven't really studied the code to figure out how
 * it happens, the snippet below may prevent the cache from exitting:
 * 
 * Call this from where the select loop fails.
 */
static int
examine_select(fd_set * readfds, fd_set * writefds)
{
    int fd = 0;
    fd_set read_x;
    fd_set write_x;
    int num;
    struct timeval tv;
    struct close_handler *ch = NULL;
    struct close_handler *next = NULL;
    FD_ENTRY *fde = NULL;

    debug(5, 0, "examine_select: Examining open file descriptors...\n");
    for (fd = 0; fd < Squid_MaxFD; fd++) {
	FD_ZERO(&read_x);
	FD_ZERO(&write_x);
	tv.tv_sec = tv.tv_usec = 0;
	if (FD_ISSET(fd, readfds))
	    FD_SET(fd, &read_x);
	else if (FD_ISSET(fd, writefds))
	    FD_SET(fd, &write_x);
	else
	    continue;
	num = select(Squid_MaxFD, &read_x, &write_x, NULL, &tv);
	if (num > -1) {
	    debug(5, 5, "FD %d is valid.\n", fd);
	    continue;
	}
	fde = &fd_table[fd];
	debug(5, 0, "FD %d: %s\n", fd, xstrerror());
	debug(5, 0, "WARNING: FD %d has handlers, but it's invalid.\n", fd);
	debug(5, 0, "FD %d is a %s called '%s'\n",
	    fd,
	    fdstatTypeStr[fd_table[fd].type],
	    fde->desc);
	debug(5, 0, "tmout:%p read:%p write:%p\n",
	    fde->timeout_handler,
	    fde->read_handler,
	    fde->write_handler);
	for (ch = fde->close_handler; ch; ch = ch->next)
	    debug(5, 0, " close handler: %p\n", ch->handler);
	if (fde->close_handler) {
	    for (ch = fde->close_handler; ch; ch = next) {
		next = ch->next;
		ch->handler(fd, ch->data);
		safe_free(ch);
	    }
	} else if (fde->timeout_handler) {
	    debug(5, 0, "examine_select: Calling Timeout Handler\n");
	    fde->timeout_handler(fd, fde->timeout_data);
	}
	fde->close_handler = NULL;
	fde->timeout_handler = NULL;
	fde->read_handler = NULL;
	fde->write_handler = NULL;
	FD_CLR(fd, readfds);
	FD_CLR(fd, writefds);
    }
    return 0;
}
#endif

static void
checkTimeouts(void)
{
    int fd;
    FD_ENTRY *fde = NULL;
    PF *callback;
    for (fd = 0; fd <= Biggest_FD; fd++) {
	fde = &fd_table[fd];
	if (fde->open != FD_OPEN)
	    continue;
	if (fde->timeout == 0)
	    continue;
	if (fde->timeout > squid_curtime)
	    continue;
	debug(5, 5, "checkTimeouts: FD %d Expired\n", fd);
	if (fde->timeout_handler) {
	    debug(5, 5, "checkTimeouts: FD %d: Call timeout handler\n", fd);
	    callback = fde->timeout_handler;
	    fde->timeout_handler = NULL;
	    callback(fd, fde->timeout_data);
	} else if (fde->read_handler) {
	    debug(5, 5, "checkTimeouts: FD %d: Call read handler\n", fd);
	    callback = fde->read_handler;
	    fde->read_handler = NULL;
	    callback(fd, fde->read_data);
	} else if (fde->write_handler) {
	    debug(5, 5, "checkTimeouts: FD %d: Call write handler\n", fd);
	    callback = fde->write_handler;
	    fde->write_handler = NULL;
	    callback(fd, fde->write_data);
	} else {
	    debug(5, 5, "checkTimeouts: FD %d: Forcing comm_close()\n", fd);
	    comm_close(fd);
	    comm_cleanup_fd_entry(fd);
	}
    }
}

/*
 * Reserve_More_FDs() called when acceopt(), open(), or socket is failing
 */
static void
Reserve_More_FDs(void)
{
    if (RESERVED_FD < Squid_MaxFD - 64) {
	RESERVED_FD = RESERVED_FD + 1;
    } else if (RESERVED_FD == Squid_MaxFD - 64) {
	RESERVED_FD = RESERVED_FD + 1;
	debug(5, 0, "Don't you have a tiny open-file table size of %d\n",
	    Squid_MaxFD - RESERVED_FD);
    }
}

/* Write to FD. */
static void
commHandleWrite(int fd, void *data)
{
    RWStateData *state = data;
    int len = 0;
    int nleft;

    debug(5, 5, "commHandleWrite: FD %d: state=%p, off %d, sz %d.\n",
	fd, state, state->offset, state->size);

    nleft = state->size - state->offset;
    len = write(fd, state->buf + state->offset, nleft);
    fd_bytes(fd, len, FD_WRITE);

    if (len == 0) {
	/* Note we even call write if nleft == 0 */
	/* We're done */
	if (nleft != 0)
	    debug(5, 2, "commHandleWrite: FD %d: write failure: connection closed with %d bytes remaining.\n", fd, nleft);
	RWStateCallbackAndFree(fd, nleft ? COMM_ERROR : COMM_OK);
    } else if (len < 0) {
	/* An error */
	if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
	    debug(50, 10, "commHandleWrite: FD %d: write failure: %s.\n",
		fd, xstrerror());
	    commSetSelect(fd,
		COMM_SELECT_WRITE,
		commHandleWrite,
		state,
		0);
	} else {
	    debug(50, 2, "commHandleWrite: FD %d: write failure: %s.\n",
		fd, xstrerror());
	    RWStateCallbackAndFree(fd, COMM_ERROR);
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
	    RWStateCallbackAndFree(fd, COMM_OK);
	}
    }
}



/* Select for Writing on FD, until SIZE bytes are sent.  Call
 * * HANDLER when complete. */
void
comm_write(int fd, char *buf, int size, RWCB * handler, void *handler_data, void (*free_func) (void *))
{
    RWStateData *state = NULL;

    debug(5, 5, "comm_write: FD %d: sz %d: hndl %p: data %p.\n",
	fd, size, handler, handler_data);

    if (fd_table[fd].rwstate) {
	debug(5, 1, "WARNING: FD %d: A comm_write is already active.\n", fd);
	RWStateCallbackAndFree(fd, COMM_ERROR);
    }
    state = xcalloc(1, sizeof(RWStateData));
    state->buf = buf;
    state->size = size;
    state->offset = 0;
    state->handler = handler;
    state->handler_data = handler_data;
    state->free = free_func;
    fd_table[fd].rwstate = state;
    commSetSelect(fd,
	COMM_SELECT_WRITE,
	commHandleWrite,
	fd_table[fd].rwstate,
	0);
}

void
commFreeMemory(void)
{
    safe_free(fd_table);
}
