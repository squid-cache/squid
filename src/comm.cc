
/*
 * $Id: comm.cc,v 1.34 1996/07/09 04:46:50 wessels Exp $
 *
 * DEBUG: section 5     Socket Functions
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

/* Block processing new client requests (accepts on ascii port) when we start
 * running shy of free file descriptors.  For example, under SunOS, we'll keep
 * 64 file descriptors free for disk-i/o and connections to remote servers */

int RESERVED_FD = 64;
struct in_addr any_addr;

#define min(x,y) ((x)<(y)? (x) : (y))
#define max(a,b) ((a)>(b)? (a) : (b))

struct _RWStateData {
    char *buf;
    long size;
    long offset;
    int timeout;		/* XXX Not used at present. */
    time_t time;		/* XXX Not used at present. */
    rw_complete_handler *handler;
    void *handler_data;
    int handle_immed;
};

/* GLOBAL */
FD_ENTRY *fd_table = NULL;	/* also used in disk.c */

/* STATIC */
static void checkTimeouts _PARAMS((void));
static void checkLifetimes _PARAMS((void));
static void Reserve_More_FDs _PARAMS((void));
static void commSetReuseAddr _PARAMS((int));
static int examine_select _PARAMS((fd_set *, fd_set *, fd_set *));
static void commSetNoLinger _PARAMS((int));
static void comm_select_incoming _PARAMS((void));
static int commBind _PARAMS((int s, struct in_addr, u_short port));
#ifdef TCP_NODELAY
static void commSetTcpNoDelay _PARAMS((int));
#endif

static int *fd_lifetime = NULL;
static struct timeval zero_tv;

/* Return the local port associated with fd. */
u_short comm_local_port(fd)
     int fd;
{
    struct sockaddr_in addr;
    int addr_len = 0;

    /* If the fd is closed already, just return */
    if (!fd_table[fd].openned) {
	debug(5, 0, "comm_local_port: FD %d has been closed.\n", fd);
	return 0;
    }
    if (fd_table[fd].local_port)
	return fd_table[fd].local_port;
    addr_len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *) &addr, &addr_len)) {
	debug(5, 1, "comm_local_port: Failed to retrieve TCP/UDP port number for socket: FD %d: %s\n", fd, xstrerror());
	return 0;
    }
    debug(5, 6, "comm_local_port: FD %d: sockaddr %u.\n", fd, addr.sin_addr.s_addr);
    fd_table[fd].local_port = ntohs(addr.sin_port);
    return fd_table[fd].local_port;
}

static int commBind(s, in_addr, port)
     int s;
     struct in_addr in_addr;
     u_short port;
{
    struct sockaddr_in S;

    memset(&S, '\0', sizeof(S));
    S.sin_family = AF_INET;
    S.sin_port = htons(port);
    S.sin_addr = in_addr;
    if (bind(s, (struct sockaddr *) &S, sizeof(S)) == 0)
	return COMM_OK;
    debug(5, 0, "commBind: Cannot bind socket FD %d to %s:%d: %s\n",
	s,
	S.sin_addr.s_addr == INADDR_ANY ? "*" : inet_ntoa(S.sin_addr),
	port, xstrerror());
    return COMM_ERROR;
}

/* Create a socket. Default is blocking, stream (TCP) socket.  IO_TYPE
 * is OR of flags specified in comm.h. */
int comm_open(io_type, addr, port, note)
     unsigned int io_type;
     struct in_addr addr;
     u_short port;
     char *note;
{
    int new_socket;
    FD_ENTRY *conn = NULL;
    int sock_type = io_type & COMM_DGRAM ? SOCK_DGRAM : SOCK_STREAM;

    /* Create socket for accepting new connections. */
    if ((new_socket = socket(AF_INET, sock_type, 0)) < 0) {
	/* Increase the number of reserved fd's if calls to socket()
	 * are failing because the open file table is full.  This
	 * limits the number of simultaneous clients */
	switch (errno) {
	case ENFILE:
	case EMFILE:
	    debug(5, 1, "comm_open: socket failure: %s\n", xstrerror());
	    Reserve_More_FDs();
	    break;
	default:
	    debug(5, 0, "comm_open: socket failure: %s\n", xstrerror());
	}
	return (COMM_ERROR);
    }
    /* update fdstat */
    fdstat_open(new_socket, FD_SOCKET);

    conn = &fd_table[new_socket];
    memset(conn, '\0', sizeof(FD_ENTRY));
    if (note)
	fd_note(new_socket, note);
    conn->openned = 1;

    if (!(io_type & COMM_NOCLOEXEC)) {
	if (fcntl(new_socket, F_SETFD, 1) < 0) {
	    debug(5, 0, "comm_open: FD %d: set close-on-exec failed: %s\n",
		new_socket, xstrerror());
	}
    }
    if (port > 0) {
	commSetNoLinger(new_socket);
	if (do_reuse)
	    commSetReuseAddr(new_socket);
    }
    if (addr.s_addr != INADDR_NONE)
	if (commBind(new_socket, addr, port) != COMM_OK)
	    return COMM_ERROR;
    conn->local_port = port;

    if (io_type & COMM_NONBLOCKING)
	if (commSetNonBlocking(new_socket) == COMM_ERROR)
	    return COMM_ERROR;
#ifdef TCP_NODELAY
    if (sock_type == SOCK_STREAM)
	commSetTcpNoDelay(new_socket);
#endif
    conn->comm_type = io_type;
    return new_socket;
}

   /*
    * NOTE: set the listen queue to FD_SETSIZE/4 and rely on the kernel to      
    * impose an upper limit.  Solaris' listen(3n) page says it has   
    * no limit on this parameter, but sys/socket.h sets SOMAXCONN 
    * to 5.  HP-UX currently has a limit of 20.  SunOS is 5 and
    * OSF 3.0 is 8.
    */
int comm_listen(sock)
     int sock;
{
    int x;
    if ((x = listen(sock, FD_SETSIZE >> 2)) < 0) {
	debug(5, 0, "comm_listen: listen(%d, %d): %s\n",
	    FD_SETSIZE >> 2,
	    sock, xstrerror());
	return x;
    }
    return sock;
}

/* Connect SOCK to specified DEST_PORT at DEST_HOST. */
int comm_connect(sock, dest_host, dest_port)
     int sock;			/* Type of communication to use. */
     char *dest_host;		/* Server's host name. */
     u_short dest_port;		/* Server's port. */
{
    struct hostent *hp = NULL;
    static struct sockaddr_in to_addr;

    /* Set up the destination socket address for message to send to. */
    to_addr.sin_family = AF_INET;

    if ((hp = ipcache_gethostbyname(dest_host, IP_BLOCKING_LOOKUP)) == 0) {
	debug(5, 1, "comm_connect: Failure to lookup host: %s.\n", dest_host);
	return (COMM_ERROR);
    }
    xmemcpy(&to_addr.sin_addr, hp->h_addr, hp->h_length);
    to_addr.sin_port = htons(dest_port);
    return comm_connect_addr(sock, &to_addr);
}

int comm_set_fd_lifetime(fd, lifetime)
     int fd;
     int lifetime;
{
    debug(5, 3, "comm_set_fd_lifetime: FD %d lft %d\n", fd, lifetime);
    if (fd < 0 || fd > FD_SETSIZE)
	return 0;
    if (lifetime < 0)
	return fd_lifetime[fd] = -1;
    if (shutdown_pending || reread_pending) {
	/* don't increase the lifetime if something pending */
	if (fd_lifetime[fd] > -1 && (fd_lifetime[fd] - squid_curtime) < lifetime)
	    return fd_lifetime[fd];
    }
    return fd_lifetime[fd] = (int) squid_curtime + lifetime;
}

int comm_get_fd_lifetime(fd)
     int fd;
{
    if (fd < 0)
	return 0;
    return fd_lifetime[fd];
}

int comm_get_fd_timeout(fd)
     int fd;
{
    if (fd < 0)
	return 0;
    return fd_table[fd].timeout_time;
}

int comm_connect_addr(sock, address)
     int sock;
     struct sockaddr_in *address;
{
    int status = COMM_OK;
    FD_ENTRY *conn = &fd_table[sock];
    int len;
    int x;
    int lft;

    /* sanity check */
    if (ntohs(address->sin_port) == 0) {
	debug(5, 10, "comm_connect_addr: %s:%d: URL uses port 0?\n",
	    inet_ntoa(address->sin_addr), ntohs(address->sin_port));
	errno = 0;
	return COMM_ERROR;
    }
    /* Establish connection. */
    if (connect(sock, (struct sockaddr *) address, sizeof(struct sockaddr_in)) < 0)
	switch (errno) {
	case EALREADY:
	    return COMM_ERROR;
	    /* NOTREACHED */
#if EAGAIN != EWOULDBLOCK
	case EAGAIN:
#endif
	case EWOULDBLOCK:
	case EINPROGRESS:
	    status = EINPROGRESS;
	    break;
	case EISCONN:
	    status = COMM_OK;
	    break;
	case EINVAL:
	    len = sizeof(x);
	    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *) &x, &len) >= 0)
		errno = x;
	default:
	    debug(5, 1, "connect: %s:%d: %s.\n",
		inet_ntoa(address->sin_addr),
		ntohs(address->sin_port),
		xstrerror());
	    return COMM_ERROR;
	}
    /* set the lifetime for this client */
    if (status == COMM_OK) {
	lft = comm_set_fd_lifetime(sock, getClientLifetime());
	strcpy(conn->ipaddr, inet_ntoa(address->sin_addr));
	conn->remote_port = ntohs(address->sin_port);
	debug(5, 10, "comm_connect_addr: FD %d (lifetime %d): connected to %s:%d.\n",
	    sock, lft, conn->ipaddr, conn->remote_port);
    } else if (status == EINPROGRESS) {
	lft = comm_set_fd_lifetime(sock, getConnectTimeout());
	debug(5, 10, "comm_connect_addr: FD %d connection pending, lifetime %d\n",
	    sock, lft);
    }
    /* Add new socket to list of open sockets. */
    conn->sender = 1;
    return status;
}

/* Wait for an incoming connection on FD.  FD should be a socket returned
 * from comm_listen. */
int comm_accept(fd, peer, me)
     int fd;
     struct sockaddr_in *peer;
     struct sockaddr_in *me;
{
    int sock;
    struct sockaddr_in P;
    struct sockaddr_in M;
    int Slen;
    FD_ENTRY *conn = NULL;
    FD_ENTRY *listener = &fd_table[fd];

    Slen = sizeof(P);
    while ((sock = accept(fd, (struct sockaddr *) &P, &Slen)) < 0) {
	switch (errno) {
#if EAGAIN != EWOULDBLOCK
	case EAGAIN:
#endif
	case EWOULDBLOCK:
	    return COMM_NOMESSAGE;
	case EINTR:
	    break;		/* if accept interrupted, try again */
	case ENFILE:
	case EMFILE:
	    Reserve_More_FDs();
	    return COMM_ERROR;
	default:
	    debug(5, 1, "comm_accept: FD %d: accept failure: %s\n",
		fd, xstrerror());
	    return COMM_ERROR;
	}
    }

    if (peer)
	*peer = P;

    if (me) {
	Slen = sizeof(M);
	memset(&M, '\0', Slen);
	getsockname(sock, (struct sockaddr *) &M, &Slen);
	*me = M;
    }
    /* fdstat update */
    fdstat_open(sock, FD_SOCKET);
    conn = &fd_table[sock];
    conn->openned = 1;
    conn->sender = 0;		/* This is an accept, therefore receiver. */
    conn->comm_type = listener->comm_type;
    strcpy(conn->ipaddr, inet_ntoa(P.sin_addr));
    conn->remote_port = htons(P.sin_port);
    conn->local_port = htons(M.sin_port);
    commSetNonBlocking(sock);
    return sock;
}

int comm_close(fd)
     int fd;
{
    FD_ENTRY *conn = NULL;
    struct close_handler *ch = NULL;

    if (fd < 0)
	return -1;

    if (fdstat_type(fd) == FD_FILE) {
	debug(5, 0, "FD %d: Someone called comm_close() on a File\n", fd);
	fatal_dump(NULL);
    }
    conn = &fd_table[fd];

    safe_free(conn->rstate);
    safe_free(conn->wstate);

    comm_set_fd_lifetime(fd, -1);	/* invalidate the lifetime */
    debug(5, 5, "comm_close: FD %d\n", fd);
    /* update fdstat */
    fdstat_close(fd);
    /* Call close handlers */
    while ((ch = conn->close_handler)) {
	conn->close_handler = ch->next;
	ch->handler(fd, ch->data);
	safe_free(ch);
    }
    memset(conn, '\0', sizeof(FD_ENTRY));
    return close(fd);
}

/* use to clean up fdtable when socket is closed without
 * using comm_close */
int comm_cleanup_fd_entry(fd)
     int fd;
{
    FD_ENTRY *conn = &fd_table[fd];
    safe_free(conn->rstate);
    safe_free(conn->wstate);
    memset(conn, 0, sizeof(FD_ENTRY));
    return 0;
}


/* Send a udp datagram to specified PORT at HOST. */
int comm_udp_send(fd, host, port, buf, len)
     int fd;
     char *host;
     u_short port;
     char *buf;
     int len;
{
    struct hostent *hp = NULL;
    static struct sockaddr_in to_addr;
    int bytes_sent;

    /* Set up the destination socket address for message to send to. */
    to_addr.sin_family = AF_INET;

    if ((hp = ipcache_gethostbyname(host, IP_BLOCKING_LOOKUP)) == 0) {
	debug(5, 1, "comm_udp_send: gethostbyname failure: %s: %s\n",
	    host, xstrerror());
	return (COMM_ERROR);
    }
    xmemcpy(&to_addr.sin_addr, hp->h_addr, hp->h_length);
    to_addr.sin_port = htons(port);
    if ((bytes_sent = sendto(fd, buf, len, 0, (struct sockaddr *) &to_addr,
		sizeof(to_addr))) < 0) {
	debug(5, 1, "comm_udp_send: sendto failure: FD %d: %s\n",
	    fd, xstrerror());
	return COMM_ERROR;
    }
    return bytes_sent;
}

/* Send a udp datagram to specified TO_ADDR. */
int comm_udp_sendto(fd, to_addr, addr_len, buf, len)
     int fd;
     struct sockaddr_in *to_addr;
     int addr_len;
     char *buf;
     int len;
{
    int bytes_sent;

    if ((bytes_sent = sendto(fd, buf, len, 0, (struct sockaddr *) to_addr, addr_len)) < 0) {
	debug(5, 1, "comm_udp_sendto: sendto failure: FD %d: %s\n", fd, xstrerror());
	debug(5, 1, "comm_udp_sendto: --> sin_family = %d\n", to_addr->sin_family);
	debug(5, 1, "comm_udp_sendto: --> sin_port   = %d\n", htons(to_addr->sin_port));
	debug(5, 1, "comm_udp_sendto: --> sin_addr   = %s\n", inet_ntoa(to_addr->sin_addr));
	debug(5, 1, "comm_udp_sendto: --> length     = %d\n", len);
	return COMM_ERROR;
    }
    return bytes_sent;
}

int comm_udp_recv(fd, buf, size, from_addr, from_size)
     int fd;
     char *buf;
     int size;
     struct sockaddr_in *from_addr;
     int *from_size;		/* in: size of from_addr; out: size filled in. */
{
    int len = recvfrom(fd, buf, size, 0, (struct sockaddr *) from_addr,
	from_size);
    if (len < 0) {
	debug(5, 1, "comm_udp_recv: recvfrom failure: FD %d: %s\n", fd,
	    xstrerror());
	return COMM_ERROR;
    }
    return len;
}

void comm_set_stall(fd, delta)
     int fd;
     int delta;
{
    if (fd < 0)
	return;
    fd_table[fd].stall_until = squid_curtime + delta;
}

static void comm_select_incoming()
{
    fd_set read_mask;
    fd_set write_mask;
    int maxfd = 0;
    int fd = 0;
    int fds[3];
    int N = 0;
    int i = 0;
    int (*tmp) () = NULL;

    FD_ZERO(&read_mask);
    FD_ZERO(&write_mask);

    if (theHttpConnection >= 0 && fdstat_are_n_free_fd(RESERVED_FD))
	fds[N++] = theHttpConnection;
    if (theInIcpConnection >= 0)
	fds[N++] = theInIcpConnection;
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
    if (select(maxfd, &read_mask, &write_mask, NULL, &zero_tv) > 0) {
	for (i = 0; i < N; i++) {
	    fd = fds[i];
	    if (FD_ISSET(fd, &read_mask)) {
		tmp = fd_table[fd].read_handler;
		fd_table[fd].read_handler = 0;
		tmp(fd, fd_table[fd].read_data);
	    }
	    if (FD_ISSET(fd, &write_mask)) {
		tmp = fd_table[fd].write_handler;
		fd_table[fd].write_handler = 0;
		tmp(fd, fd_table[fd].write_data);
	    }
	}
    }
}


/* Select on all sockets; call handlers for those that are ready. */
int comm_select(sec, failtime)
     time_t sec;
     time_t failtime;
{
    fd_set exceptfds;
    fd_set readfds;
    fd_set writefds;
    int (*tmp) () = NULL;
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
	if (0 < failtime && failtime < squid_curtime)
	    break;

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);

	if (shutdown_pending || reread_pending) {
	    serverConnectionsClose();
	    ftpServerClose();
	    ipcacheShutdownServers();
	    setSocketShutdownLifetimes();
	}
	nfds = 0;
	maxfd = fdstat_biggest_fd() + 1;
	for (i = 0; i < maxfd; i++) {
#if USE_ASYNC_IO
           /* Using async IO for disk handle, so don't select on them */
           if (fdstat_type(i) == FD_FILE) 
               continue;
#endif
	    /* Check each open socket for a handler. */
	    if (fd_table[i].read_handler && fd_table[i].stall_until <= squid_curtime) {
		nfds++;
		FD_SET(i, &readfds);
	    }
	    if (fd_table[i].write_handler) {
		nfds++;
		FD_SET(i, &writefds);
	    }
	    if (fd_table[i].except_handler) {
		nfds++;
		FD_SET(i, &exceptfds);
	    }
	}
	if (!fdstat_are_n_free_fd(RESERVED_FD)) {
	    FD_CLR(theHttpConnection, &readfds);
	}
	if (shutdown_pending || reread_pending)
	    debug(5, 2, "comm_select: Still waiting on %d FDs\n", nfds);
	if (nfds == 0)
	    return COMM_SHUTDOWN;
	if (shutdown_pending || reread_pending)
	    debug(5, 2, "comm_select: Still waiting on %d FDs\n", nfds);
	while (1) {
#if USE_ASYNC_IO
           /* Another CPU vs latency tradeoff for async IO */
           poll_time.tv_sec = 0;
           poll_time.tv_usec = 250000;
#else      
	    poll_time.tv_sec = sec > 1 ? 1 : 0;
	    poll_time.tv_usec = 0;
#endif
	    num = select(maxfd, &readfds, &writefds, &exceptfds, &poll_time);
	    if (num >= 0)
		break;
	    if (errno == EINTR)
		break;
	    debug(5, 0, "comm_select: select failure: %s\n",
		xstrerror());
	    examine_select(&readfds, &writefds, &exceptfds);
	    return COMM_ERROR;
	    /* NOTREACHED */
	}
#if USE_ASYNC_IO
       aioExamine();          /* See if any IO completed */
#endif
	if (num < 0)
	    continue;
	debug(5, num ? 5 : 8, "comm_select: %d sockets ready at %d\n",
	    num, (int) squid_curtime);

	/* Check lifetime and timeout handlers ONCE each second.
	 * Replaces brain-dead check every time through the loop! */
	if (squid_curtime > last_timeout) {
	    last_timeout = squid_curtime;
	    checkTimeouts();
	    checkLifetimes();
	}
	if (num == 0)
	    continue;

	/* scan each socket but the accept socket. Poll this 
	 * more frequently to minimiize losses due to the 5 connect 
	 * limit in SunOS */

	maxfd = fdstat_biggest_fd() + 1;
	for (fd = 0; fd < maxfd && num > 0; fd++) {

	    if (!(FD_ISSET(fd, &readfds) || FD_ISSET(fd, &writefds) ||
		    FD_ISSET(fd, &exceptfds)))
		continue;
	    else
		--num;

	    /*
	     * Admit more connections quickly until we hit the hard limit.
	     * Don't forget to keep the UDP acks coming and going.
	     */
	    comm_select_incoming();

	    if ((fd == theInIcpConnection) || (fd == theHttpConnection))
		continue;

	    if (FD_ISSET(fd, &readfds)) {
		debug(5, 6, "comm_select: FD %d ready for reading\n", fd);
		if (fd_table[fd].read_handler) {
		    tmp = fd_table[fd].read_handler;
		    fd_table[fd].read_handler = 0;
		    debug(5, 10, "calling read handler %p(%d,%p)\n",
			tmp, fd, fd_table[fd].read_data);
		    tmp(fd, fd_table[fd].read_data);
		}
	    }
	    if (FD_ISSET(fd, &writefds)) {
		debug(5, 5, "comm_select: FD %d ready for writing\n", fd);
		if (fd_table[fd].write_handler) {
		    tmp = fd_table[fd].write_handler;
		    fd_table[fd].write_handler = 0;
		    debug(5, 10, "calling write handler %p(%d,%p)\n",
			tmp, fd, fd_table[fd].write_data);
		    tmp(fd, fd_table[fd].write_data);
		}
	    }
	    if (FD_ISSET(fd, &exceptfds)) {
		debug(5, 5, "comm_select: FD %d has an exception\n", fd);
		if (fd_table[fd].except_handler) {
		    tmp = fd_table[fd].except_handler;
		    fd_table[fd].except_handler = 0;
		    debug(5, 10, "calling except handler %p(%d,%p)\n",
			tmp, fd, fd_table[fd].except_data);
		    tmp(fd, fd_table[fd].except_data);
		}
	    }
	}
	return COMM_OK;
    } while (timeout > getCurrentTime());

    debug(5, 8, "comm_select: time out: %d.\n", squid_curtime);
    return COMM_TIMEOUT;
}

void comm_set_select_handler(fd, type, handler, client_data)
     int fd;
     unsigned int type;
     int (*handler) ();
     void *client_data;
{
    comm_set_select_handler_plus_timeout(fd, type, handler, client_data, 0);
}

void comm_set_select_handler_plus_timeout(fd, type, handler, client_data, timeout)
     int fd;
     unsigned int type;
     int (*handler) ();
     void *client_data;
     time_t timeout;
{
    if (type & COMM_SELECT_TIMEOUT) {
	fd_table[fd].timeout_time = (getCurrentTime() + timeout);
	fd_table[fd].timeout_delta = timeout;
	fd_table[fd].timeout_handler = handler;
	fd_table[fd].timeout_data = client_data;
	if ((timeout <= 0) && handler) {
	    debug(5, 2, "comm_set_select_handler_plus_timeout: Zero timeout doesn't make sense\n");
	}
    }
    if (type & COMM_SELECT_READ) {
	fd_table[fd].read_handler = handler;
	fd_table[fd].read_data = client_data;
    }
    if (type & COMM_SELECT_WRITE) {
	fd_table[fd].write_handler = handler;
	fd_table[fd].write_data = client_data;
    }
    if (type & COMM_SELECT_EXCEPT) {
	fd_table[fd].except_handler = handler;
	fd_table[fd].except_data = client_data;
    }
    if (type & COMM_SELECT_LIFETIME) {
	fd_table[fd].lifetime_handler = handler;
	fd_table[fd].lifetime_data = client_data;
    }
}

int comm_get_select_handler(fd, type, handler_ptr, client_data_ptr)
     int fd;
     unsigned int type;
     int (**handler_ptr) ();
     void **client_data_ptr;
{
    if (type & COMM_SELECT_TIMEOUT) {
	*handler_ptr = fd_table[fd].timeout_handler;
	*client_data_ptr = fd_table[fd].timeout_data;
    }
    if (type & COMM_SELECT_READ) {
	*handler_ptr = fd_table[fd].read_handler;
	*client_data_ptr = fd_table[fd].read_data;
    }
    if (type & COMM_SELECT_WRITE) {
	*handler_ptr = fd_table[fd].write_handler;
	*client_data_ptr = fd_table[fd].write_data;
    }
    if (type & COMM_SELECT_EXCEPT) {
	*handler_ptr = fd_table[fd].except_handler;
	*client_data_ptr = fd_table[fd].except_data;
    }
    if (type & COMM_SELECT_LIFETIME) {
	*handler_ptr = fd_table[fd].lifetime_handler;
	*client_data_ptr = fd_table[fd].lifetime_data;
    }
    return 0;			/* XXX What is meaningful? */
}

void comm_add_close_handler(fd, handler, data)
     int fd;
     int (*handler) ();
     void *data;
{
    struct close_handler *new = xmalloc(sizeof(*new));

    debug(5, 5, "comm_add_close_handler: fd=%d handler=0x%p data=0x%p\n", fd, handler, data);

    new->handler = handler;
    new->data = data;
    new->next = fd_table[fd].close_handler;
    fd_table[fd].close_handler = new;
}

void comm_remove_close_handler(fd, handler, data)
     int fd;
     int (*handler) ();
     void *data;
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

static void commSetNoLinger(fd)
     int fd;
{
    struct linger L;
    L.l_onoff = 0;		/* off */
    L.l_linger = 0;
    debug(5, 10, "commSetNoLinger: turning off SO_LINGER on FD %d\n", fd);
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &L, sizeof(L)) < 0)
	debug(5, 0, "commSetNoLinger: FD %d: %s\n", fd, xstrerror());
}

static void commSetReuseAddr(fd)
     int fd;
{
    int on = 1;
    debug(5, 10, "commSetReuseAddr: turning on SO_REUSEADDR on FD %d\n", fd);
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0)
	debug(5, 1, "commSetReuseAddr: FD %d: %s\n", fd, xstrerror());
}

#ifdef TCP_NODELAY
static void commSetTcpNoDelay(fd)
     int fd;
{
    int on = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof(on)) < 0)
	debug(5, 1, "commSetTcpNoDelay: FD %d: %s\n", fd, xstrerror());
}
#endif

int commSetNonBlocking(fd)
     int fd;
{
#if defined(O_NONBLOCK) && !defined(_SQUID_SUNOS_) && !defined(_SQUID_SOLARIS_)
    if (fcntl(fd, F_SETFL, O_NONBLOCK)) {
	debug(5, 0, "comm_open: FD %d: error setting O_NONBLOCK: %s\n",
	    fd, xstrerror());
	return COMM_ERROR;
    }
#else
    if (fcntl(fd, F_SETFL, O_NDELAY)) {
	debug(5, 0, "comm_open: FD %d: error setting O_NDELAY: %s\n",
	    fd, xstrerror());
	return COMM_ERROR;
    }
#endif
    return 0;
}

char **getAddressList(name)
     char *name;
{
    struct hostent *hp = NULL;
    if (name == NULL)
	return NULL;
    if ((hp = ipcache_gethostbyname(name, IP_BLOCKING_LOOKUP)))
	return hp->h_addr_list;
    debug(5, 0, "getAddress: gethostbyname failure: %s: %s\n",
	name, xstrerror());
    return NULL;
}

struct in_addr *getAddress(name)
     char *name;
{
    static struct in_addr first;
    char **list = NULL;
    if (name == NULL)
	return NULL;
    if ((list = getAddressList(name))) {
	xmemcpy(&first.s_addr, *list, 4);
	return (&first);
    }
    debug(5, 0, "getAddress: gethostbyname failure: %s: %s\n",
	name, xstrerror());
    return NULL;
}

/*
 *  the fd_lifetime is used as a hardlimit to timeout dead sockets.
 *  The basic problem is that many WWW clients are abusive and
 *  it results in squid having lots of CLOSE_WAIT states.  Until
 *  we can find a better solution, we give all asciiPort or
 *  squid initiated clients a maximum lifetime.
 */
int comm_init()
{
    int i;

    fd_table = xcalloc(FD_SETSIZE, sizeof(FD_ENTRY));
    meta_data.misc += FD_SETSIZE * sizeof(FD_ENTRY);
    /* Keep a few file descriptors free so that we don't run out of FD's
     * after accepting a client but before it opens a socket or a file.
     * Since FD_SETSIZE can be as high as several thousand, don't waste them */
    RESERVED_FD = min(100, FD_SETSIZE / 4);
    /* hardwired lifetimes */
    fd_lifetime = xmalloc(sizeof(int) * FD_SETSIZE);
    for (i = 0; i < FD_SETSIZE; i++)
	comm_set_fd_lifetime(i, -1);	/* denotes invalid */
    meta_data.misc += FD_SETSIZE * sizeof(int);
    zero_tv.tv_sec = 0;
    zero_tv.tv_usec = 0;
    any_addr.s_addr = inet_addr("0.0.0.0");
    return 0;
}


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
static int examine_select(readfds, writefds, exceptfds)
     fd_set *readfds, *writefds, *exceptfds;
{
    int fd = 0;
    fd_set read_x;
    fd_set write_x;
    fd_set except_x;
    int num;
    struct timeval tv;
    struct close_handler *ch = NULL;
    struct close_handler *next = NULL;
    FD_ENTRY *f = NULL;

    debug(5, 0, "examine_select: Examining open file descriptors...\n");
    for (fd = 0; fd < FD_SETSIZE; fd++) {
	FD_ZERO(&read_x);
	FD_ZERO(&write_x);
	FD_ZERO(&except_x);
	tv.tv_sec = tv.tv_usec = 0;
	if ((FD_ISSET(fd, readfds)) ||
	    (FD_ISSET(fd, writefds)) ||
	    (FD_ISSET(fd, exceptfds))) {
	    FD_SET(fd, &read_x);
	    num = select(FD_SETSIZE, &read_x, &read_x, &read_x, &tv);
	    if (num < 0) {
		f = &fd_table[fd];
		debug(5, 0, "WARNING: FD %d has handlers, but it's invalid.\n", fd);
		debug(5, 0, "lifetm:%p tmout:%p read:%p write:%p expt:%p\n",
		    f->lifetime_handler,
		    f->timeout_handler,
		    f->read_handler,
		    f->write_handler,
		    f->except_handler);
		for (ch = f->close_handler; ch; ch = ch->next)
		    debug(5, 0, " close handler: %p\n", ch->handler);
		if (f->close_handler) {
		    for (ch = f->close_handler; ch; ch = next) {
			next = ch->next;
			ch->handler(fd, ch->data);
			safe_free(ch);
		    }
		} else if (f->lifetime_handler) {
		    debug(5, 0, "examine_select: Calling Lifetime Handler\n");
		    f->lifetime_handler(fd, f->lifetime_data);
		} else if (f->timeout_handler) {
		    debug(5, 0, "examine_select: Calling Timeout Handler\n");
		    f->timeout_handler(fd, f->timeout_data);
		}
		f->close_handler = 0;
		f->lifetime_handler = 0;
		f->timeout_handler = 0;
		f->read_handler = 0;
		f->write_handler = 0;
		f->except_handler = 0;
		FD_CLR(fd, readfds);
		FD_CLR(fd, writefds);
		FD_CLR(fd, exceptfds);
	    }
	}
    }
    return 0;
}

char *fd_note(fd, s)
     int fd;
     char *s;
{
    if (s == NULL)
	return (fd_table[fd].ascii_note);
    strncpy(fd_table[fd].ascii_note, s, FD_ASCII_NOTE_SZ - 1);
    return (NULL);
}

static void checkTimeouts()
{
    int fd;
    int (*tmp) () = NULL;
    FD_ENTRY *f = NULL;

    /* scan for timeout */
    for (fd = 0; fd < FD_SETSIZE; ++fd) {
	f = &fd_table[fd];
	if ((f->timeout_handler) &&
	    (f->timeout_time <= squid_curtime)) {
	    tmp = f->timeout_handler;
	    debug(5, 5, "comm_select: timeout on socket %d at %d\n",
		fd, squid_curtime);
	    f->timeout_handler = 0;
	    tmp(fd, f->timeout_data);
	}
    }
}

static void checkLifetimes()
{
    int fd;
    time_t lft;

    int (*func) () = NULL;

    for (fd = 0; fd < FD_SETSIZE; fd++) {
	if ((lft = comm_get_fd_lifetime(fd)) == -1)
	    continue;
	if (lft > squid_curtime)
	    continue;
	debug(5, 5, "checkLifetimes: FD %d Expired\n", fd);
	if ((func = fd_table[fd].lifetime_handler)) {
	    debug(5, 5, "checkLifetimes: FD %d: Calling lifetime handler\n", fd);
	    func(fd, fd_table[fd].lifetime_data);
	    fd_table[fd].lifetime_handler = NULL;
	} else if ((func = fd_table[fd].read_handler)) {
	    debug(5, 5, "checkLifetimes: FD %d: Calling read handler\n", fd);
	    func(fd, fd_table[fd].read_data);
	    fd_table[fd].read_handler = NULL;
	} else if ((func = fd_table[fd].read_handler)) {
	    debug(5, 5, "checkLifetimes: FD %d: Calling read handler\n", fd);
	    func(fd, fd_table[fd].read_data);
	    fd_table[fd].read_handler = NULL;
	} else if ((func = fd_table[fd].write_handler)) {
	    debug(5, 5, "checkLifetimes: FD %d: Calling write handler\n", fd);
	    func(fd, fd_table[fd].write_data);
	    fd_table[fd].write_handler = NULL;
	} else {
	    debug(5, 5, "checkLifetimes: FD %d: No handlers, calling comm_close()\n", fd);
	    comm_close(fd);
	    comm_cleanup_fd_entry(fd);
	}
	if (fd_table[fd].openned) {
	    /* still opened */
	    debug(5, 5, "checkLifetimes: FD %d: Forcing comm_close()\n", fd);
	    comm_close(fd);
	    comm_cleanup_fd_entry(fd);
	}
    }
}

/*
 * Reserve_More_FDs() called when acceopt(), open(), or socket is failing
 */
static void Reserve_More_FDs()
{
    if (RESERVED_FD < FD_SETSIZE - 64) {
	RESERVED_FD = RESERVED_FD + 1;
    } else if (RESERVED_FD == FD_SETSIZE - 64) {
	RESERVED_FD = RESERVED_FD + 1;
	debug(5, 0, "Don't you have a tiny open-file table size of %d\n",
	    FD_SETSIZE - RESERVED_FD);
    }
}

int fd_of_first_client(e)
     StoreEntry *e;
{
    int fd;

    fd = e->mem_obj->fd_of_first_client;

    if (fd > 0) {
	if (e == fd_table[fd].store_entry) {
	    return (fd);
	}
    }
    return (-1);
}

/* Read from FD. */
static int commHandleRead(fd, state)
     int fd;
     RWStateData *state;
{
    int len;

    len = read(fd, state->buf + state->offset, state->size - state->offset);
    debug(5, 5, "commHandleRead: FD %d: read %d bytes\n", fd, len);

    if (len <= 0) {
	switch (errno) {
#if EAGAIN != EWOULDBLOCK
	case EAGAIN:
#endif
	case EWOULDBLOCK:
	    /* reschedule self */
	    comm_set_select_handler(fd,
		COMM_SELECT_READ,
		(PF) commHandleRead,
		state);
	    return COMM_OK;
	default:
	    /* Len == 0 means connection closed; otherwise would not have been
	     * called by comm_select(). */
	    debug(5, len == 0 ? 2 : 1, "commHandleRead: FD %d: read failure: %s\n",
		fd, len == 0 ? "connection closed" : xstrerror());
	    fd_table[fd].rstate = NULL;		/* The handler may issue a new read */
	    /* Notify caller that we failed */
	    state->handler(fd,
		state->buf,
		state->offset,
		COMM_ERROR,
		state->handler_data);
	    safe_free(state);
	    return COMM_ERROR;
	}
    }
    state->offset += len;

    /* Call handler if we have read enough */
    if (state->offset >= state->size || state->handle_immed) {
	fd_table[fd].rstate = NULL;	/* The handler may issue a new read */
	state->handler(fd,
	    state->buf,
	    state->offset,
	    COMM_OK,
	    state->handler_data);
	safe_free(state);
    } else {
	/* Reschedule until we are done */
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) commHandleRead,
	    state);
    }
    return COMM_OK;
}

/* Select for reading on FD, until SIZE bytes are received.  Call
 * HANDLER when complete. */
void comm_read(fd, buf, size, timeout, immed, handler, handler_data)
     int fd;
     char *buf;
     int size;
     int timeout;
     int immed;			/* Call handler immediately when data available */
     rw_complete_handler *handler;
     void *handler_data;
{
    RWStateData *state = NULL;

    debug(5, 5, "comm_read: FD %d: sz %d: tout %d: hndl %p: data %p.\n",
	fd, size, timeout, handler, handler_data);

    if (fd_table[fd].rstate) {
	debug(5, 1, "comm_read: WARNING! FD %d: A comm_read is already active.\n", fd);
	safe_free(fd_table[fd].rstate);
    }
    state = xcalloc(1, sizeof(RWStateData));
    fd_table[fd].rstate = state;
    state->buf = buf;
    state->size = size;
    state->offset = 0;
    state->handler = handler;
    state->timeout = timeout;
    state->handle_immed = immed;
    state->time = squid_curtime;
    state->handler_data = handler_data;
    comm_set_select_handler(fd,
	COMM_SELECT_READ,
	(PF) commHandleRead,
	state);
}

/* Write to FD. */
static void commHandleWrite(fd, state)
     int fd;
     RWStateData *state;
{
    int len = 0;
    int nleft;

    debug(5, 5, "commHandleWrite: FD %d: state=%p, off %d, sz %d.\n",
	fd, state, state->offset, state->size);

    nleft = state->size - state->offset;
    len = write(fd, state->buf + state->offset, nleft);

    if (len == 0) {
	/* Note we even call write if nleft == 0 */
	/* We're done */
	if (nleft != 0)
	    debug(5, 2, "commHandleWrite: FD %d: write failure: connection closed with %d bytes remaining.\n", fd, nleft);
	fd_table[fd].wstate = NULL;
	if (state->handler)
	    state->handler(fd,
		state->buf,
		state->offset,
		nleft ? COMM_ERROR : COMM_OK,
		state->handler_data);
	else
	    xfree(state->buf);
	safe_free(state);
	return;
    } else if (len < 0) {
	/* An error */
	if (errno == EWOULDBLOCK || errno == EAGAIN) {
	    /* XXX: Re-install the handler rather than giving up. I hope
	     * this doesn't freeze this socket due to some random OS bug
	     * returning EWOULDBLOCK indefinitely.  Ought to maintain a
	     * retry count in state? */
	    debug(5, 10, "commHandleWrite: FD %d: write failure: %s.\n",
		fd, xstrerror());
	    comm_set_select_handler(fd,
		COMM_SELECT_WRITE,
		(PF) commHandleWrite,
		state);
	    return;
	}
	debug(5, 2, "commHandleWrite: FD %d: write failure: %s.\n",
	    fd, xstrerror());
	/* Notify caller that we failed */
	fd_table[fd].wstate = NULL;
	if (state->handler)
	    state->handler(fd,
		state->buf,
		state->offset,
		COMM_ERROR,
		state->handler_data);
	else
	    xfree(state->buf);
	safe_free(state);
	return;
    } else {
	/* A successful write, continue */
	state->offset += len;
	if (state->offset < state->size) {
	    /* Not done, reinstall the write handler and write some more */
	    comm_set_select_handler(fd,
		COMM_SELECT_WRITE,
		(PF) commHandleWrite,
		state);
	    return;
	}
	fd_table[fd].wstate = NULL;
	/* Notify caller that the write is complete */
	if (state->handler)
	    state->handler(fd,
		state->buf,
		state->offset,
		COMM_OK,
		state->handler_data);
	else
	    xfree(state->buf);
	safe_free(state);
    }
}



/* Select for Writing on FD, until SIZE bytes are sent.  Call
 * * HANDLER when complete. */
void comm_write(fd, buf, size, timeout, handler, handler_data)
     int fd;
     char *buf;
     int size;
     int timeout;
     rw_complete_handler *handler;
     void *handler_data;
{
    RWStateData *state = NULL;

    debug(5, 5, "comm_write: FD %d: sz %d: tout %d: hndl %p: data %p.\n",
	fd, size, timeout, handler, handler_data);

    if (fd_table[fd].wstate) {
	debug(5, 1, "comm_write: WARNING! FD %d: A comm_write is already active.\n", fd);
	safe_free(fd_table[fd].wstate);
    }
    state = xcalloc(1, sizeof(RWStateData));
    state->buf = buf;
    state->size = size;
    state->offset = 0;
    state->handler = handler;
    state->timeout = timeout;
    state->time = squid_curtime;
    state->handler_data = handler_data;
    comm_set_select_handler(fd,
	COMM_SELECT_WRITE,
	(PF) commHandleWrite,
	fd_table[fd].wstate = state);
}
