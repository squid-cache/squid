
/* $Id: comm.cc,v 1.28 1996/04/17 17:40:15 wessels Exp $ */

/* DEBUG: Section 5             comm: socket level functions */

#include "squid.h"


/* Block processing new client requests (accepts on ascii port) when we start
 * running shy of free file descriptors.  For example, under SunOS, we'll keep
 * 64 file descriptors free for disk-i/o and connections to remote servers */

int RESERVED_FD = 64;

#define min(x,y) ((x)<(y)? (x) : (y))
#define max(a,b) ((a)>(b)? (a) : (b))


/* GLOBAL */
FD_ENTRY *fd_table = NULL;	/* also used in disk.c */

/* STATIC */
static int *fd_lifetime = NULL;
static void checkTimeouts _PARAMS((void));
static void checkLifetimes _PARAMS((void));
static void Reserve_More_FDs _PARAMS((void));
static int commSetReuseAddr _PARAMS((int));
static int examine_select _PARAMS((fd_set *, fd_set *, fd_set *));
static int commSetNoLinger _PARAMS((int));
static struct timeval zero_tv;
static void comm_select_incoming _PARAMS((void));

/* Return the local port associated with fd. */
int comm_port(fd)
     int fd;
{
    struct sockaddr_in addr;
    int addr_len = 0;

    if (fd_table[fd].port)
	return fd_table[fd].port;

    /* If the fd is closed already, just return */
    if (!fd_table[fd].openned) {
	debug(5, 0, "comm_port: FD %d has been closed.\n", fd);
	return (COMM_ERROR);
    }
    addr_len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *) &addr, &addr_len)) {
	debug(5, 1, "comm_port: Failed to retrieve TCP/UDP port number for socket: FD %d: %s\n", fd, xstrerror());
	return (COMM_ERROR);
    }
    debug(5, 6, "comm_port: FD %d: sockaddr %u.\n", fd, addr.sin_addr.s_addr);
    fd_table[fd].port = ntohs(addr.sin_port);

    return fd_table[fd].port;
}

static int do_bind(s, host, port)
     int s;
     char *host;
     int port;
{
    struct sockaddr_in S;
    struct in_addr *addr = NULL;

    addr = getAddress(host);
    if (addr == (struct in_addr *) NULL) {
	debug(5, 0, "do_bind: Unknown host: %s\n", host);
	return COMM_ERROR;
    }
    memset(&S, '\0', sizeof(S));
    S.sin_family = AF_INET;
    S.sin_port = htons(port);
    S.sin_addr = *addr;

    if (bind(s, (struct sockaddr *) &S, sizeof(S)) == 0)
	return COMM_OK;

    debug(5, 0, "do_bind: Cannot bind socket FD %d to %s:%d: %s\n",
	s,
	S.sin_addr.s_addr == htonl(INADDR_ANY) ? "*" : inet_ntoa(S.sin_addr),
	port, xstrerror());
    return COMM_ERROR;
}

/* Create a socket. Default is blocking, stream (TCP) socket.  IO_TYPE
 * is OR of flags specified in comm.h. */
int comm_open(io_type, port, handler, note)
     unsigned int io_type;
     int port;
     int (*handler) ();		/* Interrupt handler. */
     char *note;
{
    int new_socket;
    FD_ENTRY *conn = NULL;
    int sock_type = io_type & COMM_DGRAM ? SOCK_DGRAM : SOCK_STREAM;
    wordlist *p = NULL;

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
    fdstat_open(new_socket, Socket);

    conn = &fd_table[new_socket];
    memset(conn, '\0', sizeof(FD_ENTRY));
    fd_note(new_socket, note);
    conn->openned = 1;

    if (fcntl(new_socket, F_SETFD, 1) < 0) {
	debug(5, 0, "comm_open: FD %d: failed to set close-on-exec flag: %s\n",
	    new_socket, xstrerror());
    }
    if (port > 0) {
	if (commSetNoLinger(new_socket) < 0) {
	    debug(5, 0, "comm_open: failed to turn off SO_LINGER: %s\n",
		xstrerror());
	}
	if (do_reuse) {
	    commSetReuseAddr(new_socket);
	}
    }
    if (port) {
	for (p = getBindAddrList(); p; p = p->next) {
	    if (do_bind(new_socket, p->key, port) == COMM_OK)
		break;
	    if (p->next == (wordlist *) NULL)
		return COMM_ERROR;
	}
    }
    conn->port = port;

    if (io_type & COMM_NONBLOCKING) {
	/*
	 * Set up the flag NOT to have the socket to wait for message from
	 * network forever, but to return -1 when no message is coming in.
	 */
#if defined(O_NONBLOCK) && !defined(_SQUID_SUNOS_) && !defined(_SQUID_SOLARIS_)
	if (fcntl(new_socket, F_SETFL, O_NONBLOCK)) {
	    debug(5, 0, "comm_open: FD %d: Failure to set O_NONBLOCK: %s\n",
		new_socket, xstrerror());
	    return (COMM_ERROR);
	}
#else
	if (fcntl(new_socket, F_SETFL, O_NDELAY)) {
	    debug(5, 0, "comm_open: FD %d: Failure to set O_NDELAY: %s\n",
		new_socket, xstrerror());
	    return (COMM_ERROR);
	}
#endif /* O_NONBLOCK */
    }
    conn->comm_type = io_type;
    return new_socket;
}

   /*
    * NOTE: set the listen queue to 50 and rely on the kernel to      
    * impose an upper limit.  Solaris' listen(3n) page says it has   
    * no limit on this parameter, but sys/socket.h sets SOMAXCONN 
    * to 5.  HP-UX currently has a limit of 20.  SunOS is 5 and
    * OSF 3.0 is 8.
    */
int comm_listen(sock)
     int sock;
{
    int x;
    if ((x = listen(sock, 50)) < 0) {
	debug(5, 0, "comm_listen: listen(%d, 50): %s\n",
	    sock, xstrerror());
	return x;
    }
    return sock;
}


/* Connect SOCK to specified DEST_PORT at DEST_HOST. */
int comm_connect(sock, dest_host, dest_port)
     int sock;			/* Type of communication to use. */
     char *dest_host;		/* Server's host name. */
     int dest_port;		/* Server's port. */
{
    struct hostent *hp = NULL;
    static struct sockaddr_in to_addr;

    /* Set up the destination socket address for message to send to. */
    to_addr.sin_family = AF_INET;

    if ((hp = ipcache_gethostbyname(dest_host)) == 0) {
	debug(5, 1, "comm_connect: Failure to lookup host: %s.\n", dest_host);
	return (COMM_ERROR);
    }
    memcpy(&to_addr.sin_addr, hp->h_addr, hp->h_length);
    to_addr.sin_port = htons(dest_port);
    return comm_connect_addr(sock, &to_addr);
}

int comm_set_fd_lifetime(fd, lifetime)
     int fd;
     int lifetime;
{
    if (fd < 0 || fd > getMaxFD())
	return 0;
    if (lifetime < 0)
	return fd_lifetime[fd] = -1;
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
	    debug(5, 1, "comm_connect_addr: %s:%d: socket failure: %s.\n",
		inet_ntoa(address->sin_addr),
		ntohs(address->sin_port),
		xstrerror());
	    return COMM_ERROR;
	}
    /* set the lifetime for this client */
    if (status == COMM_OK) {
	lft = comm_set_fd_lifetime(sock, getClientLifetime());
	strcpy(conn->ipaddr, inet_ntoa(address->sin_addr));
	conn->port = ntohs(address->sin_port);
	debug(5, 10, "comm_connect_addr: FD %d (lifetime %d): connected to %s:%d.\n",
	    sock, lft, conn->ipaddr, conn->port);
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
    fdstat_open(sock, Socket);
    conn = &fd_table[sock];
    conn->openned = 1;
    conn->sender = 0;		/* This is an accept, therefore receiver. */
    conn->comm_type = listener->comm_type;
    strcpy(conn->ipaddr, inet_ntoa(P.sin_addr));

    commSetNonBlocking(sock);

    return sock;
}

int comm_close(fd)
     int fd;
{
    FD_ENTRY *conn = NULL;

    if (fd < 0)
	return -1;

    if (fdstat_type(fd) == File) {
	debug(5, 0, "FD %d: Someone called comm_close() on a File\n", fd);
	fatal_dump(NULL);
    }
    conn = &fd_table[fd];

    comm_set_fd_lifetime(fd, -1);	/* invalidate the lifetime */
    debug(5, 10, "comm_close: FD %d\n", fd);
    /* update fdstat */
    fdstat_close(fd);
    if (conn->close_handler)
	conn->close_handler(fd, conn->close_data);
    memset(conn, '\0', sizeof(FD_ENTRY));
    return close(fd);
}

/* use to clean up fdtable when socket is closed without
 * using comm_close */
int comm_cleanup_fd_entry(fd)
     int fd;
{
    FD_ENTRY *conn = &fd_table[fd];

    memset(conn, 0, sizeof(FD_ENTRY));
    return 0;
}


/* Send a udp datagram to specified PORT at HOST. */
int comm_udp_send(fd, host, port, buf, len)
     int fd;
     char *host;
     int port;
     char *buf;
     int len;
{
    struct hostent *hp = NULL;
    static struct sockaddr_in to_addr;
    int bytes_sent;

    /* Set up the destination socket address for message to send to. */
    to_addr.sin_family = AF_INET;

    if ((hp = ipcache_gethostbyname(host)) == 0) {
	debug(5, 1, "comm_udp_send: gethostbyname failure: %s: %s\n",
	    host, xstrerror());
	return (COMM_ERROR);
    }
    memcpy(&to_addr.sin_addr, hp->h_addr, hp->h_length);
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

    if (theAsciiConnection >= 0 && fdstat_are_n_free_fd(RESERVED_FD))
	fds[N++] = theAsciiConnection;
    if (theUdpConnection >= 0)
	fds[N++] = theUdpConnection;
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

    while (timeout > getCurrentTime()) {
	if (0 < failtime && failtime < squid_curtime)
	    break;

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);

	nfds = 0;
	maxfd = fdstat_biggest_fd() + 1;
	for (i = 0; i < maxfd; i++) {
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
	    FD_CLR(theAsciiConnection, &readfds);
	}
	if (nfds == 0)
	    return COMM_SHUTDOWN;
	while (1) {
	    poll_time.tv_sec = 1;
	    poll_time.tv_usec = 0;
	    num = select(maxfd, &readfds, &writefds, &exceptfds, &poll_time);
	    if (num >= 0)
		break;
	    /* break on interrupt so outer loop will reset FD_SET's */
	    if (errno == EINTR)
		break;
	    debug(5, 0, "comm_select: select failure: %s (errno %d).\n",
		xstrerror(), errno);
	    examine_select(&readfds, &writefds, &exceptfds);
	    return COMM_ERROR;
	}
	if (num < 0)
	    continue;

	debug(5, num ? 5 : 8, "comm_select: %d sockets ready at %d\n",
	    num, squid_curtime);

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

	    if ((fd == theUdpConnection) || (fd == theAsciiConnection))
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
    }

    debug(5, 8, "comm_select: time out: %d.\n", squid_curtime);
    return COMM_TIMEOUT;
}


/* Select on fd to see if any io pending. */
int comm_pending(fd, sec, usec)
     int fd;
     long sec, usec;
{
    fd_set readfds;
    int num;
    struct timeval timeout;

    /* Find a fd ready for reading. */
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    while (1) {
	timeout.tv_sec = (time_t) sec;
	timeout.tv_usec = (time_t) usec;
	num = select(FD_SETSIZE, &readfds, NULL, NULL, &timeout);
	if (num >= 0)
	    break;
	switch (errno) {
#if EAGAIN != EWOULDBLOCK
	case EAGAIN:
#endif
	case EWOULDBLOCK:
	    return COMM_NOMESSAGE;
	case EINTR:
	    break;		/* if select interrupted, try again */
	default:
	    debug(5, 1, "comm_pending: select failure: %s\n", xstrerror());
	    return COMM_ERROR;
	}
    }

    debug(5, 5, "comm_pending: %d sockets ready for reading\n", num);

    if (num && FD_ISSET(fd, &readfds)) {
	return COMM_OK;
    }
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
    if (type & COMM_SELECT_CLOSE) {
	fd_table[fd].close_handler = handler;
	fd_table[fd].close_data = client_data;
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


static int commSetNoLinger(fd)
     int fd;
{
    struct linger L;

    L.l_onoff = 0;		/* off */
    L.l_linger = 0;

    debug(5, 10, "commSetNoLinger: turning off SO_LINGER on FD %d\n", fd);
    return setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &L, sizeof(L));
}

static int commSetReuseAddr(fd)
     int fd;
{
    int on = 1;
    int rc;

    debug(5, 10, "commSetReuseAddr: turning on SO_REUSEADDR on FD %d\n", fd);
    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));
    if (rc < 0)
	debug(5, 1, "commSetReuseAddr: FD=%d: %s\n", fd, xstrerror());
    return rc;
}

int commSetNonBlocking(fd)
     int fd;
{
    debug(5, 10, "commSetNonBlocking: setting FD %d to non-blocking i/o.\n",
	fd);
    /*
     * Set up the flag NOT to have the socket to wait for message from
     * network forever, but to return -1 when no message is coming in.
     */

#if defined(O_NONBLOCK) && !defined(_SQUID_SUNOS_) && !defined(_SQUID_SOLARIS_)
    if (fcntl(fd, F_SETFL, O_NONBLOCK)) {
	debug(5, 0, "comm_open: FD %d: error setting O_NONBLOCK: %s\n",
	    fd, xstrerror());
	return (COMM_ERROR);
    }
#else
    if (fcntl(fd, F_SETFL, O_NDELAY)) {
	debug(5, 0, "comm_open: FD %d: error setting O_NDELAY: %s\n",
	    fd, xstrerror());
	return (COMM_ERROR);
    }
#endif /* HPUX */
    return 0;
}

char **getAddressList(name)
     char *name;
{
    struct hostent *hp = NULL;
    if (name == NULL)
	return NULL;
    if ((hp = ipcache_gethostbyname(name)))
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
	memcpy(&first.s_addr, *list, 4);
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
    int i, max_fd = getMaxFD();

    fd_table = (FD_ENTRY *) xcalloc(max_fd, sizeof(FD_ENTRY));
    /* Keep a few file descriptors free so that we don't run out of FD's
     * after accepting a client but before it opens a socket or a file.
     * Since getMaxFD can be as high as several thousand, don't waste them */
    RESERVED_FD = min(100, getMaxFD() / 4);
    /* hardwired lifetimes */
    fd_lifetime = (int *) xmalloc(sizeof(int) * max_fd);
    for (i = 0; i < max_fd; i++)
	comm_set_fd_lifetime(i, -1);	/* denotes invalid */
    zero_tv.tv_sec = 0;
    zero_tv.tv_usec = 0;
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
    int maxfd = getMaxFD();
    struct timeval tv;
    FD_ENTRY *f = NULL;

    debug(5, 0, "examine_select: Examining open file descriptors...\n");
    for (fd = 0; fd < maxfd; fd++) {
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
		if (f->close_handler) {
		    debug(5, 0, "examine_select: Calling Close Handler\n");
		    f->close_handler(fd, f->close_data);
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
    debug(5, 0, "examine_select: Finished examining open file descriptors.\n");
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
    int maxfd = fdstat_biggest_fd() + 1;

    /* scan for timeout */
    for (fd = 0; fd < maxfd; ++fd) {
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
    int max_fd = getMaxFD();
    time_t lft;
    int (*tmp_local) () = NULL;
    int use_lifetime_handler = 0;
    int use_read = 0;

    /* scan for hardwired lifetime expires, do the timeouts first though */
    for (fd = 0; fd < max_fd; fd++) {
	lft = comm_get_fd_lifetime(fd);
	if ((lft != -1) && (lft < squid_curtime)) {
	    if (fd_table[fd].lifetime_handler != NULL) {
		use_lifetime_handler = 1;
		tmp_local = fd_table[fd].lifetime_handler;
		fd_table[fd].lifetime_handler = 0;	/* reset it */
	    } else if (fd_table[fd].read_handler != NULL) {
		use_read = 1;
		tmp_local = fd_table[fd].read_handler;
		fd_table[fd].read_handler = 0;	/* reset it */
	    } else if (fd_table[fd].write_handler != NULL) {
		use_read = 0;
		tmp_local = fd_table[fd].write_handler;
		fd_table[fd].write_handler = 0;		/* reset it */
	    } else {
		use_read = 0;
		tmp_local = NULL;
	    }
	    if (tmp_local) {
		if (use_lifetime_handler) {
		    debug(5, 2, "comm_select: FD %d lifetime expire: %d < %d (Lifetime handler %p)\n",
			fd, lft, squid_curtime, tmp_local);
		} else {
		    debug(5, 2, "comm_select: FD %d lifetime expire: %d < %d (%s handler %p)\n",
			fd, lft, squid_curtime,
			use_read ? "read" : "write", tmp_local);
		}
	    } else {
		debug(5, 1, "comm_select: FD %d lifetime expire: %d < %d (handler not available.)\n",
		    fd, lft, squid_curtime);
	    }

	    if (tmp_local != NULL) {
		if (use_lifetime_handler) {
		    tmp_local(fd, fd_table[fd].lifetime_data);
		} else {
		    /* 
		     *  we close(2) first so that the handler fails and 
		     *  deallocates the structure.
		     */
		    (void) close(fd);
		    tmp_local(fd, use_read ? fd_table[fd].read_data :
			fd_table[fd].write_data);
		}
		if (fd_table[fd].openned) {
		    /* hmm.. still openned. do full comm_close */
		    debug(5, 5, "comm_select: FD %d lifetime expire: %d < %d : Handler did not close the socket.\n comm_select will do.\n",
			fd, lft, squid_curtime);
		    comm_close(fd);
		} else {
		    /* seems like handle closed it. 
		     * clean up fd_table just to make sure */
		    debug(5, 5, "comm_select: FD %d lifetime expire: %d : Handler closed the socket.\n",
			fd, lft);
		    /* just to make sure here */
		    comm_cleanup_fd_entry(fd);
		}
	    } else {
		/* no handle. do full comm_close */
		debug(5, 5, "comm_select: FD %d lifetime expire: %d < %d : No handler to close the socket.\n comm_select will do.\n",
		    fd, lft, squid_curtime);
		comm_close(fd);
	    }
	}
    }
}

/*
 * Reserve_More_FDs() called when acceopt(), open(), or socket is failing
 */
static void Reserve_More_FDs()
{
    if (RESERVED_FD < getMaxFD() - 64) {
	RESERVED_FD = RESERVED_FD + 1;
    } else if (RESERVED_FD == getMaxFD() - 64) {
	RESERVED_FD = RESERVED_FD + 1;
	debug(5, 0, "Don't you have a tiny open-file table size of %d\n",
	    getMaxFD() - RESERVED_FD);
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
