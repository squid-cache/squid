
/*
 * $Id: ipc.cc,v 1.28 2002/04/04 23:59:25 hno Exp $
 *
 * DEBUG: section 54    Interprocess Communication
 * AUTHOR: Duane Wessels
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

static const char *hello_string = "hi there\n";
#define HELLO_BUF_SZ 32
static char hello_buf[HELLO_BUF_SZ];

static int
ipcCloseAllFD(int prfd, int pwfd, int crfd, int cwfd)
{
    if (prfd >= 0)
	comm_close(prfd);
    if (prfd != pwfd)
	if (pwfd >= 0)
	    comm_close(pwfd);
    if (crfd >= 0)
	comm_close(crfd);
    if (crfd != cwfd)
	if (cwfd >= 0)
	    comm_close(cwfd);
    return -1;
}

int
ipcCreate(int type, const char *prog, const char *const args[], const char *name, int *rfd, int *wfd)
{
    pid_t pid;
    struct sockaddr_in CS;
    struct sockaddr_in PS;
    int crfd = -1;
    int prfd = -1;
    int cwfd = -1;
    int pwfd = -1;
    int fd;
    int t1, t2, t3;
    socklen_t len;
    int tmp_s;
#if HAVE_PUTENV
    char *env_str;
#endif
    int x;

#if USE_POLL && defined(_SQUID_OSF_)
    assert(type != IPC_FIFO);
#endif

    if (rfd)
	*rfd = -1;
    if (wfd)
	*wfd = -1;
    if (type == IPC_TCP_SOCKET) {
	crfd = cwfd = comm_open(SOCK_STREAM,
	    0,
	    local_addr,
	    0,
	    COMM_NOCLOEXEC,
	    name);
	prfd = pwfd = comm_open(SOCK_STREAM,
	    0,			/* protocol */
	    local_addr,
	    0,			/* port */
	    0,			/* blocking */
	    name);
    } else if (type == IPC_UDP_SOCKET) {
	crfd = cwfd = comm_open(SOCK_DGRAM,
	    0,
	    local_addr,
	    0,
	    COMM_NOCLOEXEC,
	    name);
	prfd = pwfd = comm_open(SOCK_DGRAM,
	    0,
	    local_addr,
	    0,
	    0,
	    name);
    } else if (type == IPC_FIFO) {
	int p2c[2];
	int c2p[2];
	if (pipe(p2c) < 0) {
	    debug(50, 0) ("ipcCreate: pipe: %s\n", xstrerror());
	    return -1;
	}
	if (pipe(c2p) < 0) {
	    debug(50, 0) ("ipcCreate: pipe: %s\n", xstrerror());
	    return -1;
	}
	fd_open(prfd = p2c[0], FD_PIPE, "IPC FIFO Parent Read");
	fd_open(cwfd = p2c[1], FD_PIPE, "IPC FIFO Child Write");
	fd_open(crfd = c2p[0], FD_PIPE, "IPC FIFO Child Read");
	fd_open(pwfd = c2p[1], FD_PIPE, "IPC FIFO Parent Write");
#if HAVE_SOCKETPAIR && defined(AF_UNIX)
    } else if (type == IPC_UNIX_STREAM) {
	int fds[2];
	int buflen = 32768;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
	    debug(50, 0) ("ipcCreate: socketpair: %s\n", xstrerror());
	    return -1;
	}
	setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, (void *) &buflen, sizeof(buflen));
	setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, (void *) &buflen, sizeof(buflen));
	setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, (void *) &buflen, sizeof(buflen));
	setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, (void *) &buflen, sizeof(buflen));
	fd_open(prfd = pwfd = fds[0], FD_PIPE, "IPC UNIX STREAM Parent");
	fd_open(crfd = cwfd = fds[1], FD_PIPE, "IPC UNIX STREAM Parent");
    } else if (type == IPC_UNIX_DGRAM) {
	int fds[2];
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) < 0) {
	    debug(50, 0) ("ipcCreate: socketpair: %s\n", xstrerror());
	    return -1;
	}
	fd_open(prfd = pwfd = fds[0], FD_PIPE, "IPC UNIX DGRAM Parent");
	fd_open(crfd = cwfd = fds[1], FD_PIPE, "IPC UNIX DGRAM Parent");
#endif
    } else {
	assert(IPC_NONE);
    }
    debug(54, 3) ("ipcCreate: prfd FD %d\n", prfd);
    debug(54, 3) ("ipcCreate: pwfd FD %d\n", pwfd);
    debug(54, 3) ("ipcCreate: crfd FD %d\n", crfd);
    debug(54, 3) ("ipcCreate: cwfd FD %d\n", cwfd);

    if (crfd < 0) {
	debug(54, 0) ("ipcCreate: Failed to create child FD.\n");
	return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
    }
    if (pwfd < 0) {
	debug(54, 0) ("ipcCreate: Failed to create server FD.\n");
	return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
    }
    if (type == IPC_TCP_SOCKET || type == IPC_UDP_SOCKET) {
	len = sizeof(PS);
	memset(&PS, '\0', len);
	if (getsockname(pwfd, (struct sockaddr *) &PS, &len) < 0) {
	    debug(50, 0) ("ipcCreate: getsockname: %s\n", xstrerror());
	    return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
	}
	debug(54, 3) ("ipcCreate: FD %d sockaddr %s:%d\n",
	    pwfd, inet_ntoa(PS.sin_addr), ntohs(PS.sin_port));
	len = sizeof(CS);
	memset(&CS, '\0', len);
	if (getsockname(crfd, (struct sockaddr *) &CS, &len) < 0) {
	    debug(50, 0) ("ipcCreate: getsockname: %s\n", xstrerror());
	    return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
	}
	debug(54, 3) ("ipcCreate: FD %d sockaddr %s:%d\n",
	    crfd, inet_ntoa(CS.sin_addr), ntohs(CS.sin_port));
    }
    if (type == IPC_TCP_SOCKET) {
	if (listen(crfd, 1) < 0) {
	    debug(50, 1) ("ipcCreate: listen FD %d: %s\n", crfd, xstrerror());
	    return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
	}
	debug(54, 3) ("ipcCreate: FD %d listening...\n", crfd);
    }
    /* flush or else we get dup data if unbuffered_logs is set */
    logsFlush();
    if ((pid = fork()) < 0) {
	debug(50, 1) ("ipcCreate: fork: %s\n", xstrerror());
	return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
    }
    if (pid > 0) {		/* parent */
	/* close shared socket with child */
	comm_close(crfd);
	if (cwfd != crfd)
	    comm_close(cwfd);
	cwfd = crfd = -1;
	if (type == IPC_TCP_SOCKET || type == IPC_UDP_SOCKET) {
	    if (comm_connect_addr(pwfd, &CS) == COMM_ERROR)
		return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
	}
	memset(hello_buf, '\0', HELLO_BUF_SZ);
	if (type == IPC_UDP_SOCKET)
	    x = recv(prfd, hello_buf, HELLO_BUF_SZ - 1, 0);
	else
	    x = read(prfd, hello_buf, HELLO_BUF_SZ - 1);
	if (x < 0) {
	    debug(50, 0) ("ipcCreate: PARENT: hello read test failed\n");
	    debug(50, 0) ("--> read: %s\n", xstrerror());
	    return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
	} else if (strcmp(hello_buf, hello_string)) {
	    debug(54, 0) ("ipcCreate: PARENT: hello read test failed\n");
	    debug(54, 0) ("--> read returned %d\n", x);
	    debug(54, 0) ("--> got '%s'\n", rfc1738_escape(hello_buf));
	    return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
	}
	commSetTimeout(prfd, -1, NULL, NULL);
	commSetNonBlocking(prfd);
	commSetNonBlocking(pwfd);
	if (rfd)
	    *rfd = prfd;
	if (wfd)
	    *wfd = pwfd;
	fd_table[prfd].flags.ipc = 1;
	fd_table[pwfd].flags.ipc = 1;
	if (Config.sleep_after_fork) {
	    /* XXX emulation of usleep() */
	    struct timeval sl;
	    sl.tv_sec = Config.sleep_after_fork / 1000000;
	    sl.tv_usec = Config.sleep_after_fork % 1000000;
	    select(0, NULL, NULL, NULL, &sl);
	}
	return pid;
    }
    /* child */
    no_suid();			/* give up extra priviliges */
    /* close shared socket with parent */
    close(prfd);
    if (pwfd != prfd)
	close(pwfd);
    pwfd = prfd = -1;

    if (type == IPC_TCP_SOCKET) {
	debug(54, 3) ("ipcCreate: calling accept on FD %d\n", crfd);
	if ((fd = accept(crfd, NULL, NULL)) < 0) {
	    debug(50, 0) ("ipcCreate: FD %d accept: %s\n", crfd, xstrerror());
	    _exit(1);
	}
	debug(54, 3) ("ipcCreate: CHILD accepted new FD %d\n", fd);
	close(crfd);
	cwfd = crfd = fd;
    } else if (type == IPC_UDP_SOCKET) {
	if (comm_connect_addr(crfd, &PS) == COMM_ERROR)
	    return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
    }
    if (type == IPC_UDP_SOCKET) {
	x = send(cwfd, hello_string, strlen(hello_string) + 1, 0);
	if (x < 0) {
	    debug(50, 0) ("sendto FD %d: %s\n", cwfd, xstrerror());
	    debug(50, 0) ("ipcCreate: CHILD: hello write test failed\n");
	    _exit(1);
	}
    } else {
	if (write(cwfd, hello_string, strlen(hello_string) + 1) < 0) {
	    debug(50, 0) ("write FD %d: %s\n", cwfd, xstrerror());
	    debug(50, 0) ("ipcCreate: CHILD: hello write test failed\n");
	    _exit(1);
	}
    }
#if HAVE_PUTENV
    env_str = xcalloc((tmp_s = strlen(Config.debugOptions) + 32), 1);
    snprintf(env_str, tmp_s, "SQUID_DEBUG=%s", Config.debugOptions);
    putenv(env_str);
#endif
    /*
     * This double-dup stuff avoids problems when one of 
     *  crfd, cwfd, or debug_log are in the rage 0-2.
     */
    do {
	x = open(_PATH_DEVNULL, 0, 0444);
	if (x > -1)
	    commSetCloseOnExec(x);
    } while (x < 3);
    t1 = dup(crfd);
    t2 = dup(cwfd);
    t3 = dup(fileno(debug_log));
    assert(t1 > 2 && t2 > 2 && t3 > 2);
    close(crfd);
    close(cwfd);
    close(fileno(debug_log));
    dup2(t1, 0);
    dup2(t2, 1);
    dup2(t3, 2);
    close(t1);
    close(t2);
    close(t3);
    /* Make sure all other filedescriptors are closed */
    for (x = 3; x < SQUID_MAXFD; x++)
	close(x);
#if HAVE_SETSID
    setsid();
#endif
    execvp(prog, (char *const *) args);
    debug_log = fdopen(2, "a+");
    debug(50, 0) ("ipcCreate: %s: %s\n", prog, xstrerror());
    _exit(1);
    return 0;
}
