
/*
 * $Id: ipc.cc,v 1.1 1998/01/31 05:34:57 wessels Exp $
 *
 * DEBUG: section 54    Interprocess Communication
 * AUTHOR: Duane Wessels
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
ipcCreate(int type, const char *prog, char *const args[], const char *name, int *rfd, int *wfd)
{
    pid_t pid;
    struct sockaddr_in CS;
    struct sockaddr_in PS;
    int crfd = -1;
    int prfd = -1;
    int cwfd = -1;
    int pwfd = -1;
    int fd;
    int len;
    int tmp_s;
    char *env_str;
    int x;

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
	    debug(50,1)("ipcCreate: listen FD %d: %s\n", crfd, xstrerror());
	    return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
	}
	debug(54, 3) ("ipcCreate: FD %d listening...\n", crfd);
    }

    /* flush or else we get dup data if unbuffered_logs is set */
    logsFlush();
    if ((pid = fork()) < 0) {
	debug(50, 0) ("ipcCreate: fork: %s\n", xstrerror());
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
	    x = recv(prfd, hello_buf, 127, 0);
	else
	    x = read(prfd, hello_buf, 127);
	if (x < 0) {
	    debug(50, 0) ("ipcCreate: PARENT: hello read test failed\n");
	    debug(50, 0) ("--> read: %s\n", xstrerror());
	    return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
	} else if (strcmp(hello_buf, hello_string)) {
	    debug(50, 0) ("ipcCreate: PARENT: hello read test failed\n");
	    debug(50, 0) ("--> got '%s'\n", rfc1738_escape(hello_buf));
	    return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
	}
	commSetTimeout(prfd, -1, NULL, NULL);
	commSetNonBlocking(prfd);
	commSetNonBlocking(pwfd);
	if (rfd)
	    *rfd = prfd;
	if (wfd)
	    *wfd = pwfd;
	return pwfd;
    }
    /* child */
    no_suid();			/* give up extra priviliges */
    /* close shared socket with parent */
    comm_close(prfd);
    if (pwfd != prfd)
	comm_close(pwfd);
    pwfd = prfd = -1;

    if (type == IPC_TCP_SOCKET) {
	debug(54, 3) ("ipcCreate: calling accept on FD %d\n", crfd);
	if ((fd = accept(crfd, NULL, NULL)) < 0) {
	    debug(50, 0) ("ipcCreate: FD %d accept: %s\n", crfd, xstrerror());
	    _exit(1);
	}
	debug(54, 3) ("ipcCreate: accepted new FD %d\n", fd);
	close(crfd);
	cwfd = crfd = fd;
    } else if (type == IPC_UDP_SOCKET) {
	    if (comm_connect_addr(crfd, &PS) == COMM_ERROR)
		return ipcCloseAllFD(prfd, pwfd, crfd, cwfd);
    }

    if (type == IPC_UDP_SOCKET) {
	x = send(cwfd, hello_string, strlen(hello_string), 0);
	if (x < 0) {
	    debug(50, 0) ("sendto FD %d: %s\n", cwfd, xstrerror());
	    debug(50, 0) ("ipcCreate: CHILD: hello write test failed\n");
	    _exit(1);
	}
    } else {
	if (write(cwfd, hello_string, strlen(hello_string)) < 0) {
	    debug(50, 0) ("write FD %d: %s\n", cwfd, xstrerror());
	    debug(50, 0) ("ipcCreate: CHILD: hello write test failed\n");
	    _exit(1);
	}
    }
    env_str = xcalloc((tmp_s = strlen(Config.debugOptions) + 32), 1);
    snprintf(env_str, tmp_s, "SQUID_DEBUG=%s", Config.debugOptions);
    putenv(env_str);
    dup2(crfd, 0);
    dup2(cwfd, 1);
    dup2(fileno(debug_log), 2);
    fclose(debug_log);
    /*
     * Solaris pthreads seems to close FD 0 upon fork(), so don't close
     * this FD if its 0, 1, or 2.
     * -- Michael O'Reilly <michael@metal.iinet.net.au>
     */
    if (crfd > 2)
	close(crfd);
    if (cwfd != crfd)
	if (cwfd > 2)
	    close(cwfd);
    execvp(prog, args);
    debug(50, 0) ("ipcCreate: %s: %s\n", prog, xstrerror());
    _exit(1);
    return 0;
}
