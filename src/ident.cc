/* $Id: ident.cc,v 1.1 1996/05/03 23:22:22 wessels Exp $ */

/*
 * DEBUG: Section 30           ident/RFC931
 */

#include "squid.h"

#define IDENT_PORT 113

static void identRequestComplete _PARAMS((int, char *, int, int, icpStateData *));
static void identReadReply _PARAMS((int, icpStateData *));
static void identClose _PARAMS((int, icpStateData *));

static void identClose(fd, icpState)
     int fd;
     icpStateData *icpState;
{
    debug(30, 1, "identClose: FD %d\n", fd);
    icpState->ident_fd = -1;
}

/* start a TCP connection to the peer host on port 113 */
void identStart(sock, icpState)
     icpStateData *icpState;
{
    char *host;
    u_short port;
    static char reqbuf[BUFSIZ];
    int status;

    host = inet_ntoa(icpState->peer.sin_addr);
    port = ntohs(icpState->peer.sin_port);

    debug(30, 1, "identStart: peer is %s:%d\n", host, port);

    if (sock < 0) {
	if ((sock = comm_open(COMM_NONBLOCKING, 0, 0, "ident")) == COMM_ERROR) {
	    debug(30, 4, "identStart: Failed because we're out of sockets.\n");
	    return;
	}
    }
    icpState->ident_fd = sock;
    comm_set_select_handler(sock,
	COMM_SELECT_CLOSE,
	(PF) identClose,
	(void *) icpState);
    if ((status = comm_connect(sock, host, IDENT_PORT)) < 0) {
	if (status != EINPROGRESS) {
	    comm_close(sock);
	    return;		/* die silently */
	}
	debug(30, 1, "identStart: FD %d: %s\n", sock, xstrerror());
	comm_set_select_handler(sock,
	    COMM_SELECT_WRITE,
	    (PF) identStart,
	    (void *) icpState);
	return;
    }
    debug(30, 1, "identStart: FD %d: Connected, preparing request...\n", sock);
    sprintf(reqbuf, "%d, %d\r\n",
	ntohs(icpState->peer.sin_port),
	ntohs(icpState->me.sin_port));
    /* XXX icpWrite() returns a data structure which we need to free if there is
     * a timeout */
    (void) icpWrite(sock,
	reqbuf,
	strlen(reqbuf),
	5,			/* timeout */
	identRequestComplete,
	(void *) icpState);
    comm_set_select_handler(sock,
	COMM_SELECT_READ,
	(PF) identReadReply,
	(void *) icpState);
}

static void identRequestComplete(fd, buf, size, errflag, state)
     int fd;
     char *buf;
     int size;
     int errflag;
     icpStateData *state;
{
    debug(30, 1, "identRequestComplete: FD %d: wrote %d bytes\n", fd, size);
}

static void identReadReply(fd, icpState)
     int fd;
     icpStateData *icpState;
{
    static char buf[BUFSIZ];
    char *t = NULL;
    int len = -1;

    buf[0] = '\0';
    len = read(fd, buf, BUFSIZ);
    if (len < 0) {
	debug(30, 1, "identReadReply: FD %d: %s\n", fd, xstrerror());
    } else if (len == 0) {
	debug(30, 1, "identReadReply: FD %d: Read 0 bytes\n", fd);
    }
    if ((t = strchr(buf, '\r')))
	*t = '\0';
    if ((t = strchr(buf, '\n')))
	*t = '\0';
    debug(30, 1, "identReadReply: FD %d: Read '%s'\n", fd, buf);
    if (strstr(buf, "USERID")) {
	if ((t = strrchr(buf, ':'))) {
	    while (isspace(*++t));
	    strncpy(icpState->ident, t, ICP_IDENT_SZ);
	}
    }
    comm_close(fd);
}
