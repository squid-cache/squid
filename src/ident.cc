/*
 * $Id: ident.cc,v 1.13 1996/09/16 21:11:09 wessels Exp $
 *
 * DEBUG: section 30    Ident (RFC 931)
 * AUTHOR: Duane Wessels
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

#include "squid.h"

#define IDENT_PORT 113

static void identRequestComplete __P((int, char *, int, int, void *));
static void identReadReply __P((int, icpStateData *));
static void identClose __P((int, icpStateData *));

static void
identClose(int fd, icpStateData * icpState)
{
    icpState->ident_fd = -1;
}

/* start a TCP connection to the peer host on port 113 */
void
identStart(int sock, icpStateData * icpState)
{
    char *host;
    u_short port;
    LOCAL_ARRAY(char, reqbuf, BUFSIZ);
    int status;

    host = inet_ntoa(icpState->peer.sin_addr);
    port = ntohs(icpState->peer.sin_port);

    if (sock < 0) {
	sock = comm_open(SOCK_STREAM,
		0,
		Config.Addrs.tcp_outgoing,
		0,
		COMM_NONBLOCKING,
		"ident");
	if (sock == COMM_ERROR)
	    return;
    }
    icpState->ident_fd = sock;
    comm_add_close_handler(sock,
	(PF) identClose,
	(void *) icpState);
    if ((status = comm_connect(sock, host, IDENT_PORT)) < 0) {
	if (status != EINPROGRESS) {
	    comm_close(sock);
	    return;		/* die silently */
	}
	comm_set_select_handler(sock,
	    COMM_SELECT_WRITE,
	    (PF) identStart,
	    (void *) icpState);
	return;
    }
    sprintf(reqbuf, "%d, %d\r\n",
	ntohs(icpState->peer.sin_port),
	ntohs(icpState->me.sin_port));
    comm_write(sock,
	reqbuf,
	strlen(reqbuf),
	5,			/* timeout */
	identRequestComplete,
	(void *) icpState,
	NULL);
    comm_set_select_handler(sock,
	COMM_SELECT_READ,
	(PF) identReadReply,
	(void *) icpState);
}

static void
identRequestComplete(int fd, char *buf, int size, int errflag, void *data)
{
    debug(30, 5, "identRequestComplete: FD %d: wrote %d bytes\n", fd, size);
}

static void
identReadReply(int fd, icpStateData * icpState)
{
    LOCAL_ARRAY(char, buf, BUFSIZ);
    char *t = NULL;
    int len = -1;

    buf[0] = '\0';
    len = read(fd, buf, BUFSIZ);
    if (len > 0) {
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
    }
    comm_close(fd);
}
