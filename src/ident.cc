
/*
 * $Id: ident.cc,v 1.37 1997/11/12 00:08:54 wessels Exp $
 *
 * DEBUG: section 30    Ident (RFC 931)
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

#define IDENT_PORT 113

static PF identReadReply;
static PF identClose;
static CNCB identConnectDone;
static void identCallback(ConnStateData * connState);

static void
identClose(int fdnotused, void *data)
{
    ConnStateData *connState = data;
    connState->ident.fd = -1;
}

/* start a TCP connection to the peer host on port 113 */
void
identStart(int fd, ConnStateData * connState, IDCB * callback)
{
    connState->ident.callback = callback;
    connState->ident.state = IDENT_PENDING;
    if (fd < 0) {
	fd = comm_open(SOCK_STREAM,
	    0,
	    connState->me.sin_addr,
	    0,
	    COMM_NONBLOCKING,
	    "ident");
	if (fd == COMM_ERROR) {
	    identCallback(connState);
	    return;
	}
    }
    connState->ident.fd = fd;
    comm_add_close_handler(fd,
	identClose,
	connState);
    commConnectStart(fd,
	inet_ntoa(connState->peer.sin_addr),
	IDENT_PORT,
	identConnectDone,
	connState);
}

static void
identConnectDone(int fd, int status, void *data)
{
    ConnStateData *connState = data;
    LOCAL_ARRAY(char, reqbuf, BUFSIZ);
    if (status != COMM_OK) {
	comm_close(fd);
	identCallback(connState);
	return;
    }
    snprintf(reqbuf, BUFSIZ, "%d, %d\r\n",
	ntohs(connState->peer.sin_port),
	ntohs(connState->me.sin_port));
    comm_write(fd, xstrdup(reqbuf), strlen(reqbuf), NULL, connState, xfree);
    commSetSelect(fd, COMM_SELECT_READ, identReadReply, connState, 0);
}

static void
identReadReply(int fd, void *data)
{
    ConnStateData *connState = data;
    LOCAL_ARRAY(char, buf, BUFSIZ);
    char *t = NULL;
    int len = -1;

    buf[0] = '\0';
    len = read(fd, buf, BUFSIZ);
    fd_bytes(fd, len, FD_READ);
    if (len > 0) {
	if ((t = strchr(buf, '\r')))
	    *t = '\0';
	if ((t = strchr(buf, '\n')))
	    *t = '\0';
	debug(30, 5) ("identReadReply: FD %d: Read '%s'\n", fd, buf);
	if (strstr(buf, "USERID")) {
	    if ((t = strrchr(buf, ':'))) {
		while (isspace(*++t));
		xstrncpy(connState->ident.ident, t, ICP_IDENT_SZ);
	    }
	}
    }
    comm_close(fd);
    identCallback(connState);
}

static void
identCallback(ConnStateData * connState)
{
    connState->ident.state = IDENT_DONE;
    if (connState->ident.callback)
	connState->ident.callback(connState);
}
