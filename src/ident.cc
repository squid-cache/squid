/*
 * $Id: ident.cc,v 1.24 1997/01/08 17:04:23 wessels Exp $
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

static void identRequestComplete _PARAMS((int, char *, int, int, void *));
static void identReadReply _PARAMS((int, icpStateData *));
static void identClose _PARAMS((int, icpStateData *));
static void identConnectDone _PARAMS((int fd, int status, void *data));
static void identCallback _PARAMS((icpStateData * icpState));

static void
identClose(int fd, icpStateData * icpState)
{
    icpState->ident.fd = -1;
}

/* start a TCP connection to the peer host on port 113 */
void
identStart(int fd, icpStateData * icpState, void (*callback) _PARAMS((void *)))
{
    icpState->ident.callback = callback;
    icpState->ident.state = IDENT_PENDING;
    if (fd < 0) {
	fd = comm_open(SOCK_STREAM,
	    0,
	    icpState->me.sin_addr,
	    0,
	    COMM_NONBLOCKING,
	    "ident");
	if (fd == COMM_ERROR) {
	    identCallback(icpState);
	    return;
	}
    }
    icpState->ident.fd = fd;
    comm_add_close_handler(fd,
	(PF) identClose,
	(void *) icpState);
    icpState->identConnectState.fd = fd;
    icpState->identConnectState.host = inet_ntoa(icpState->peer.sin_addr);
    icpState->identConnectState.port = IDENT_PORT;
    icpState->identConnectState.handler = identConnectDone;
    icpState->identConnectState.data = icpState;
    comm_nbconnect(fd, &icpState->identConnectState);
}

static void
identConnectDone(int fd, int status, void *data)
{
    icpStateData *icpState = data;
    LOCAL_ARRAY(char, reqbuf, BUFSIZ);
    if (status == COMM_ERROR) {
	comm_close(fd);
	identCallback(icpState);
	return;
    }
    sprintf(reqbuf, "%d, %d\r\n",
	ntohs(icpState->peer.sin_port),
	ntohs(icpState->me.sin_port));
    comm_write(fd,
	reqbuf,
	strlen(reqbuf),
	5,			/* timeout */
	identRequestComplete,
	(void *) icpState,
	NULL);
    commSetSelect(fd,
	COMM_SELECT_READ,
	(PF) identReadReply,
	(void *) icpState, 0);
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
	debug(30, 5, "identReadReply: FD %d: Read '%s'\n", fd, buf);
	if (strstr(buf, "USERID")) {
	    if ((t = strrchr(buf, ':'))) {
		while (isspace(*++t));
		xstrncpy(icpState->ident.ident, t, ICP_IDENT_SZ);
	    }
	}
    }
    comm_close(fd);
    identCallback(icpState);
}

static void
identCallback(icpStateData * icpState)
{
    icpState->ident.state = IDENT_DONE;
    if (icpState->ident.callback)
	icpState->ident.callback(icpState);
}
