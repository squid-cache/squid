
/*
 * $Id: send-announce.cc,v 1.53 1998/07/22 20:37:46 wessels Exp $
 *
 * DEBUG: section 27    Cache Announcer
 * AUTHOR: Duane Wessels
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

static IPH send_announce;

void
start_announce(void *datanotused)
{
    void *junk;
    if (0 == Config.onoff.announce)
	return;
    if (theOutIcpConnection < 0)
	return;
    cbdataAdd(junk = xmalloc(1), MEM_NONE);
    ipcache_nbgethostbyname(Config.Announce.host, send_announce, junk);
    eventAdd("send_announce", start_announce, NULL, (double) Config.Announce.period, 1);
}

static void
send_announce(const ipcache_addrs * ia, void *junk)
{
    LOCAL_ARRAY(char, tbuf, 256);
    LOCAL_ARRAY(char, sndbuf, BUFSIZ);
    struct sockaddr_in S;
    char *host = Config.Announce.host;
    char *file = NULL;
    u_short port = Config.Announce.port;
    int l;
    int n;
    int fd;
    int x;
    cbdataFree(junk);
    if (ia == NULL) {
	debug(27, 1) ("send_announce: Unknown host '%s'\n", host);
	return;
    }
    debug(27, 0) ("Sending Announcement to %s\n", host);
    sndbuf[0] = '\0';
    snprintf(tbuf, 256, "cache_version SQUID/%s\n", version_string);
    strcat(sndbuf, tbuf);
    assert(Config.Port.http);
    snprintf(tbuf, 256, "Running on %s %d %d\n",
	getMyHostname(),
	(int) Config.Port.http->i,
	(int) Config.Port.icp);
    strcat(sndbuf, tbuf);
    if (Config.adminEmail) {
	snprintf(tbuf, 256, "cache_admin: %s\n", Config.adminEmail);
	strcat(sndbuf, tbuf);
    }
    snprintf(tbuf, 256, "generated %d [%s]\n",
	(int) squid_curtime,
	mkhttpdlogtime(&squid_curtime));
    strcat(sndbuf, tbuf);
    l = strlen(sndbuf);
    if ((file = Config.Announce.file) != NULL) {
	fd = file_open(file, O_RDONLY, NULL, NULL, NULL);
	if (fd > -1 && (n = read(fd, sndbuf + l, BUFSIZ - l - 1)) > 0) {
	    fd_bytes(fd, n, FD_READ);
	    l += n;
	    sndbuf[l] = '\0';
	    file_close(fd);
	} else {
	    debug(50, 1) ("send_announce: %s: %s\n", file, xstrerror());
	}
    }
    memset(&S, '\0', sizeof(S));
    S.sin_family = AF_INET;
    S.sin_port = htons(port);
    S.sin_addr = ia->in_addrs[0];
    assert(theOutIcpConnection > 0);
    x = comm_udp_sendto(theOutIcpConnection,
	&S, sizeof(S),
	sndbuf, strlen(sndbuf) + 1);
    if (x < 0)
	debug(27, 1) ("send_announce: FD %d: %s\n", theOutIcpConnection,
	    xstrerror());
}
