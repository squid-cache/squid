
/*
 * $Id: send-announce.cc,v 1.32 1997/04/30 18:31:00 wessels Exp $
 *
 * DEBUG: section 27    Cache Announcer
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

static void
send_announce _PARAMS((int fd, const ipcache_addrs * ia, void *data));

void
start_announce(void *unused)
{
    if (!Config.Announce.on)
	return;
    ipcache_nbgethostbyname(Config.Announce.host, 0, send_announce, NULL);
    eventAdd("send_announce", start_announce, NULL, Config.Announce.rate);
}

static void
send_announce(int fd, const ipcache_addrs * ia, void *data)
{
    LOCAL_ARRAY(char, tbuf, 256);
    LOCAL_ARRAY(char, sndbuf, BUFSIZ);
    icpUdpData *qdata = NULL;
    char *host = Config.Announce.host;
    char *file = NULL;
    u_short port = Config.Announce.port;
    int l;
    int n;
    if (ia == NULL) {
	debug(27, 1, "send_announce: Unknown host '%s'\n", host);
	return;
    }
    debug(27, 0, "Sending Announcement to %s\n", host);
    sndbuf[0] = '\0';
    sprintf(tbuf, "cache_version SQUID/%s\n", version_string);
    strcat(sndbuf, tbuf);
    sprintf(tbuf, "Running on %s %d %d\n",
	getMyHostname(),
	Config.Port.http,
	Config.Port.icp);
    strcat(sndbuf, tbuf);
    if (Config.adminEmail) {
	sprintf(tbuf, "cache_admin: %s\n", Config.adminEmail);
	strcat(sndbuf, tbuf);
    }
    sprintf(tbuf, "generated %d [%s]\n",
	(int) squid_curtime,
	mkhttpdlogtime(&squid_curtime));
    strcat(sndbuf, tbuf);
    l = strlen(sndbuf);
    if ((file = Config.Announce.file)) {
	fd = file_open(file, NULL, O_RDONLY, NULL, NULL);
	if (fd > -1 && (n = read(fd, sndbuf + l, BUFSIZ - l - 1)) > 0) {
	    fd_bytes(fd, n, FD_READ);
	    l += n;
	    sndbuf[l] = '\0';
	    file_close(fd);
	} else {
	    debug(50, 1, "send_announce: %s: %s\n", file, xstrerror());
	}
    }
    qdata = xcalloc(1, sizeof(icpUdpData));
    qdata->msg = xstrdup(sndbuf);
    qdata->len = strlen(sndbuf) + 1;
    qdata->address.sin_family = AF_INET;
    qdata->address.sin_port = htons(port);
    qdata->address.sin_addr = ia->in_addrs[0];
    AppendUdp(qdata);
    commSetSelect(theOutIcpConnection,
	COMM_SELECT_WRITE,
	icpUdpReply,
	qdata, 0);
}
