/*
 * DEBUG: section 27    Cache Announcer
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
#include "comm/Connection.h"
#include "disk.h"
#include "event.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "ICP.h"
#include "ipcache.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "tools.h"

static IPH send_announce;

void
start_announce(void *datanotused)
{
    if (0 == Config.onoff.announce)
        return;

    if (!Comm::IsConnOpen(icpOutgoingConn))
        return;

    ipcache_nbgethostbyname(Config.Announce.host, send_announce, NULL);

    eventAdd("send_announce", start_announce, NULL, (double) Config.Announce.period, 1);
}

static void
send_announce(const ipcache_addrs *ia, const DnsLookupDetails &, void *junk)
{
    LOCAL_ARRAY(char, tbuf, 256);
    LOCAL_ARRAY(char, sndbuf, BUFSIZ);

    char *host = Config.Announce.host;
    char *file = NULL;
    unsigned short port = Config.Announce.port;
    int l;
    int n;
    int fd;

    if (ia == NULL) {
        debugs(27, DBG_IMPORTANT, "send_announce: Unknown host '" << host << "'");
        return;
    }

    debugs(27, DBG_IMPORTANT, "Sending Announcement to " << host);
    sndbuf[0] = '\0';
    snprintf(tbuf, 256, "cache_version SQUID/%s\n", version_string);
    strcat(sndbuf, tbuf);
    assert(Config.Sockaddr.http);
    snprintf(tbuf, 256, "Running on %s %d %d\n",
             getMyHostname(),
             getMyPort(),
             (int) Config.Port.icp);
    strcat(sndbuf, tbuf);

    if (Config.adminEmail) {
        snprintf(tbuf, 256, "cache_admin: %s\n", Config.adminEmail);
        strcat(sndbuf, tbuf);
    }

    snprintf(tbuf, 256, "generated %d [%s]\n",
             (int) squid_curtime,
             Time::FormatHttpd(squid_curtime));
    strcat(sndbuf, tbuf);
    l = strlen(sndbuf);

    if ((file = Config.Announce.file) != NULL) {
        fd = file_open(file, O_RDONLY | O_TEXT);

        if (fd > -1 && (n = FD_READ_METHOD(fd, sndbuf + l, BUFSIZ - l - 1)) > 0) {
            fd_bytes(fd, n, FD_READ);
            l += n;
            sndbuf[l] = '\0';
            file_close(fd);
        } else {
            debugs(50, DBG_IMPORTANT, "send_announce: " << file << ": " << xstrerror());
        }
    }

    Ip::Address S = ia->in_addrs[0];
    S.SetPort(port);
    assert(Comm::IsConnOpen(icpOutgoingConn));

    if (comm_udp_sendto(icpOutgoingConn->fd, S, sndbuf, strlen(sndbuf) + 1) < 0)
        debugs(27, DBG_IMPORTANT, "ERROR: Failed to announce to " << S << " from " << icpOutgoingConn->local << ": " << xstrerror());
}
