/*
 * $Id: whois.cc,v 1.1 1998/06/04 19:06:15 wessels Exp $
 *
 * DEBUG: section 75    WHOIS protocol
 * AUTHOR: Duane Wessels, Kostas Anagnostakis
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

#define WHOIS_PORT 43

typedef struct {
    StoreEntry *entry;
    request_t *request;
} WhoisState;

static PF whoisClose;
static PF whoisTimeout;
static PF whoisReadReply;

/* PUBLIC */

void
whoisStart(request_t * request, StoreEntry * entry, int fd)
{
    WhoisState *p = xcalloc(1, sizeof(*p));
    char *buf;
    size_t l;
    p->request = request;
    p->entry = entry;
    cbdataAdd(p, MEM_NONE);
    storeLockObject(p->entry);
    comm_add_close_handler(fd, whoisClose, p);
    l = strLen(p->request->urlpath)+3;
    buf = xmalloc(l);
    snprintf(buf, l, "%s\r\n", strBuf(p->request->urlpath) + 1);
    comm_write(fd, buf, strlen(buf), NULL, p, xfree);
    commSetSelect(fd, COMM_SELECT_READ, whoisReadReply, p, 0);
    commSetTimeout(fd, Config.Timeout.read, whoisTimeout, p);
}

/* PRIVATE */

static void
whoisTimeout(int fd, void *data)
{
    WhoisState *p = data;
    debug(75, 1) ("whoisTimeout: %s\n", storeUrl(p->entry));
    whoisClose(fd, p);
}

static void
whoisReadReply(int fd, void *data)
{
    WhoisState *p = data;
    StoreEntry *entry = p->entry;
    char *buf = memAllocate(MEM_4K_BUF);
    int len;
    len = read(fd, buf, 4095);
    buf[len] = '\0';
    debug(75, 3) ("whoisReadReply: FD %d read %d bytes\n", fd, len);
    debug(75, 5) ("{%s}\n", buf);
    if (len <= 0) {
	storeComplete(entry);
	debug(75, 3) ("whoisReadReply: Done: %s\n", storeUrl(entry));
	comm_close(fd);
	memFree(MEM_4K_BUF, buf);
	return;
    }
    storeAppend(entry, buf, len);
    memFree(MEM_4K_BUF, buf);
    fd_bytes(fd, len, FD_READ);
    commSetSelect(fd, COMM_SELECT_READ, whoisReadReply, p, Config.Timeout.read);
}

static void
whoisClose(int fd, void *data)
{
    WhoisState *p = data;
    debug(75, 3) ("whoisClose: FD %d\n", fd);
    storeUnlockObject(p->entry);
    cbdataFree(p);
}
