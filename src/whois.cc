/*
 * $Id: whois.cc,v 1.5 1998/07/22 20:38:07 wessels Exp $
 *
 * DEBUG: section 75    WHOIS protocol
 * AUTHOR: Duane Wessels, Kostas Anagnostakis
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

#define WHOIS_PORT 43

typedef struct {
    StoreEntry *entry;
    request_t *request;
    FwdState *fwdState;
} WhoisState;

static PF whoisClose;
static PF whoisTimeout;
static PF whoisReadReply;

/* PUBLIC */

void
whoisStart(FwdState * fwdState, int fd)
{
    WhoisState *p = xcalloc(1, sizeof(*p));
    char *buf;
    size_t l;
    p->request = fwdState->request;
    p->entry = fwdState->entry;
    p->fwdState = fwdState;
    cbdataAdd(p, MEM_NONE);
    storeLockObject(p->entry);
    comm_add_close_handler(fd, whoisClose, p);
    l = strLen(p->request->urlpath) + 3;
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
    if (len > 0) {
	fd_bytes(fd, len, FD_READ);
	kb_incr(&Counter.server.all.kbytes_in, len);
	kb_incr(&Counter.server.http.kbytes_in, len);
	storeAppend(entry, buf, len);
	commSetSelect(fd, COMM_SELECT_READ, whoisReadReply, p, Config.Timeout.read);
    } else if (len < 0) {
	debug(50, 2) ("whoisReadReply: FD %d: read failure: %s.\n",
	    fd, xstrerror());
	if (ignoreErrno(errno)) {
	    commSetSelect(fd, COMM_SELECT_READ, whoisReadReply, p, Config.Timeout.read);
	} else if (entry->mem_obj->inmem_hi == 0) {
	    fwdFail(p->fwdState, ERR_READ_ERROR, HTTP_INTERNAL_SERVER_ERROR, errno);
	    comm_close(fd);
	} else {
	    storeAbort(entry, 0);
	    comm_close(fd);
	}
    } else {
	storeComplete(entry);
	debug(75, 3) ("whoisReadReply: Done: %s\n", storeUrl(entry));
	comm_close(fd);
    }
    memFree(MEM_4K_BUF, buf);
}

static void
whoisClose(int fd, void *data)
{
    WhoisState *p = data;
    debug(75, 3) ("whoisClose: FD %d\n", fd);
    storeUnlockObject(p->entry);
    cbdataFree(p);
}
