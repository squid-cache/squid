
/*
 * $Id: wais.cc,v 1.68 1997/04/30 20:06:37 wessels Exp $
 *
 * DEBUG: section 24    WAIS Relay
 * AUTHOR: Harvest Derived
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

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "squid.h"

#define  WAIS_DELETE_GAP  (64*1024)

typedef struct {
    int fd;
    StoreEntry *entry;
    method_t method;
    char *relayhost;
    int relayport;
    char *mime_hdr;
    char request[MAX_URL];
    int ip_lookup_pending;
} WaisStateData;

static PF waisStateFree;
static void waisStartComplete _PARAMS((void *, int));
static PF waisTimeout;
static PF waisReadReply;
static void waisSendComplete _PARAMS((int, char *, int, int, void *));
static PF waisSendRequest;
static IPH waisConnect;
static CNCB waisConnectDone;

static void
waisStateFree(int fd, void *data)
{
    WaisStateData *waisState = data;
    if (waisState == NULL)
	return;
    storeUnlockObject(waisState->entry);
    if (waisState->ip_lookup_pending)
	ipcacheUnregister(waisState->relayhost, waisState);
    xfree(waisState);
}

/* This will be called when socket lifetime is expired. */
static void
waisTimeout(int fd, void *data)
{
    WaisStateData *waisState = data;
    StoreEntry *entry = waisState->entry;
    debug(24, 4, "waisTimeout: FD %d: '%s'\n", fd, entry->url);
    squid_error_entry(entry, ERR_READ_TIMEOUT, NULL);
    comm_close(fd);
}



/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
static void
waisReadReply(int fd, void *data)
{
    WaisStateData *waisState = data;
    LOCAL_ARRAY(char, buf, 4096);
    int len;
    StoreEntry *entry = waisState->entry;
    int clen;
    int off;
    int bin;

    if (entry->flag & DELETE_BEHIND && !storeClientWaiting(entry)) {
	/* we can terminate connection right now */
	squid_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	comm_close(fd);
	return;
    }
    /* check if we want to defer reading */
    clen = entry->mem_obj->e_current_len;
    off = storeGetLowestReaderOffset(entry);
    if ((clen - off) > WAIS_DELETE_GAP) {
	if (entry->flag & CLIENT_ABORT_REQUEST) {
	    squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	    comm_close(fd);
	    return;
	}
	IOStats.Wais.reads_deferred++;
	debug(24, 3, "waisReadReply: Read deferred for Object: %s\n",
	    entry->url);
	debug(24, 3, "                Current Gap: %d bytes\n", clen - off);
	/* reschedule, so it will automatically reactivated
	 * when Gap is big enough. */
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    waisReadReply,
	    waisState, 0);
	/* don't install read handler while we're above the gap */
	if (!BIT_TEST(entry->flag, READ_DEFERRED)) {
	    commSetTimeout(fd, Config.Timeout.defer, NULL, NULL);
	    BIT_SET(entry->flag, READ_DEFERRED);
	}
	/* dont try reading again for a while */
	comm_set_stall(fd, Config.stallDelay);
	return;
    } else {
	BIT_RESET(entry->flag, READ_DEFERRED);
    }
    len = read(fd, buf, 4096);
    fd_bytes(fd, len, FD_READ);
    debug(24, 5, "waisReadReply: FD %d read len:%d\n", fd, len);
    if (len > 0) {
	commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
	IOStats.Wais.reads++;
	for (clen = len - 1, bin = 0; clen; bin++)
	    clen >>= 1;
	IOStats.Wais.read_hist[bin]++;
    }
    if (len < 0) {
	debug(50, 1, "waisReadReply: FD %d: read failure: %s.\n", xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    commSetSelect(fd, COMM_SELECT_READ,
		waisReadReply, waisState, 0);
	} else {
	    BIT_RESET(entry->flag, ENTRY_CACHABLE);
	    storeReleaseRequest(entry);
	    squid_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    comm_close(fd);
	}
    } else if (len == 0 && entry->mem_obj->e_current_len == 0) {
	squid_error_entry(entry,
	    ERR_ZERO_SIZE_OBJECT,
	    errno ? xstrerror() : NULL);
	comm_close(fd);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	entry->expires = squid_curtime;
	storeComplete(entry);
	comm_close(fd);
    } else {
	storeAppend(entry, buf, len);
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    waisReadReply,
	    waisState, 0);
    }
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
static void
waisSendComplete(int fd, char *buf, int size, int errflag, void *data)
{
    WaisStateData *waisState = data;
    StoreEntry *entry = waisState->entry;
    debug(24, 5, "waisSendComplete: FD %d size: %d errflag: %d\n",
	fd, size, errflag);
    if (errflag) {
	squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
    } else {
	/* Schedule read reply. */
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    waisReadReply,
	    waisState, 0);
    }
}

/* This will be called when connect completes. Write request. */
static void
waisSendRequest(int fd, void *data)
{
    WaisStateData *waisState = data;
    int len = strlen(waisState->request) + 4;
    char *buf = NULL;
    const char *Method = RequestMethodStr[waisState->method];

    debug(24, 5, "waisSendRequest: FD %d\n", fd);

    if (Method)
	len += strlen(Method);
    if (waisState->mime_hdr)
	len += strlen(waisState->mime_hdr);

    buf = xcalloc(1, len + 1);

    if (waisState->mime_hdr)
	sprintf(buf, "%s %s %s\r\n", Method, waisState->request,
	    waisState->mime_hdr);
    else
	sprintf(buf, "%s %s\r\n", Method, waisState->request);
    debug(24, 6, "waisSendRequest: buf: %s\n", buf);
    comm_write(fd,
	buf,
	len,
	waisSendComplete,
	(void *) waisState,
	xfree);
    if (BIT_TEST(waisState->entry->flag, ENTRY_CACHABLE))
	storeSetPublicKey(waisState->entry);	/* Make it public */
}

int
waisStart(method_t method, char *mime_hdr, StoreEntry * entry)
{
    WaisStateData *waisState = NULL;
    int fd;
    char *url = entry->url;
    debug(24, 3, "waisStart: \"%s %s\"\n", RequestMethodStr[method], url);
    debug(24, 4, "            header: %s\n", mime_hdr);
    if (!Config.Wais.relayHost) {
	debug(24, 0, "waisStart: Failed because no relay host defined!\n");
	squid_error_entry(entry, ERR_NO_RELAY, NULL);
	return COMM_ERROR;
    }
    fd = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	url);
    if (fd == COMM_ERROR) {
	debug(24, 4, "waisStart: Failed because we're out of sockets.\n");
	squid_error_entry(entry, ERR_NO_FDS, xstrerror());
	return COMM_ERROR;
    }
    waisState = xcalloc(1, sizeof(WaisStateData));
    waisState->method = method;
    waisState->relayhost = Config.Wais.relayHost;
    waisState->relayport = Config.Wais.relayPort;
    waisState->mime_hdr = mime_hdr;
    waisState->fd = fd;
    waisState->entry = entry;
    xstrncpy(waisState->request, url, MAX_URL);
    comm_add_close_handler(waisState->fd,
	waisStateFree,
	waisState);
    commSetTimeout(fd, Config.Timeout.read, waisTimeout, waisState);
    storeLockObject(entry, waisStartComplete, waisState);
    return COMM_OK;
}


static void
waisStartComplete(void *data, int status)
{
    WaisStateData *waisState = data;
    waisState->ip_lookup_pending = 1;
    ipcache_nbgethostbyname(waisState->relayhost,
	waisState->fd,
	waisConnect,
	waisState);
}


static void
waisConnect(int fd, const ipcache_addrs * ia, void *data)
{
    WaisStateData *waisState = data;
    waisState->ip_lookup_pending = 0;
    if (!ipcache_gethostbyname(waisState->relayhost, 0)) {
	debug(24, 4, "waisstart: Unknown host: %s\n", waisState->relayhost);
	squid_error_entry(waisState->entry, ERR_DNS_FAIL, dns_error_message);
	comm_close(waisState->fd);
	return;
    }
    commSetTimeout(fd, Config.Timeout.connect, waisTimeout, waisState);
    commConnectStart(fd,
	waisState->relayhost,
	waisState->relayport,
	waisConnectDone,
	waisState);
}

static void
waisConnectDone(int fd, int status, void *data)
{
    WaisStateData *waisState = data;
    if (status == COMM_ERROR) {
	squid_error_entry(waisState->entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
	return;
    }
    /* Install connection complete handler. */
    if (opt_no_ipcache)
	ipcacheInvalidate(waisState->relayhost);
    commSetSelect(fd,
	COMM_SELECT_WRITE,
	waisSendRequest,
	waisState, 0);
}
