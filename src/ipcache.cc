
/*
 * $Id: ipcache.cc,v 1.159 1998/02/23 21:07:13 kostas Exp $
 *
 * DEBUG: section 14    IP Cache
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

struct _ip_pending {
    IPH *handler;
    void *handlerData;
    struct _ip_pending *next;
};

struct ipcacheQueueData {
    struct ipcacheQueueData *next;
    ipcache_entry *i;
};

static struct {
    int requests;
    int replies;
    int hits;
    int misses;
    int pending_hits;
    int negative_hits;
    int errors;
    int ghbn_calls;		/* # calls to blocking gethostbyname() */
    int release_locked;
} IpcacheStats;

static dlink_list lru_list;

static int ipcache_testname(void);
static PF ipcache_dnsHandleRead;
static ipcache_entry *ipcache_parsebuffer(const char *buf, dnsserver_t *);
static void ipcache_release(ipcache_entry *);
static ipcache_entry *ipcache_create(const char *name);
static void ipcache_call_pending(ipcache_entry *);
static ipcache_entry *ipcacheAddNew(const char *, const struct hostent *, ipcache_status_t);
static void ipcacheAddHostent(ipcache_entry *, const struct hostent *);
static int ipcacheHasPending(ipcache_entry *);
static ipcache_entry *ipcache_get(const char *);
static IPH dummy_handler;
static int ipcacheExpiredEntry(ipcache_entry *);
static void ipcacheAddPending(ipcache_entry *, IPH *, void *);
static void ipcacheEnqueue(ipcache_entry *);
static void *ipcacheDequeue(void);
static void ipcache_dnsDispatch(dnsserver_t *, ipcache_entry *);
static void ipcacheStatPrint(ipcache_entry *, StoreEntry *);
static void ipcacheUnlockEntry(ipcache_entry *);
static void ipcacheLockEntry(ipcache_entry *);
static void ipcacheNudgeQueue(void);
static void ipcacheChangeKey(ipcache_entry * i);

static ipcache_addrs static_addrs;
static hash_table *ip_table = NULL;
static struct ipcacheQueueData *ipcacheQueueHead = NULL;
static struct ipcacheQueueData **ipcacheQueueTailP = &ipcacheQueueHead;
static int queue_length = 0;

static char ipcache_status_char[] =
{
    'C',
    'N',
    'P',
    'D'
};

static long ipcache_low = 180;
static long ipcache_high = 200;

#if LIBRESOLV_DNS_TTL_HACK
extern int _dns_ttl_;
#endif

static void
ipcacheEnqueue(ipcache_entry * i)
{
    static time_t last_warning = 0;
    struct ipcacheQueueData *new = xcalloc(1, sizeof(struct ipcacheQueueData));
    new->i = i;
    *ipcacheQueueTailP = new;
    ipcacheQueueTailP = &new->next;
    queue_length++;
    if (queue_length < NDnsServersAlloc)
	return;
    if (squid_curtime - last_warning < 600)
	return;
    last_warning = squid_curtime;
    debug(14, 1) ("ipcacheEnqueue: WARNING: All dnsservers are busy.\n");
    debug(14, 1) ("ipcacheEnqueue: WARNING: %d DNS lookups queued\n", queue_length);
    if (Config.dnsChildren >= DefaultDnsChildrenMax)
	return;
    debug(14, 1) ("ipcacheEnqueue: Consider increasing 'dns_children' in your config file.\n");
}

static void *
ipcacheDequeue(void)
{
    struct ipcacheQueueData *old = NULL;
    ipcache_entry *i = NULL;
    if (ipcacheQueueHead) {
	i = ipcacheQueueHead->i;
	old = ipcacheQueueHead;
	ipcacheQueueHead = ipcacheQueueHead->next;
	if (ipcacheQueueHead == NULL)
	    ipcacheQueueTailP = &ipcacheQueueHead;
	safe_free(old);
	queue_length--;
    }
    if (i != NULL)
	assert(i->status == IP_PENDING);
    return i;
}

static int
ipcache_testname(void)
{
    wordlist *w = NULL;
    debug(14, 1) ("Performing DNS Tests...\n");
    if ((w = Config.dns_testname_list) == NULL)
	return 1;
    for (; w; w = w->next) {
	IpcacheStats.ghbn_calls++;
	if (gethostbyname(w->key) != NULL)
	    return 1;
    }
    return 0;
}

/* removes the given ipcache entry */
static void
ipcache_release(ipcache_entry * i)
{
    hash_link *table_entry = NULL;
    if ((table_entry = hash_lookup(ip_table, i->name)) == NULL) {
	debug(14, 0) ("ipcache_release: Could not find key '%s'\n", i->name);
	return;
    }
    assert(i == (ipcache_entry *) table_entry);
    if (i->locks) {
	i->expires = squid_curtime;
	ipcacheChangeKey(i);
	IpcacheStats.release_locked++;
	return;
    }
    if (hash_remove_link(ip_table, table_entry)) {
	debug(14, 0) ("ipcache_release: hash_remove_link() failed for '%s'\n",
	    i->name);
	return;
    }
    dlinkDelete(&i->lru, &lru_list);
    if (i->status == IP_CACHED) {
	safe_free(i->addrs.in_addrs);
	safe_free(i->addrs.bad_mask);
	debug(14, 5) ("ipcache_release: Released IP cached record for '%s'.\n",
	    i->name);
    }
    safe_free(i->name);
    safe_free(i->error_message);
    safe_free(i);
    --meta_data.ipcache_count;
    return;
}

static ipcache_entry *
ipcache_get(const char *name)
{
    assert(ip_table != NULL);
    return (ipcache_entry *) hash_lookup(ip_table, name);
}

static int
ipcacheExpiredEntry(ipcache_entry * i)
{
    if (i->status == IP_PENDING)
	return 0;
    if (i->status == IP_DISPATCHED)
	return 0;
    if (i->locks != 0)
	return 0;
    if (i->addrs.count == 0)
	return 1;
    if (i->expires > squid_curtime)
	return 0;
    return 1;
}

void
ipcache_purgelru(void *voidnotused)
{
    dlink_node *m;
    dlink_node *prev = NULL;
    ipcache_entry *i;
    int removed = 0;
    for (m = lru_list.tail; m; m = prev) {
	if (meta_data.ipcache_count < ipcache_low)
	    break;
	prev = m->prev;
	i = m->data;
	if (i->status == IP_PENDING)
	    continue;
	if (i->status == IP_DISPATCHED)
	    continue;
	if (i->locks != 0)
	    continue;
	ipcache_release(i);
	removed++;
    }
    debug(14, 3) ("ipcache_purgelru: removed %d entries\n", removed);
}

/* create blank ipcache_entry */
static ipcache_entry *
ipcache_create(const char *name)
{
    static ipcache_entry *i;
    if (meta_data.ipcache_count > ipcache_high)
	ipcache_purgelru(NULL);
    meta_data.ipcache_count++;
    i = xcalloc(1, sizeof(ipcache_entry));
    i->name = xstrdup(name);
    i->expires = squid_curtime + Config.negativeDnsTtl;
    hash_join(ip_table, (hash_link *) i);
    dlinkAdd(i, &i->lru, &lru_list);
    return i;
}

static void
ipcacheAddHostent(ipcache_entry * i, const struct hostent *hp)
{
    int addr_count = 0;
    int k;
    safe_free(i->addrs.in_addrs);
    safe_free(i->addrs.bad_mask);
    while ((addr_count < 255) && *(hp->h_addr_list + addr_count))
	++addr_count;
    i->addrs.count = (unsigned char) addr_count;
    i->addrs.in_addrs = xcalloc(addr_count, sizeof(struct in_addr));
    i->addrs.bad_mask = xcalloc(addr_count, sizeof(unsigned char));
    i->addrs.badcount = 0;
    for (k = 0; k < addr_count; k++)
	xmemcpy(&i->addrs.in_addrs[k].s_addr,
	    *(hp->h_addr_list + k),
	    hp->h_length);
}

static ipcache_entry *
ipcacheAddNew(const char *name, const struct hostent *hp, ipcache_status_t status)
{
    ipcache_entry *i;
    if (ipcache_get(name))
	fatal_dump("ipcacheAddNew: somebody adding a duplicate!");
    debug(14, 10) ("ipcacheAddNew: Adding '%s', status=%c\n",
	name,
	ipcache_status_char[status]);
    i = ipcache_create(name);
    if (hp)
	ipcacheAddHostent(i, hp);
    i->status = status;
    i->lastref = squid_curtime;
    return i;
}

/* walks down the pending list, calling handlers */
static void
ipcache_call_pending(ipcache_entry * i)
{
    struct _ip_pending *p = NULL;
    int nhandler = 0;
    i->lastref = squid_curtime;
    ipcacheLockEntry(i);
    while (i->pending_head != NULL) {
	p = i->pending_head;
	i->pending_head = p->next;
	if (p->handler) {
	    nhandler++;
	    dns_error_message = i->error_message;
	    if (cbdataValid(p->handlerData)) {
		p->handler(i->status == IP_CACHED ? &i->addrs : NULL,
		    p->handlerData);
	    }
	    cbdataUnlock(p->handlerData);
	}
	safe_free(p);
    }
    i->pending_head = NULL;	/* nuke list */
    debug(14, 10) ("ipcache_call_pending: Called %d handlers.\n", nhandler);
    ipcacheUnlockEntry(i);
}


static ipcache_entry *
ipcache_parsebuffer(const char *inbuf, dnsserver_t * dnsData)
{
    char *buf = xstrdup(inbuf);
    char *token;
    static ipcache_entry i;
    int k;
    int ipcount;
    int aliascount;
    debug(14, 5) ("ipcache_parsebuffer: parsing:\n%s", inbuf);
    memset(&i, '\0', sizeof(ipcache_entry));
    i.expires = squid_curtime + Config.positiveDnsTtl;
    for (token = strtok(buf, w_space); token; token = strtok(NULL, w_space)) {
	if (!strcmp(token, "$end")) {
	    break;
	} else if (!strcmp(token, "$alive")) {
	    dnsData->answer = squid_curtime;
	} else if (!strcmp(token, "$fail")) {
	    if ((token = strtok(NULL, "\n")) == NULL)
		fatal_dump("Invalid $fail");
	    i.expires = squid_curtime + Config.negativeDnsTtl;
	    i.status = IP_NEGATIVE_CACHED;
	} else if (!strcmp(token, "$message")) {
	    if ((token = strtok(NULL, "\n")) == NULL)
		fatal_dump("Invalid $message");
	    i.error_message = xstrdup(token);
	} else if (!strcmp(token, "$name")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $name");
	    i.status = IP_CACHED;
	} else if (!strcmp(token, "$h_name")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $h_name");
	    /* ignore $h_name */
	} else if (!strcmp(token, "$h_len")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $h_len");
	    /* ignore $h_length */
	} else if (!strcmp(token, "$ipcount")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $ipcount");
	    ipcount = atoi(token);
	    i.addrs.count = (unsigned char) ipcount;
	    if (ipcount == 0) {
		i.addrs.in_addrs = NULL;
		i.addrs.bad_mask = NULL;
	    } else {
		i.addrs.in_addrs = xcalloc(ipcount, sizeof(struct in_addr));
		i.addrs.bad_mask = xcalloc(ipcount, sizeof(unsigned char));
	    }
	    for (k = 0; k < ipcount; k++) {
		if ((token = strtok(NULL, w_space)) == NULL)
		    fatal_dump("Invalid IP address");
		if (!safe_inet_addr(token, &i.addrs.in_addrs[k]))
		    fatal_dump("Invalid IP address");
	    }
	} else if (!strcmp(token, "$aliascount")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $aliascount");
	    aliascount = atoi(token);
	    for (k = 0; k < aliascount; k++) {
		if ((token = strtok(NULL, w_space)) == NULL)
		    fatal_dump("Invalid alias");
	    }
	} else if (!strcmp(token, "$ttl")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $ttl");
	    i.expires = squid_curtime + atoi(token);
	} else {
	    debug(14, 0) ("--> %s <--\n", inbuf);
	    debug_trap("Invalid dnsserver output");
	}
    }
    xfree(buf);
    return &i;
}

static void
ipcacheNudgeQueue(void)
{
    dnsserver_t *dnsData;
    ipcache_entry *i = NULL;
    while ((dnsData = dnsGetFirstAvailable()) && (i = ipcacheDequeue()))
	ipcache_dnsDispatch(dnsData, i);
}

static void
ipcache_dnsHandleRead(int fd, void *data)
{
    dnsserver_t *dnsData = data;
    int len;
    int n;
    ipcache_entry *i = NULL;
    ipcache_entry *x = NULL;

    len = read(fd,
	dnsData->ip_inbuf + dnsData->offset,
	dnsData->size - dnsData->offset);
    fd_bytes(fd, len, FD_READ);
    debug(14, 5) ("ipcache_dnsHandleRead: Result from DNS ID %d (%d bytes)\n",
	dnsData->id, len);
    if (len <= 0) {
	if (len < 0 && ignoreErrno(errno)) {
	    commSetSelect(fd,
		COMM_SELECT_READ,
		ipcache_dnsHandleRead,
		dnsData,
		0);
	    return;
	}
	debug(14, EBIT_TEST(dnsData->flags, HELPER_CLOSING) ? 5 : 1)
	    ("FD %d: Connection from DNSSERVER #%d is closed, disabling\n",
	    fd, dnsData->id);
	dnsData->flags = 0;
	commSetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
	comm_close(fd);
	return;
    }
    n = ++IpcacheStats.replies;
    DnsStats.replies++;
    dnsData->offset += len;
    dnsData->ip_inbuf[dnsData->offset] = '\0';
    i = dnsData->data;
    assert(i != NULL);
    assert(i->status == IP_DISPATCHED);
    if (strstr(dnsData->ip_inbuf, "$end\n")) {
	/* end of record found */
	statLogHistCount(&Counter.dns.svc_time,
	    tvSubMsec(dnsData->dispatch_time, current_time));
	if ((x = ipcache_parsebuffer(dnsData->ip_inbuf, dnsData)) == NULL) {
	    debug(14, 0) ("ipcache_dnsHandleRead: ipcache_parsebuffer failed?!\n");
	} else {
	    dnsData->offset = 0;
	    dnsData->ip_inbuf[0] = '\0';
	    i->addrs = x->addrs;
	    i->error_message = x->error_message;
	    i->status = x->status;
	    i->expires = x->expires;
	    ipcache_call_pending(i);
	}
	ipcacheUnlockEntry(i);	/* unlock from IP_DISPATCHED */
    } else {
	debug(14, 5) ("ipcache_dnsHandleRead: Incomplete reply\n");
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    ipcache_dnsHandleRead,
	    dnsData,
	    0);
    }
    if (dnsData->offset == 0) {
	dnsData->data = NULL;
	EBIT_CLR(dnsData->flags, HELPER_BUSY);
	if (EBIT_TEST(dnsData->flags, HELPER_SHUTDOWN))
	    dnsShutdownServer(dnsData);
	cbdataUnlock(dnsData);
    }
    ipcacheNudgeQueue();
}

static void
ipcacheAddPending(ipcache_entry * i, IPH * handler, void *handlerData)
{
    struct _ip_pending *pending = xcalloc(1, sizeof(struct _ip_pending));
    struct _ip_pending **I = NULL;
    i->lastref = squid_curtime;
    pending->handler = handler;
    pending->handlerData = handlerData;
    cbdataLock(handlerData);
    for (I = &(i->pending_head); *I; I = &((*I)->next));
    *I = pending;
    if (i->status == IP_PENDING)
	ipcacheNudgeQueue();
}

void
ipcache_nbgethostbyname(const char *name, IPH * handler, void *handlerData)
{
    ipcache_entry *i = NULL;
    dnsserver_t *dnsData = NULL;
    const ipcache_addrs *addrs = NULL;

    if (!handler)
	fatal_dump("ipcache_nbgethostbyname: NULL handler");

    debug(14, 4) ("ipcache_nbgethostbyname: Name '%s'.\n", name);
    IpcacheStats.requests++;

    if (name == NULL || name[0] == '\0') {
	debug(14, 4) ("ipcache_nbgethostbyname: Invalid name!\n");
	handler(NULL, handlerData);
	return;
    }
    if ((addrs = ipcacheCheckNumeric(name))) {
	handler(addrs, handlerData);
	return;
    }
    if ((i = ipcache_get(name))) {
	if (ipcacheExpiredEntry(i)) {
	    ipcache_release(i);
	    i = NULL;
	}
    }
    if (i == NULL) {
	/* MISS: No entry, create the new one */
	debug(14, 5) ("ipcache_nbgethostbyname: MISS for '%s'\n", name);
	IpcacheStats.misses++;
	i = ipcacheAddNew(name, NULL, IP_PENDING);
	ipcacheAddPending(i, handler, handlerData);
    } else if (i->status == IP_CACHED || i->status == IP_NEGATIVE_CACHED) {
	/* HIT */
	debug(14, 4) ("ipcache_nbgethostbyname: HIT for '%s'\n", name);
	if (i->status == IP_NEGATIVE_CACHED)
	    IpcacheStats.negative_hits++;
	else
	    IpcacheStats.hits++;
	ipcacheAddPending(i, handler, handlerData);
	ipcache_call_pending(i);
	return;
    } else if (i->status == IP_PENDING || i->status == IP_DISPATCHED) {
	debug(14, 4) ("ipcache_nbgethostbyname: PENDING for '%s'\n", name);
	IpcacheStats.pending_hits++;
	ipcacheAddPending(i, handler, handlerData);
	if (squid_curtime - i->expires > 600) {
	    debug(14, 0) ("ipcache_nbgethostbyname: '%s' PENDING for %d seconds, aborting\n", name, squid_curtime + Config.negativeDnsTtl - i->expires);
	    ipcacheChangeKey(i);
	    ipcache_call_pending(i);
	}
	return;
    } else {
	fatal_dump("ipcache_nbgethostbyname: BAD ipcache_entry status");
    }

    /* for HIT, PENDING, DISPATCHED we've returned.  For MISS we continue */

    if ((dnsData = dnsGetFirstAvailable())) {
	ipcache_dnsDispatch(dnsData, i);
    } else if (NDnsServersAlloc) {
	ipcacheEnqueue(i);
    } else {
	/* generate abort if we get here */
	assert(NDnsServersAlloc);
    }
}

static void
ipcache_dnsDispatch(dnsserver_t * dns, ipcache_entry * i)
{
    char *buf = NULL;
    assert(EBIT_TEST(dns->flags, HELPER_ALIVE));
    if (!ipcacheHasPending(i)) {
	debug(14, 0) ("Skipping lookup of '%s' because client(s) disappeared.\n",
	    i->name);
	i->status = IP_NEGATIVE_CACHED;
	ipcache_release(i);
	return;
    }
    assert(i->status == IP_PENDING);
    buf = xcalloc(1, 256);
    snprintf(buf, 256, "%s\n", i->name);
    EBIT_SET(dns->flags, HELPER_BUSY);
    dns->data = i;
    i->status = IP_DISPATCHED;
    cbdataLock(dns);
    comm_write(dns->outpipe,
	buf,
	strlen(buf),
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	xfree);
    commSetSelect(dns->outpipe,
	COMM_SELECT_READ,
	ipcache_dnsHandleRead,
	dns, 0);
    debug(14, 5) ("ipcache_dnsDispatch: Request sent to DNS server #%d.\n",
	dns->id);
    dns->dispatch_time = current_time;
    DnsStats.requests++;
    DnsStats.hist[dns->id - 1]++;
    ipcacheLockEntry(i);	/* lock while IP_DISPATCHED */
}


/* initialize the ipcache */
void
ipcache_init(void)
{
    debug(14, 3) ("Initializing IP Cache...\n");

    memset(&IpcacheStats, '\0', sizeof(IpcacheStats));

    /* test naming lookup */
    if (!opt_dns_tests) {
	debug(14, 4) ("ipcache_init: Skipping DNS name lookup tests.\n");
    } else if (!ipcache_testname()) {
	fatal("ipcache_init: DNS name lookup tests failed.");
    } else {
	debug(14, 1) ("Successful DNS name lookup tests...\n");
    }

    ip_table = hash_create(urlcmp, 229, hash4);		/* small hash table */
    memset(&static_addrs, '\0', sizeof(ipcache_addrs));
    static_addrs.in_addrs = xcalloc(1, sizeof(struct in_addr));
    static_addrs.bad_mask = xcalloc(1, sizeof(unsigned char));

    ipcache_high = (long) (((float) Config.ipcache.size *
	    (float) Config.ipcache.high) / (float) 100);
    ipcache_low = (long) (((float) Config.ipcache.size *
	    (float) Config.ipcache.low) / (float) 100);
    cachemgrRegister("ipcache",
	"IP Cache Stats and Contents",
	stat_ipcache_get, 0);
}

int
ipcacheUnregister(const char *name, void *data)
{
    ipcache_entry *i = NULL;
    struct _ip_pending *p = NULL;
    int n = 0;
    debug(14, 3) ("ipcacheUnregister: name '%s'\n", name);
    if ((i = ipcache_get(name)) == NULL)
	return 0;
    if (i->status == IP_PENDING || i->status == IP_DISPATCHED) {
	for (p = i->pending_head; p; p = p->next) {
	    if (p->handlerData != data)
		continue;
	    p->handler = NULL;
	    n++;
	}
    }
    assert(n > 0);
    debug(14, 3) ("ipcacheUnregister: unregistered %d handlers\n", n);
    return n;
}

const ipcache_addrs *
ipcache_gethostbyname(const char *name, int flags)
{
    ipcache_entry *i = NULL;
    ipcache_addrs *addrs;

    if (!name)
	fatal_dump("ipcache_gethostbyname: NULL name");
    debug(14, 3) ("ipcache_gethostbyname: '%s', flags=%x\n", name, flags);
    IpcacheStats.requests++;
    if ((i = ipcache_get(name))) {
	if (ipcacheExpiredEntry(i)) {
	    ipcache_release(i);
	    i = NULL;
	}
    }
    if (i) {
	if (i->status == IP_NEGATIVE_CACHED) {
	    IpcacheStats.negative_hits++;
	    dns_error_message = i->error_message;
	    return NULL;
	} else {
	    IpcacheStats.hits++;
	    i->lastref = squid_curtime;
	    return &i->addrs;
	}
    }
    if ((addrs = ipcacheCheckNumeric(name)))
	return addrs;
    IpcacheStats.misses++;
    if (flags & IP_LOOKUP_IF_MISS)
	ipcache_nbgethostbyname(name, dummy_handler, NULL);
    return NULL;
}

static void
ipcacheStatPrint(ipcache_entry * i, StoreEntry * sentry)
{
    int k;
    storeAppendPrintf(sentry, " %-32.32s  %c%c %6d %6d %2d(%2d)",
	i->name,
	ipcache_status_char[i->status],
	i->locks ? 'L' : ' ',
	(int) (squid_curtime - i->lastref),
	(int) (i->expires - squid_curtime),
	(int) i->addrs.count,
	(int) i->addrs.badcount);
    for (k = 0; k < (int) i->addrs.count; k++)
	storeAppendPrintf(sentry, " %15s-%3s", inet_ntoa(i->addrs.in_addrs[k]),
	    i->addrs.bad_mask[k] ? "BAD" : "OK ");
    storeAppendPrintf(sentry, "\n");
}

/* process objects list */
void
stat_ipcache_get(StoreEntry * sentry)
{
    dlink_node *m;
    assert(ip_table != NULL);
    storeAppendPrintf(sentry, "IP Cache Statistics:\n");
    storeAppendPrintf(sentry, "IPcache Entries: %d\n",
	meta_data.ipcache_count);
    storeAppendPrintf(sentry, "IPcache Requests: %d\n",
	IpcacheStats.requests);
    storeAppendPrintf(sentry, "IPcache Hits: %d\n",
	IpcacheStats.hits);
    storeAppendPrintf(sentry, "IPcache Pending Hits: %d\n",
	IpcacheStats.pending_hits);
    storeAppendPrintf(sentry, "IPcache Negative Hits: %d\n",
	IpcacheStats.negative_hits);
    storeAppendPrintf(sentry, "IPcache Misses: %d\n",
	IpcacheStats.misses);
    storeAppendPrintf(sentry, "Blocking calls to gethostbyname(): %d\n",
	IpcacheStats.ghbn_calls);
    storeAppendPrintf(sentry, "Attempts to release locked entries: %d\n",
	IpcacheStats.release_locked);
    storeAppendPrintf(sentry, "pending queue length: %d\n", queue_length);
    storeAppendPrintf(sentry, "\n\n");
    storeAppendPrintf(sentry, "IP Cache Contents:\n\n");
    storeAppendPrintf(sentry, " %-29.29s %5s %6s %6s %1s\n",
	"Hostname",
	"Flags",
	"lstref",
	"TTL",
	"N");
    for (m = lru_list.head; m; m = m->next)
	ipcacheStatPrint(m->data, sentry);
}

static void
dummy_handler(const ipcache_addrs * addrsnotused, void *datanotused)
{
    return;
}

static int
ipcacheHasPending(ipcache_entry * i)
{
    struct _ip_pending *p = NULL;
    if (i->status != IP_PENDING)
	return 0;
    for (p = i->pending_head; p; p = p->next)
	if (p->handler)
	    return 1;
    return 0;
}

void
ipcacheReleaseInvalid(const char *name)
{
    ipcache_entry *i;
    if ((i = ipcache_get(name)) == NULL)
	return;
    if (i->status != IP_NEGATIVE_CACHED)
	return;
    ipcache_release(i);
}

void
ipcacheInvalidate(const char *name)
{
    ipcache_entry *i;
    if ((i = ipcache_get(name)) == NULL)
	return;
    i->expires = squid_curtime;
    /* NOTE, don't call ipcache_release here becuase we might be here due
     * to a thread started from ipcache_call_pending() which will cause a
     * FMR */
}

ipcache_addrs *
ipcacheCheckNumeric(const char *name)
{
    struct in_addr ip;
    /* check if it's already a IP address in text form. */
    if (!safe_inet_addr(name, &ip))
	return NULL;
    static_addrs.count = 1;
    static_addrs.cur = 0;
    static_addrs.in_addrs[0].s_addr = ip.s_addr;
    static_addrs.bad_mask[0] = FALSE;
    static_addrs.badcount = 0;
    return &static_addrs;
}

static void
ipcacheLockEntry(ipcache_entry * i)
{
    if (i->locks++ == 0) {
	dlinkDelete(&i->lru, &lru_list);
	dlinkAdd(i, &i->lru, &lru_list);
    }
}

static void
ipcacheUnlockEntry(ipcache_entry * i)
{
    assert(i->locks > 0);
    i->locks--;
    if (ipcacheExpiredEntry(i))
	ipcache_release(i);
}

void
ipcacheCycleAddr(const char *name)
{
    ipcache_entry *i;
    ipcache_addrs *ia;
    unsigned char fullcircle;
    if ((i = ipcache_get(name)) == NULL)
	return;
    if (i->status != IP_CACHED)
	return;
    ia = &i->addrs;
    fullcircle = ia->cur;
    while (ia->bad_mask[ia->cur]) {
	if (++ia->cur == ia->count)
	    ia->cur = 0;
	if (ia->cur == fullcircle) {	/* All bad, just use next one */
	    if (++ia->cur == ia->count)
		ia->cur = 0;
	    break;
	}
    }
}

/* "MarkBad" function must leave the "cur" pointer at the next
 * available good address, or the next bad address, in the list.
 * This simulates the functionality of RemoveBadAddr() which it
 * replaces.  Marking, instead of removing, allows bad addresses
 * to be retried as a last resort before returning an error to
 * the user.
 */
void
ipcacheMarkBadAddr(const char *name, struct in_addr addr)
{
    ipcache_entry *i;
    ipcache_addrs *ia;
    int k;
    if ((i = ipcache_get(name)) == NULL)
	return;
    ia = &i->addrs;
    for (k = 0; k < (int) ia->count; k++) {
	if (ia->in_addrs[k].s_addr == addr.s_addr)
	    break;
    }
    if (k == (int) ia->count)
	return;
    if (!ia->bad_mask[k]) {
	ia->bad_mask[k] = TRUE;
	ia->badcount++;
	debug(14, 2) ("ipcacheMarkBadAddr: %s [%s]\n",
	    name, inet_ntoa(ia->in_addrs[k]));
	if (ia->badcount != ia->count) {
	    /* at least one good address left */
	    i->expires = squid_curtime + Config.positiveDnsTtl;
	    while (ia->bad_mask[ia->cur])
		if (++ia->cur == ia->count)
		    ia->cur = 0;
	    return;
	}
    }
    if (++ia->cur == ia->count)
	ia->cur = 0;
}

void
ipcacheMarkGoodAddr(const char *name, struct in_addr addr)
{
    ipcache_entry *i;
    ipcache_addrs *ia;
    int k;
    if ((i = ipcache_get(name)) == NULL)
	return;
    ia = &i->addrs;
    for (k = 0; k < (int) ia->count; k++) {
	if (ia->in_addrs[k].s_addr == addr.s_addr)
	    break;
    }
    if (k == (int) ia->count)
	return;
    i->expires = squid_curtime + Config.positiveDnsTtl;
    if (ia->bad_mask[k]) {
	ia->bad_mask[k] = FALSE;
	ia->badcount--;
	i->expires = squid_curtime + Config.positiveDnsTtl;
	debug(14, 2) ("ipcacheMarkGoodAddr: %s [%s]\n",
	    name, inet_ntoa(ia->in_addrs[k]));
    }
}

void
ipcacheFreeMemory(void)
{
    ipcache_entry *i;
    ipcache_entry **list;
    int k = 0;
    int j;
    list = xcalloc(meta_data.ipcache_count, sizeof(ipcache_entry *));
    i = (ipcache_entry *) hash_first(ip_table);
    while (i && k < meta_data.ipcache_count) {
	*(list + k) = i;
	k++;
	i = (ipcache_entry *) hash_next(ip_table);
    }
    for (j = 0; j < k; j++) {
	i = *(list + j);
	safe_free(i->addrs.in_addrs);
	safe_free(i->addrs.bad_mask);
	safe_free(i->name);
	safe_free(i->error_message);
	safe_free(i);
    }
    xfree(list);
    hashFreeMemory(ip_table);
    ip_table = NULL;
}

static void
ipcacheChangeKey(ipcache_entry * i)
{
    static int index = 0;
    LOCAL_ARRAY(char, new_key, 256);
    hash_link *table_entry = hash_lookup(ip_table, i->name);
    if (table_entry == NULL) {
	debug(14, 0) ("ipcacheChangeKey: Could not find key '%s'\n", i->name);
	return;
    }
    assert(i == (ipcache_entry *) table_entry);
    if (hash_remove_link(ip_table, table_entry)) {
	debug_trap("ipcacheChangeKey: hash_remove_link() failed\n");
	return;
    }
    snprintf(new_key, 256, "%d/", ++index);
    strncat(new_key, i->name, 128);
    debug(14, 1) ("ipcacheChangeKey: from '%s' to '%s'\n", i->name, new_key);
    safe_free(i->name);
    i->name = xstrdup(new_key);
    hash_join(ip_table, (hash_link *) i);
}

/* call during reconfigure phase to clear out all the 
 * pending and dispatched reqeusts that got lost */
void
ipcache_restart(void)
{
    ipcache_entry *this;
    ipcache_entry *next;
    assert(ip_table != NULL);
    while (ipcacheDequeue());
    next = (ipcache_entry *) hash_first(ip_table);
    while ((this = next) != NULL) {
	next = (ipcache_entry *) hash_next(ip_table);
	if (this->status == IP_CACHED)
	    continue;
	if (this->status == IP_NEGATIVE_CACHED)
	    continue;
#if DONT
	/* else its PENDING or DISPATCHED; there are no dnsservers
	 * running, so abort it */
	this->status = IP_NEGATIVE_CACHED;
	ipcache_release(this);
#endif
    }
    /* recalculate these while we're at it */
    ipcache_high = (long) (((float) Config.ipcache.size *
	    (float) Config.ipcache.high) / (float) 100);
    ipcache_low = (long) (((float) Config.ipcache.size *
	    (float) Config.ipcache.low) / (float) 100);
}

#ifdef SQUID_SNMP

int 
ipcache_getMax()
{
    int i = 0;
    dlink_node *m = NULL;
    for (m = lru_list.head; m && m->data; m = m->next)
	i++;
    return i;
}

variable_list *
snmp_ipcacheFn(variable_list * Var, long *ErrP)
{
    variable_list *Answer;
    ipcache_entry *IPc = NULL;
    dlink_node *m = NULL;
    int cnt = 1;
    debug(49, 5) ("snmp_ipcacheFn: Processing request with %d.%d!\n", Var->name[11], Var->name[12]);

    cnt = Var->name[12];

    for (m = lru_list.head; --cnt && m; m = m->next);
    debug(49, 5) ("snmp_ipcacheFn: cnt now=%d m=%x, data=%x\n", cnt, m->data);
    if (!m || !(IPc = m->data)) {
	*ErrP = SNMP_ERR_NOSUCHNAME;
	return NULL;
    }
    Answer = snmp_var_new(Var->name, Var->name_length);
    *ErrP = SNMP_ERR_NOERROR;
    Answer->val.integer = xmalloc(Answer->val_len);
    Answer->val_len = sizeof(long);
    switch (Var->name[11]) {
    case NET_IPC_ID:
	Answer->type = SMI_INTEGER;
	*(Answer->val.integer) = Var->name[12];
	break;
    case NET_IPC_NAME:
	xfree(Answer->val.integer);
	Answer->type = SMI_STRING;
	Answer->val_len = strlen(IPc->name);
	Answer->val.string = xstrdup(IPc->name);
	break;
    case NET_IPC_IP:
	Answer->type = SMI_IPADDRESS;
	*(Answer->val.integer) = IPc->addrs.in_addrs[0].s_addr;		/* first one only */
	break;
    case NET_IPC_STATE:
	Answer->type = SMI_INTEGER;
	*(Answer->val.integer) = IPc->status;
	break;
    default:
	*ErrP = SNMP_ERR_NOSUCHNAME;
	snmp_var_free(Answer);
	xfree(Answer->val.integer);
	return (NULL);
    }
    return Answer;
}
#endif
