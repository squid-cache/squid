/*
 * $Id: ipcache.cc,v 1.47 1996/08/28 17:22:07 wessels Exp $
 *
 * DEBUG: section 14    IP Cache
 * AUTHOR: Harvest Derived
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

#define MAX_LINELEN (4096)

#define MAX_IP		 1024	/* Maximum cached IP */
#define IP_LOW_WATER       90
#define IP_HIGH_WATER      95
#define MAX_HOST_NAME	  256

struct _ip_pending {
    int fd;
    IPH handler;
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
    int avg_svc_time;
    int ghbn_calls;		/* # calls to blocking gethostbyname() */
} IpcacheStats;

static int ipcache_testname _PARAMS((void));
static int ipcache_compareLastRef _PARAMS((ipcache_entry **, ipcache_entry **));
static int ipcache_reverseLastRef _PARAMS((ipcache_entry **, ipcache_entry **));
static int ipcache_dnsHandleRead _PARAMS((int, dnsserver_t *));
static ipcache_entry *ipcache_parsebuffer _PARAMS((char *buf, dnsserver_t *));
static void ipcache_release _PARAMS((ipcache_entry *));
static ipcache_entry *ipcache_GetFirst _PARAMS((void));
static ipcache_entry *ipcache_GetNext _PARAMS((void));
static ipcache_entry *ipcache_create _PARAMS((void));
static void ipcache_add_to_hash _PARAMS((ipcache_entry *));
static void ipcache_call_pending _PARAMS((ipcache_entry *));
static void ipcache_call_pending_badname _PARAMS((int fd, IPH handler, void *));
static void ipcache_add _PARAMS((char *, ipcache_entry *, struct hostent *, int));
static int ipcacheHasPending _PARAMS((ipcache_entry *));
static ipcache_entry *ipcache_get _PARAMS((char *));
static int dummy_handler _PARAMS((int, struct hostent * hp, void *));
static int ipcacheExpiredEntry _PARAMS((ipcache_entry *));
static void ipcacheAddPending _PARAMS((ipcache_entry *, int fd, IPH, void *));
static void ipcacheEnqueue _PARAMS((ipcache_entry *));
static void *ipcacheDequeue _PARAMS((void));
static void ipcache_dnsDispatch _PARAMS((dnsserver_t *, ipcache_entry *));
static struct hostent *ipcacheCheckNumeric _PARAMS((char *name));
static void ipcacheStatPrint _PARAMS((ipcache_entry *, StoreEntry *));

static struct hostent *static_result = NULL;
static HashID ip_table = 0;
static struct ipcacheQueueData *ipcacheQueueHead = NULL;
static struct ipcacheQueueData **ipcacheQueueTailP = &ipcacheQueueHead;

static char ipcache_status_char[] =
{
    'C',
    'N',
    'P',
    'D'
};

long ipcache_low = 180;
long ipcache_high = 200;

static void ipcacheEnqueue(i)
     ipcache_entry *i;
{
    struct ipcacheQueueData *new = xcalloc(1, sizeof(struct ipcacheQueueData));
    new->i = i;
    *ipcacheQueueTailP = new;
    ipcacheQueueTailP = &new->next;
}

static void *ipcacheDequeue()
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
    }
    return i;
}

static int ipcache_testname()
{
    wordlist *w = NULL;
    debug(14, 1, "Performing DNS Tests...\n");
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
static void ipcache_release(i)
     ipcache_entry *i;
{
    hash_link *table_entry = NULL;
    int k;

    if ((table_entry = hash_lookup(ip_table, i->name)) == NULL) {
	debug(14, 0, "ipcache_release: Could not find key '%s'\n", i->name);
	return;
    }
    if (i != (ipcache_entry *) table_entry)
	fatal_dump("ipcache_release: i != table_entry!");
    if (i->status == IP_PENDING) {
	debug(14, 1, "ipcache_release: Someone called on a PENDING entry\n");
	return;
    }
    if (i->status == IP_DISPATCHED) {
	debug(14, 1, "ipcache_release: Someone called on a DISPATCHED entry\n");
	return;
    }
    if (hash_remove_link(ip_table, table_entry)) {
	debug(14, 0, "ipcache_release: hash_remove_link() failed for '%s'\n",
	    i->name);
	return;
    }
    if (i->status == IP_CACHED) {
	for (k = 0; k < (int) i->addr_count; k++)
	    safe_free(*(i->entry.h_addr_list + k));
	safe_free(i->entry.h_addr_list);
	for (k = 0; k < (int) i->alias_count; k++)
	    safe_free(i->entry.h_aliases[k]);
	safe_free(i->entry.h_aliases);
	safe_free(i->entry.h_name);
	debug(14, 5, "ipcache_release: Released IP cached record for '%s'.\n",
	    i->name);
    }
    safe_free(i->name);
    safe_free(i->error_message);
    memset(i, '\0', sizeof(ipcache_entry));
    safe_free(i);
    --meta_data.ipcache_count;
    return;
}

/* return match for given name */
static ipcache_entry *ipcache_get(name)
     char *name;
{
    hash_link *e;
    static ipcache_entry *i;

    i = NULL;
    if (ip_table) {
	if ((e = hash_lookup(ip_table, name)) != NULL)
	    i = (ipcache_entry *) e;
    }
    return i;
}

/* get the first ip entry in the storage */
static ipcache_entry *ipcache_GetFirst()
{
    return (ipcache_entry *) hash_first(ip_table);
}

/* get the next ip entry in the storage for a given search pointer */
static ipcache_entry *ipcache_GetNext()
{
    return (ipcache_entry *) hash_next(ip_table);
}

static int ipcache_compareLastRef(e1, e2)
     ipcache_entry **e1, **e2;
{
    if (!e1 || !e2)
	fatal_dump(NULL);
    if ((*e1)->lastref > (*e2)->lastref)
	return (1);
    if ((*e1)->lastref < (*e2)->lastref)
	return (-1);
    return (0);
}

static int ipcache_reverseLastRef(e1, e2)
     ipcache_entry **e1, **e2;
{
    if ((*e1)->lastref < (*e2)->lastref)
	return (1);
    if ((*e1)->lastref > (*e2)->lastref)
	return (-1);
    return (0);
}

static int ipcacheExpiredEntry(i)
     ipcache_entry *i;
{
    if (i->status == IP_PENDING)
	return 0;
    if (i->status == IP_DISPATCHED)
	return 0;
    if (i->expires > squid_curtime)
	return 0;
    return 1;
}

/* finds the LRU and deletes */
int ipcache_purgelru()
{
    ipcache_entry *i = NULL;
    int local_ip_count = 0;
    int local_ip_notpending_count = 0;
    int removed = 0;
    int k;
    ipcache_entry **LRU_list = NULL;
    int LRU_list_count = 0;

    LRU_list = xcalloc(meta_data.ipcache_count, sizeof(ipcache_entry *));

    for (i = ipcache_GetFirst(); i; i = ipcache_GetNext()) {
	if (ipcacheExpiredEntry(i)) {
	    ipcache_release(i);
	    removed++;
	    continue;
	}
	local_ip_count++;

	if (LRU_list_count == meta_data.ipcache_count)
	    break;
	if (i->status == IP_PENDING)
	    continue;
	if (i->status == IP_DISPATCHED)
	    continue;
	local_ip_notpending_count++;
	LRU_list[LRU_list_count++] = i;
    }

    debug(14, 3, "ipcache_purgelru: ipcache_count: %5d\n", meta_data.ipcache_count);
    debug(14, 3, "                  actual count : %5d\n", local_ip_count);
    debug(14, 3, "                   high W mark : %5d\n", ipcache_high);
    debug(14, 3, "                   low  W mark : %5d\n", ipcache_low);
    debug(14, 3, "                   not pending : %5d\n", local_ip_notpending_count);
    debug(14, 3, "                LRU candidates : %5d\n", LRU_list_count);

    /* sort LRU candidate list */
    qsort((char *) LRU_list,
	LRU_list_count,
	sizeof(ipcache_entry *),
	(QS) ipcache_compareLastRef);
    for (k = 0; k < LRU_list_count; k++) {
	if (meta_data.ipcache_count < ipcache_low)
	    break;
	if (LRU_list[k] == NULL)
	    break;
	ipcache_release(LRU_list[k]);
	removed++;
    }

    debug(14, 3, "                       removed : %5d\n", removed);
    safe_free(LRU_list);
    return (removed > 0) ? 0 : -1;
}


/* create blank ipcache_entry */
static ipcache_entry *ipcache_create()
{
    static ipcache_entry *new;

    if (meta_data.ipcache_count > ipcache_high) {
	if (ipcache_purgelru() < 0)
	    debug(14, 0, "HELP!! IP Cache is overflowing!\n");
    }
    meta_data.ipcache_count++;
    new = xcalloc(1, sizeof(ipcache_entry));
    /* set default to 4, in case parser fail to get token $h_length from
     * dnsserver. */
    new->entry.h_length = 4;
    new->expires = squid_curtime + Config.negativeDnsTtl;
    return new;

}

static void ipcache_add_to_hash(i)
     ipcache_entry *i;
{
    if (hash_join(ip_table, (hash_link *) i)) {
	debug(14, 1, "ipcache_add_to_hash: Cannot add %s (%p) to hash table %d.\n",
	    i->name, i, ip_table);
    }
    debug(14, 5, "ipcache_add_to_hash: name <%s>\n", i->name);
}


static void ipcache_add(name, i, hp, cached)
     char *name;
     ipcache_entry *i;
     struct hostent *hp;
     int cached;
{
    int addr_count;
    int alias_count;
    int k;

    if (ipcache_get(name))
	fatal_dump("ipcache_add: somebody adding a duplicate!");
    debug(14, 10, "ipcache_add: Adding name '%s' (%s).\n", name,
	cached ? "cached" : "not cached");
    i->name = xstrdup(name);
    if (cached) {
	/* count for IPs */
	addr_count = 0;
	while ((addr_count < 255) && *(hp->h_addr_list + addr_count))
	    ++addr_count;

	i->addr_count = (unsigned char) addr_count;

	/* count for Alias */
	alias_count = 0;
	if (hp->h_aliases)
	    while ((alias_count < 255) && hp->h_aliases[alias_count])
		++alias_count;

	i->alias_count = (unsigned char) alias_count;

	/* copy ip addresses information */
	i->entry.h_addr_list = xcalloc(addr_count + 1, sizeof(char *));
	for (k = 0; k < addr_count; k++) {
	    *(i->entry.h_addr_list + k) = xcalloc(1, hp->h_length);
	    xmemcpy(*(i->entry.h_addr_list + k), *(hp->h_addr_list + k), hp->h_length);
	}

	if (alias_count) {
	    /* copy aliases information */
	    i->entry.h_aliases = xcalloc(alias_count + 1, sizeof(char *));
	    for (k = 0; k < alias_count; k++) {
		i->entry.h_aliases[k] = xcalloc(1, strlen(hp->h_aliases[k]) + 1);
		strcpy(i->entry.h_aliases[k], hp->h_aliases[k]);
	    }
	}
	i->entry.h_length = hp->h_length;
	i->entry.h_name = xstrdup(hp->h_name);
	i->status = IP_CACHED;
	i->expires = squid_curtime + Config.positiveDnsTtl;
    } else {
	i->status = IP_NEGATIVE_CACHED;
	i->expires = squid_curtime + Config.negativeDnsTtl;
    }
    ipcache_add_to_hash(i);
}

/* walks down the pending list, calling handlers */
static void ipcache_call_pending(i)
     ipcache_entry *i;
{
    struct _ip_pending *p = NULL;
    int nhandler = 0;

    i->lastref = squid_curtime;

    while (i->pending_head != NULL) {
	p = i->pending_head;
	i->pending_head = p->next;
	if (p->handler) {
	    nhandler++;
	    dns_error_message = i->error_message;
	    p->handler(p->fd,
		(i->status == IP_CACHED) ? &(i->entry) : NULL,
		p->handlerData);
	}
	memset(p, '\0', sizeof(struct _ip_pending));
	safe_free(p);
    }
    i->pending_head = NULL;	/* nuke list */
    debug(14, 10, "ipcache_call_pending: Called %d handlers.\n", nhandler);
}

static void ipcache_call_pending_badname(fd, handler, data)
     int fd;
     IPH handler;
     void *data;
{
    debug(14, 0, "ipcache_call_pending_badname: Bad Name: Calling handler with NULL result.\n");
    handler(fd, NULL, data);
}

static ipcache_entry *ipcache_parsebuffer(inbuf, dnsData)
     char *inbuf;
     dnsserver_t *dnsData;
{
    char *buf = xstrdup(inbuf);
    char *token;
    static ipcache_entry i;
    int k;
    int ipcount;
    int aliascount;
    debug(14, 5, "ipcache_parsebuffer: parsing:\n%s", inbuf);
    for (token = strtok(buf, w_space); token; token = strtok(NULL, w_space)) {
	if (!strcmp(token, "$end")) {
	    break;
	} else if (!strcmp(token, "$alive")) {
	    dnsData->answer = squid_curtime;
	} else if (!strcmp(token, "$fail")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $fail");
	} else if (!strcmp(token, "$message")) {
	    if ((token = strtok(NULL, "\n")) == NULL)
		fatal_dump("Invalid $message");
	    i.error_message = xstrdup(token);
	} else if (!strcmp(token, "$name")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $name");
	} else if (!strcmp(token, "$h_name")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $h_name");
	    i.entry.h_name = xstrdup(token);
	} else if (!strcmp(token, "$h_len")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $h_len");
	    i.entry.h_length = atoi(token);
	} else if (!strcmp(token, "$ipcount")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $ipcount");
	    ipcount = atoi(token);
	    i.addr_count = (unsigned char) ipcount;
	    if (ipcount == 0) {
		i.entry.h_addr_list = NULL;
	    } else {
		i.entry.h_addr_list = xcalloc(ipcount + 1, sizeof(char *));
	    }
	    for (k = 0; k < ipcount; k++) {
		if ((token = strtok(NULL, w_space)) == NULL)
		    fatal_dump("Invalid IP address");
		*(i.entry.h_addr_list + k) = xcalloc(1, i.entry.h_length);
		*((u_num32 *) (void *) *(i.entry.h_addr_list + k))
		    = inet_addr(token);
	    }
	} else if (!strcmp(token, "$aliascount")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $aliascount");
	    aliascount = atoi(token);
	    i.alias_count = (unsigned char) aliascount;
	    if (aliascount == 0) {
		i.entry.h_aliases = NULL;
	    } else {
		i.entry.h_aliases = xcalloc(aliascount, sizeof(char *));
	    }
	    for (k = 0; k < aliascount; k++) {
		if ((token = strtok(NULL, w_space)) == NULL)
		    fatal_dump("Invalid alias");
		*(i.entry.h_aliases + k) = xstrdup(token);
	    }
	} else if (!strcmp(token, "$ttl")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $ttl");
	    i.expires = squid_curtime + atoi(token);
	} else {
	    fatal_dump("Invalid dnsserver output");
	}
    }
    xfree(buf);
    return &i;
}

static int ipcache_dnsHandleRead(fd, dnsData)
     int fd;
     dnsserver_t *dnsData;
{
    int len;
    int svc_time;
    int n;
    ipcache_entry *i = NULL;
    ipcache_entry *x = NULL;

    len = read(fd,
	dnsData->ip_inbuf + dnsData->offset,
	dnsData->size - dnsData->offset);
    debug(14, 5, "ipcache_dnsHandleRead: Result from DNS ID %d (%d bytes)\n",
	dnsData->id, len);
    if (len <= 0) {
	debug(14, dnsData->flags & DNS_FLAG_CLOSING ? 5 : 1,
	    "FD %d: Connection from DNSSERVER #%d is closed, disabling\n",
	    fd, dnsData->id);
	dnsData->flags = 0;
	comm_set_select_handler(fd,
	    COMM_SELECT_WRITE,
	    NULL,
	    NULL);
	comm_close(fd);
	return 0;
    }
    n = ++IpcacheStats.replies;
    dnsData->offset += len;
    dnsData->ip_inbuf[dnsData->offset] = '\0';

    if (strstr(dnsData->ip_inbuf, "$end\n")) {
	/* end of record found */
	svc_time = tvSubMsec(dnsData->dispatch_time, current_time);
	if (n > IPCACHE_AV_FACTOR)
	    n = IPCACHE_AV_FACTOR;
	IpcacheStats.avg_svc_time
	    = (IpcacheStats.avg_svc_time * (n - 1) + svc_time) / n;
	if ((x = ipcache_parsebuffer(dnsData->ip_inbuf, dnsData)) == NULL) {
	    debug(14, 0, "ipcache_dnsHandleRead: ipcache_parsebuffer failed?!\n");
	} else {
	    dnsData->offset = 0;
	    dnsData->ip_inbuf[0] = '\0';
	    i = dnsData->data;
	    i->addr_count = x->addr_count;
	    i->alias_count = x->alias_count;
	    i->entry = x->entry;
	    i->error_message = x->error_message;
	    ipcache_call_pending(i);
	}
    }
    if (dnsData->offset == 0) {
	dnsData->data = NULL;
	dnsData->flags &= ~DNS_FLAG_BUSY;
    }
    /* reschedule */
    comm_set_select_handler(dnsData->inpipe,
	COMM_SELECT_READ,
	(PF) ipcache_dnsHandleRead,
	dnsData);
    while ((dnsData = dnsGetFirstAvailable()) && (i = ipcacheDequeue()))
	ipcache_dnsDispatch(dnsData, i);
    return 0;
}

static void ipcacheAddPending(i, fd, handler, handlerData)
     ipcache_entry *i;
     int fd;
     IPH handler;
     void *handlerData;
{
    struct _ip_pending *pending = xcalloc(1, sizeof(struct _ip_pending));
    struct _ip_pending **I = NULL;
    i->lastref = squid_curtime;
    pending->fd = fd;
    pending->handler = handler;
    pending->handlerData = handlerData;
    for (I = &(i->pending_head); *I; I = &((*I)->next));
    *I = pending;
}

void ipcache_nbgethostbyname(name, fd, handler, handlerData)
     char *name;
     int fd;
     IPH handler;
     void *handlerData;
{
    ipcache_entry *i = NULL;
    dnsserver_t *dnsData = NULL;
    struct hostent *hp = NULL;

    if (!handler)
	fatal_dump("ipcache_nbgethostbyname: NULL handler");

    debug(14, 4, "ipcache_nbgethostbyname: FD %d: Name '%s'.\n", fd, name);
    IpcacheStats.requests++;

    if (name == NULL || name[0] == '\0') {
	debug(14, 4, "ipcache_nbgethostbyname: Invalid name!\n");
	ipcache_call_pending_badname(fd, handler, handlerData);
	return;
    }
    if ((hp = ipcacheCheckNumeric(name))) {
	handler(fd, hp, handlerData);
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
	debug(14, 5, "ipcache_nbgethostbyname: MISS for '%s'\n", name);
	IpcacheStats.misses++;
	i = ipcache_create();
	i->name = xstrdup(name);
	i->status = IP_PENDING;
	ipcacheAddPending(i, fd, handler, handlerData);
	ipcache_add_to_hash(i);
    } else if (i->status == IP_CACHED || i->status == IP_NEGATIVE_CACHED) {
	/* HIT */
	debug(14, 4, "ipcache_nbgethostbyname: HIT for '%s'\n", name);
	if (i->status == IP_NEGATIVE_CACHED)
	    IpcacheStats.negative_hits++;
	else
	    IpcacheStats.hits++;
	ipcacheAddPending(i, fd, handler, handlerData);
	ipcache_call_pending(i);
	return;
    } else if (i->status == IP_PENDING || i->status == IP_DISPATCHED) {
	debug(14, 4, "ipcache_nbgethostbyname: PENDING for '%s'\n", name);
	IpcacheStats.pending_hits++;
	ipcacheAddPending(i, fd, handler, handlerData);
	return;
    } else {
	fatal_dump("ipcache_nbgethostbyname: BAD ipcache_entry status");
    }

    /* for HIT, PENDING, DISPATCHED we've returned.  For MISS we continue */

    if ((dnsData = dnsGetFirstAvailable()))
	ipcache_dnsDispatch(dnsData, i);
    else
	ipcacheEnqueue(i);
}

static void ipcache_dnsDispatch(dns, i)
     dnsserver_t *dns;
     ipcache_entry *i;
{
    char *buf = NULL;
    if (!ipcacheHasPending(i)) {
	debug(14, 0, "ipcache_dnsDispatch: skipping '%s' because no handler.\n",
	    i->name);
	i->status = IP_NEGATIVE_CACHED;
	ipcache_release(i);
	return;
    }
    i->status = IP_DISPATCHED;
    buf = xcalloc(1, 256);
    sprintf(buf, "%1.254s\n", i->name);
    dns->flags |= DNS_FLAG_BUSY;
    dns->data = i;
    comm_write(dns->outpipe,
	buf,
	strlen(buf),
	0,			/* timeout */
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	xfree);
    comm_set_select_handler(dns->outpipe,
	COMM_SELECT_READ,
	(PF) ipcache_dnsHandleRead,
	dns);
    debug(14, 5, "ipcache_dnsDispatch: Request sent to DNS server #%d.\n",
	dns->id);
    dns->dispatch_time = current_time;
    DnsStats.requests++;
    DnsStats.hist[dns->id - 1]++;
}


/* initialize the ipcache */
void ipcache_init()
{

    debug(14, 3, "Initializing IP Cache...\n");

    memset(&IpcacheStats, '\0', sizeof(IpcacheStats));

    /* test naming lookup */
    if (!opt_dns_tests) {
	debug(14, 4, "ipcache_init: Skipping DNS name lookup tests.\n");
    } else if (!ipcache_testname()) {
	fatal("ipcache_init: DNS name lookup tests failed/");
    } else {
	debug(14, 1, "Successful DNS name lookup tests...\n");
    }

    ip_table = hash_create(urlcmp, 229, hash_string);	/* small hash table */
    /* init static area */
    static_result = xcalloc(1, sizeof(struct hostent));
    static_result->h_length = 4;
    static_result->h_addr_list = xcalloc(2, sizeof(char *));
    *(static_result->h_addr_list + 0) = xcalloc(1, 4);
    static_result->h_name = xcalloc(1, MAX_HOST_NAME + 1);

    ipcache_high = (long) (((float) MAX_IP *
	    (float) IP_HIGH_WATER) / (float) 100);
    ipcache_low = (long) (((float) MAX_IP *
	    (float) IP_LOW_WATER) / (float) 100);
}

/* clean up the pending entries in dnsserver */
/* return 1 if we found the host, 0 otherwise */
int ipcache_unregister(name, fd)
     char *name;
     int fd;
{
    ipcache_entry *i = NULL;
    struct _ip_pending *p = NULL;
    int n = 0;

    debug(14, 3, "ipcache_unregister: FD %d, name '%s'\n", fd, name);
    if ((i = ipcache_get(name)) == NULL)
	return 0;
    if (i->status == IP_PENDING || i->status == IP_DISPATCHED) {
	for (p = i->pending_head; p; p = p->next) {
	    if (p->fd == fd && p->handler != NULL) {
		p->handler = NULL;
		p->fd = -1;
		n++;
	    }
	}
    }
    debug(14, 3, "ipcache_unregister: unregistered %d handlers\n", n);
    return n;
}

struct hostent *ipcache_gethostbyname(name, flags)
     char *name;
     int flags;
{
    ipcache_entry *i = NULL;
    struct hostent *hp = NULL;

    if (!name)
	fatal_dump("ipcache_gethostbyname: NULL name");
    IpcacheStats.requests++;
    if ((i = ipcache_get(name))) {
	if (ipcacheExpiredEntry(i)) {
	    ipcache_release(i);
	    i = NULL;
	}
    }
    if (i) {
	if (i->status == IP_PENDING || i->status == IP_DISPATCHED) {
	    IpcacheStats.pending_hits++;
	    return NULL;
	} else if (i->status == IP_NEGATIVE_CACHED) {
	    IpcacheStats.negative_hits++;
	    dns_error_message = i->error_message;
	    return NULL;
	} else {
	    IpcacheStats.hits++;
	    i->lastref = squid_curtime;
	    return &i->entry;
	}
    }
    IpcacheStats.misses++;
    if ((hp = ipcacheCheckNumeric(name)))
	return hp;
    if (flags & IP_BLOCKING_LOOKUP) {
	IpcacheStats.ghbn_calls++;
	hp = gethostbyname(name);
	if (hp && hp->h_name && (hp->h_name[0] != '\0') && ip_table) {
	    /* good address, cached */
	    ipcache_add(name, ipcache_create(), hp, 1);
	    i = ipcache_get(name);
	    i->lastref = squid_curtime;
	    i->expires = squid_curtime + Config.positiveDnsTtl;
	    return &i->entry;
	}
	/* bad address, negative cached */
	if (ip_table) {
	    ipcache_add(name, ipcache_create(), hp, 0);
	    i = ipcache_get(name);
	    i->lastref = squid_curtime;
	    i->expires = squid_curtime + Config.negativeDnsTtl;
	    return NULL;
	}
    }
    if (flags & IP_LOOKUP_IF_MISS)
	ipcache_nbgethostbyname(name, -1, dummy_handler, NULL);
    return NULL;
}

static void ipcacheStatPrint(i, sentry)
     ipcache_entry *i;
     StoreEntry *sentry;
{
    int k;
    storeAppendPrintf(sentry, " {%-32.32s  %c %6d %6d %d",
	i->name,
	ipcache_status_char[i->status],
	(int) (squid_curtime - i->lastref),
	(int) (i->expires - squid_curtime),
	i->addr_count);
    for (k = 0; k < (int) i->addr_count; k++) {
	struct in_addr addr;
	xmemcpy(&addr, i->entry.h_addr_list[k], i->entry.h_length);
	storeAppendPrintf(sentry, " %15s", inet_ntoa(addr));
    }
    for (k = 0; k < (int) i->alias_count; k++) {
	storeAppendPrintf(sentry, " %s", i->entry.h_aliases[k]);
    }
    if (i->entry.h_name && strncmp(i->name, i->entry.h_name, MAX_LINELEN)) {
	storeAppendPrintf(sentry, " %s", i->entry.h_name);
    }
    storeAppendPrintf(sentry, close_bracket);
}

/* process objects list */
void stat_ipcache_get(sentry)
     StoreEntry *sentry;
{
    int k;
    int N;
    ipcache_entry *i = NULL;
    ipcache_entry **list = NULL;
    if (!ip_table)
	return;
    storeAppendPrintf(sentry, "{IP Cache Statistics:\n");
    storeAppendPrintf(sentry, "{IPcache Entries: %d}\n",
	meta_data.ipcache_count);
    storeAppendPrintf(sentry, "{IPcache Requests: %d}\n",
	IpcacheStats.requests);
    storeAppendPrintf(sentry, "{IPcache Hits: %d}\n",
	IpcacheStats.hits);
    storeAppendPrintf(sentry, "{IPcache Pending Hits: %d}\n",
	IpcacheStats.pending_hits);
    storeAppendPrintf(sentry, "{IPcache Negative Hits: %d}\n",
	IpcacheStats.negative_hits);
    storeAppendPrintf(sentry, "{IPcache Misses: %d}\n",
	IpcacheStats.misses);
    storeAppendPrintf(sentry, "{Blocking calls to gethostbyname(): %d}\n",
	IpcacheStats.ghbn_calls);
    storeAppendPrintf(sentry, "{dnsserver avg service time: %d msec}\n",
	IpcacheStats.avg_svc_time);
    storeAppendPrintf(sentry, "}\n\n");
    storeAppendPrintf(sentry, "{IP Cache Contents:\n\n");
    storeAppendPrintf(sentry, " {%-29.29s %5s %6s %6s %1s}\n",
	"Hostname",
	"Flags",
	"lstref",
	"TTL",
	"N");
    list = xcalloc(meta_data.ipcache_count, sizeof(ipcache_entry *));
    N = 0;
    for (i = ipcache_GetFirst(); i; i = ipcache_GetNext()) {
	*(list + N) = i;
	if (++N > meta_data.ipcache_count)
	    fatal_dump("stat_ipcache_get: meta_data.ipcache_count mismatch");
    }
    qsort((char *) list,
	N,
	sizeof(ipcache_entry *),
	(QS) ipcache_reverseLastRef);
    for (k = 0; k < N; k++)
	ipcacheStatPrint(*(list + k), sentry);
    storeAppendPrintf(sentry, close_bracket);
}

static int dummy_handler(u1, u2, u3)
     int u1;
     struct hostent *u2;
     void *u3;
{
    return 0;
}

static int ipcacheHasPending(i)
     ipcache_entry *i;
{
    struct _ip_pending *p = NULL;
    if (i->status != IP_PENDING)
	return 0;
    for (p = i->pending_head; p; p = p->next)
	if (p->handler)
	    return 1;
    return 0;
}

void ipcacheReleaseInvalid(name)
     char *name;
{
    ipcache_entry *i;
    if ((i = ipcache_get(name)) == NULL)
	return;
    if (i->status != IP_NEGATIVE_CACHED)
	return;
    ipcache_release(i);
}

void ipcacheInvalidate(name)
     char *name;
{
    ipcache_entry *i;
    if ((i = ipcache_get(name)) == NULL)
	return;
    i->expires = squid_curtime;
    /* NOTE, don't call ipcache_release here becuase we might be here due
     * to a thread started from ipcache_call_pending() which will cause a
     * FMR */
}

static struct hostent *ipcacheCheckNumeric(name)
     char *name;
{
    unsigned int ip;
    /* check if it's already a IP address in text form. */
    if ((ip = inet_addr(name)) == INADDR_NONE)
	return NULL;
    *((u_num32 *) (void *) static_result->h_addr_list[0]) = ip;
    strncpy(static_result->h_name, name, MAX_HOST_NAME);
    return static_result;
}
