
/*
 * $Id: fqdncache.cc,v 1.19 1996/09/16 16:28:38 wessels Exp $
 *
 * DEBUG: section 35    FQDN Cache
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

#define MAX_FQDN		 1024	/* Maximum cached FQDN */
#define FQDN_LOW_WATER       90
#define FQDN_HIGH_WATER      95

struct _fqdn_pending {
    int fd;
    FQDNH handler;
    void *handlerData;
    struct _fqdn_pending *next;
};

struct fqdncacheQueueData {
    struct fqdncacheQueueData *next;
    fqdncache_entry *f;
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
    int ghba_calls;		/* # calls to blocking gethostbyaddr() */
} FqdncacheStats;

static int fqdncache_compareLastRef __P((fqdncache_entry **, fqdncache_entry **));
static int fqdncache_dnsHandleRead __P((int, dnsserver_t *));
static fqdncache_entry *fqdncache_parsebuffer __P((char *buf, dnsserver_t *));
static int fqdncache_purgelru __P((void));
static void fqdncache_release __P((fqdncache_entry *));
static fqdncache_entry *fqdncache_GetFirst __P((void));
static fqdncache_entry *fqdncache_GetNext __P((void));
static fqdncache_entry *fqdncache_create __P((void));
static void fqdncache_add_to_hash __P((fqdncache_entry *));
static void fqdncache_call_pending __P((fqdncache_entry *));
static void fqdncache_call_pending_badname __P((int fd, FQDNH handler, void *));
static void fqdncache_add __P((char *, fqdncache_entry *, struct hostent *, int));
static int fqdncacheHasPending __P((fqdncache_entry *));
static fqdncache_entry *fqdncache_get __P((char *));
static void dummy_handler __P((int, char *, void *));
static int fqdncacheExpiredEntry __P((fqdncache_entry *));
static void fqdncacheAddPending __P((fqdncache_entry *, int fd, FQDNH, void *));
static void fqdncacheEnqueue __P((fqdncache_entry *));
static void *fqdncacheDequeue __P((void));
static void fqdncache_dnsDispatch __P((dnsserver_t *, fqdncache_entry *));

static HashID fqdn_table = 0;
static struct fqdncacheQueueData *fqdncacheQueueHead = NULL;
static struct fqdncacheQueueData **fqdncacheQueueTailP = &fqdncacheQueueHead;

static char fqdncache_status_char[] =
{
    'C',
    'N',
    'P',
    'D'
};

long fqdncache_low = 180;
long fqdncache_high = 200;

static void
fqdncacheEnqueue(fqdncache_entry * f)
{
    struct fqdncacheQueueData *new = xcalloc(1, sizeof(struct fqdncacheQueueData));
    new->f = f;
    *fqdncacheQueueTailP = new;
    fqdncacheQueueTailP = &new->next;
}

static void *
fqdncacheDequeue()
{
    struct fqdncacheQueueData *old = NULL;
    fqdncache_entry *f = NULL;
    if (fqdncacheQueueHead) {
	f = fqdncacheQueueHead->f;
	old = fqdncacheQueueHead;
	fqdncacheQueueHead = fqdncacheQueueHead->next;
	if (fqdncacheQueueHead == NULL)
	    fqdncacheQueueTailP = &fqdncacheQueueHead;
	safe_free(old);
    }
    return f;
}

/* removes the given fqdncache entry */
static void
fqdncache_release(fqdncache_entry * f)
{
    fqdncache_entry *result = NULL;
    hash_link *table_entry = NULL;
    int k;

    if ((table_entry = hash_lookup(fqdn_table, f->name)) == NULL) {
	debug(35, 0, "fqdncache_release: Could not find key '%s'\n", f->name);
	return;
    }
    result = (fqdncache_entry *) table_entry;
    if (f != result)
	fatal_dump("fqdncache_release: expected f == result!");
    if (f->status == FQDN_PENDING) {
	debug(35, 1, "fqdncache_release: Someone called on a PENDING entry\n");
	return;
    }
    if (f->status == FQDN_DISPATCHED) {
	debug(35, 1, "fqdncache_release: Someone called on a DISPATCHED entry\n");
	return;
    }
    if (hash_remove_link(fqdn_table, table_entry)) {
	debug(35, 0, "fqdncache_release: hash_remove_link() failed for '%s'\n",
	    result->name);
	return;
    }
    if (result->status == FQDN_CACHED) {
	for (k = 0; k < (int) f->name_count; k++)
	    safe_free(f->names[k]);
	debug(35, 5, "fqdncache_release: Released FQDN record for '%s'.\n",
	    result->name);
    }
    safe_free(result->name);
    safe_free(result->error_message);
    memset(result, '\0', sizeof(fqdncache_entry));
    safe_free(result);
    --meta_data.fqdncache_count;
    return;
}

/* return match for given name */
static fqdncache_entry *
fqdncache_get(char *name)
{
    hash_link *e;
    static fqdncache_entry *f;

    f = NULL;
    if (fqdn_table) {
	if ((e = hash_lookup(fqdn_table, name)) != NULL)
	    f = (fqdncache_entry *) e;
    }
    return f;
}

static fqdncache_entry *
fqdncache_GetFirst()
{
    return (fqdncache_entry *) hash_first(fqdn_table);
}

static fqdncache_entry *
fqdncache_GetNext()
{
    return (fqdncache_entry *) hash_next(fqdn_table);
}

static int
fqdncache_compareLastRef(fqdncache_entry ** e1, fqdncache_entry ** e2)
{
    if (!e1 || !e2)
	fatal_dump(NULL);
    if ((*e1)->lastref > (*e2)->lastref)
	return (1);
    if ((*e1)->lastref < (*e2)->lastref)
	return (-1);
    return (0);
}

static int
fqdncacheExpiredEntry(fqdncache_entry * f)
{
    if (f->status == FQDN_PENDING)
	return 0;
    if (f->status == FQDN_DISPATCHED)
	return 0;
    if (f->expires > squid_curtime)
	return 0;
    return 1;
}

/* finds the LRU and deletes */
static int
fqdncache_purgelru()
{
    fqdncache_entry *f = NULL;
    int local_fqdn_count = 0;
    int local_fqdn_notpending_count = 0;
    int removed = 0;
    int k;
    fqdncache_entry **LRU_list = NULL;
    int LRU_list_count = 0;
    int LRU_cur_size = meta_data.fqdncache_count;

    LRU_list = xcalloc(LRU_cur_size, sizeof(fqdncache_entry *));

    for (f = fqdncache_GetFirst(); f; f = fqdncache_GetNext()) {
	if (fqdncacheExpiredEntry(f)) {
	    fqdncache_release(f);
	    removed++;
	    continue;
	}
	local_fqdn_count++;

	if (LRU_list_count >= LRU_cur_size) {
	    /* have to realloc  */
	    LRU_cur_size += 16;
	    debug(35, 3, "fqdncache_purgelru: Have to grow LRU_list to %d. This shouldn't happen.\n",
		LRU_cur_size);
	    LRU_list = xrealloc((char *) LRU_list,
		LRU_cur_size * sizeof(fqdncache_entry *));
	}
	if (f->status == FQDN_PENDING)
	    continue;
	if (f->status == FQDN_DISPATCHED)
	    continue;
	local_fqdn_notpending_count++;
	LRU_list[LRU_list_count++] = f;
    }

    debug(35, 3, "fqdncache_purgelru: fqdncache_count: %5d\n", meta_data.fqdncache_count);
    debug(35, 3, "                  actual count : %5d\n", local_fqdn_count);
    debug(35, 3, "                   high W mark : %5d\n", fqdncache_high);
    debug(35, 3, "                   low  W mark : %5d\n", fqdncache_low);
    debug(35, 3, "                   not pending : %5d\n", local_fqdn_notpending_count);
    debug(35, 3, "                LRU candidates : %5d\n", LRU_list_count);

    /* sort LRU candidate list */
    qsort((char *) LRU_list,
	LRU_list_count,
	sizeof(f),
	(int (*)(const void *, const void *)) fqdncache_compareLastRef);
    for (k = 0; LRU_list[k] && (meta_data.fqdncache_count > fqdncache_low)
	&& k < LRU_list_count;
	++k) {
	fqdncache_release(LRU_list[k]);
	removed++;
    }

    debug(35, 3, "                       removed : %5d\n", removed);
    safe_free(LRU_list);
    return (removed > 0) ? 0 : -1;
}


/* create blank fqdncache_entry */
static fqdncache_entry *
fqdncache_create()
{
    static fqdncache_entry *new;

    if (meta_data.fqdncache_count > fqdncache_high) {
	if (fqdncache_purgelru() < 0)
	    debug(35, 0, "HELP!! FQDN Cache is overflowing!\n");
    }
    meta_data.fqdncache_count++;
    new = xcalloc(1, sizeof(fqdncache_entry));
    return new;

}

static void
fqdncache_add_to_hash(fqdncache_entry * f)
{
    if (hash_join(fqdn_table, (hash_link *) f)) {
	debug(35, 1, "fqdncache_add_to_hash: Cannot add %s (%p) to hash table %d.\n",
	    f->name, f, fqdn_table);
    }
    debug(35, 5, "fqdncache_add_to_hash: name <%s>\n", f->name);
}


static void
fqdncache_add(char *name, fqdncache_entry * f, struct hostent *hp, int cached)
{
    int k;

    if (fqdncache_get(name))
	fatal_dump("fqdncache_add: somebody adding a duplicate!");
    debug(35, 10, "fqdncache_add: Adding name '%s' (%s).\n", name,
	cached ? "cached" : "not cached");
    f->name = xstrdup(name);
    if (cached) {
	f->name_count = 0;
	f->names[f->name_count++] = xstrdup(hp->h_name);
	for (k = 0; hp->h_aliases[k]; k++) {
	    f->names[f->name_count++] = xstrdup(hp->h_aliases[k]);
	    if (f->name_count == FQDN_MAX_NAMES)
		break;
	}
	f->lastref = squid_curtime;
	f->status = FQDN_CACHED;
	f->expires = squid_curtime + Config.positiveDnsTtl;
    } else {
	f->lastref = squid_curtime;
	f->status = FQDN_NEGATIVE_CACHED;
	f->expires = squid_curtime + Config.negativeDnsTtl;
    }
    fqdncache_add_to_hash(f);
}

/* walks down the pending list, calling handlers */
static void
fqdncache_call_pending(fqdncache_entry * f)
{
    struct _fqdn_pending *p = NULL;
    int nhandler = 0;

    f->lastref = squid_curtime;

    while (f->pending_head != NULL) {
	p = f->pending_head;
	f->pending_head = p->next;
	if (p->handler) {
	    nhandler++;
	    dns_error_message = f->error_message;
	    p->handler(p->fd,
		(f->status == FQDN_CACHED) ? f->names[0] : NULL,
		p->handlerData);
	}
	memset(p, '\0', sizeof(struct _fqdn_pending));
	safe_free(p);
    }
    f->pending_head = NULL;	/* nuke list */
    debug(35, 10, "fqdncache_call_pending: Called %d handlers.\n", nhandler);
}

static void
fqdncache_call_pending_badname(int fd, FQDNH handler, void *data)
{
    debug(35, 0, "fqdncache_call_pending_badname: Bad Name: Calling handler with NULL result.\n");
    handler(fd, NULL, data);
}

static fqdncache_entry *
fqdncache_parsebuffer(char *inbuf, dnsserver_t * dnsData)
{
    char *buf = xstrdup(inbuf);
    char *token;
    static fqdncache_entry f;
    int k;
    int ipcount;
    int aliascount;
    debug(35, 5, "fqdncache_parsebuffer: parsing:\n%s", inbuf);
    memset(&f, '\0', sizeof(fqdncache_entry));
    f.expires = squid_curtime + Config.positiveDnsTtl;
    f.status = FQDN_DISPATCHED;
    for (token = strtok(buf, w_space); token; token = strtok(NULL, w_space)) {
	if (!strcmp(token, "$end")) {
	    break;
	} else if (!strcmp(token, "$alive")) {
	    dnsData->answer = squid_curtime;
	} else if (!strcmp(token, "$fail")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $fail");
	    f.expires = squid_curtime + Config.negativeDnsTtl;
	    f.status = FQDN_NEGATIVE_CACHED;
	} else if (!strcmp(token, "$message")) {
	    if ((token = strtok(NULL, "\n")) == NULL)
		fatal_dump("Invalid $message");
	    f.error_message = xstrdup(token);
	} else if (!strcmp(token, "$name")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $name");
	    f.status = FQDN_CACHED;
	} else if (!strcmp(token, "$h_name")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $h_name");
	    f.names[0] = xstrdup(token);
	    f.name_count = 1;
	} else if (!strcmp(token, "$h_len")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $h_len");
	} else if (!strcmp(token, "$ipcount")) {
	    if ((token = strtok(NULL, w_space)) == NULL)
		fatal_dump("Invalid $ipcount");
	    ipcount = atoi(token);
	    for (k = 0; k < ipcount; k++) {
		if ((token = strtok(NULL, w_space)) == NULL)
		    fatal_dump("Invalid FQDN address");
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
	    f.expires = squid_curtime + atoi(token);
	} else {
	    fatal_dump("Invalid dnsserver output");
	}
    }
    xfree(buf);
    return &f;
}

static int
fqdncache_dnsHandleRead(int fd, dnsserver_t * dnsData)
{
    int len;
    int svc_time;
    int n;
    fqdncache_entry *f = NULL;
    fqdncache_entry *x = NULL;

    len = read(fd,
	dnsData->ip_inbuf + dnsData->offset,
	dnsData->size - dnsData->offset);
    debug(35, 5, "fqdncache_dnsHandleRead: Result from DNS ID %d (%d bytes)\n",
	dnsData->id, len);
    if (len <= 0) {
	debug(35, dnsData->flags & DNS_FLAG_CLOSING ? 5 : 1,
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
    n = ++FqdncacheStats.replies;
    DnsStats.replies++;
    dnsData->offset += len;
    dnsData->ip_inbuf[dnsData->offset] = '\0';

    if (strstr(dnsData->ip_inbuf, "$end\n")) {
	/* end of record found */
	svc_time = tvSubMsec(dnsData->dispatch_time, current_time);
	if (n > FQDNCACHE_AV_FACTOR)
	    n = FQDNCACHE_AV_FACTOR;
	FqdncacheStats.avg_svc_time
	    = (FqdncacheStats.avg_svc_time * (n - 1) + svc_time) / n;
	if ((x = fqdncache_parsebuffer(dnsData->ip_inbuf, dnsData)) == NULL) {
	    debug(35, 0, "fqdncache_dnsHandleRead: fqdncache_parsebuffer failed?!\n");
	} else {
	    dnsData->offset = 0;
	    dnsData->ip_inbuf[0] = '\0';
	    f = dnsData->data;
	    f->name_count = x->name_count;
	    for (n = 0; n < (int) f->name_count; n++)
		f->names[n] = x->names[n];
	    f->error_message = x->error_message;
	    f->status = x->status;
	    f->expires = x->expires;
	    fqdncache_call_pending(f);
	}
    }
    if (dnsData->offset == 0) {
	dnsData->data = NULL;
	dnsData->flags &= ~DNS_FLAG_BUSY;
    }
    while ((dnsData = dnsGetFirstAvailable()) && (f = fqdncacheDequeue()))
	fqdncache_dnsDispatch(dnsData, f);
    return 0;
}

static void
fqdncacheAddPending(fqdncache_entry * f, int fd, FQDNH handler, void *handlerData)
{
    struct _fqdn_pending *pending = xcalloc(1, sizeof(struct _fqdn_pending));
    struct _fqdn_pending **I = NULL;

    pending->fd = fd;
    pending->handler = handler;
    pending->handlerData = handlerData;

    for (I = &(f->pending_head); *I; I = &((*I)->next));
    *I = pending;
}

int
fqdncache_nbgethostbyaddr(struct in_addr addr, int fd, FQDNH handler, void *handlerData)
{
    fqdncache_entry *f = NULL;
    dnsserver_t *dnsData = NULL;
    char *name = inet_ntoa(addr);

    if (!handler)
	fatal_dump("fqdncache_nbgethostbyaddr: NULL handler");

    debug(35, 4, "fqdncache_nbgethostbyaddr: FD %d: Name '%s'.\n", fd, name);
    FqdncacheStats.requests++;

    if (name == NULL || name[0] == '\0') {
	debug(35, 4, "fqdncache_nbgethostbyaddr: Invalid name!\n");
	fqdncache_call_pending_badname(fd, handler, handlerData);
	return 0;
    }
    if ((f = fqdncache_get(name))) {
	if (fqdncacheExpiredEntry(f)) {
	    fqdncache_release(f);
	    f = NULL;
	}
    }
    if (f == NULL) {
	/* MISS: No entry, create the new one */
	debug(35, 5, "fqdncache_nbgethostbyaddr: MISS for '%s'\n", name);
	FqdncacheStats.misses++;
	f = fqdncache_create();
	f->name = xstrdup(name);
	f->status = FQDN_PENDING;
	fqdncacheAddPending(f, fd, handler, handlerData);
	fqdncache_add_to_hash(f);
    } else if (f->status == FQDN_CACHED || f->status == FQDN_NEGATIVE_CACHED) {
	/* HIT */
	debug(35, 4, "fqdncache_nbgethostbyaddr: HIT for '%s'\n", name);
	if (f->status == FQDN_NEGATIVE_CACHED)
	    FqdncacheStats.negative_hits++;
	else
	    FqdncacheStats.hits++;
	fqdncacheAddPending(f, fd, handler, handlerData);
	fqdncache_call_pending(f);
	return 0;
    } else if (f->status == FQDN_PENDING || f->status == FQDN_DISPATCHED) {
	debug(35, 4, "fqdncache_nbgethostbyaddr: PENDING for '%s'\n", name);
	FqdncacheStats.pending_hits++;
	fqdncacheAddPending(f, fd, handler, handlerData);
	return 0;
    } else {
	fatal_dump("fqdncache_nbgethostbyaddr: BAD fqdncache_entry status");
    }

    /* for HIT, PENDING, DISPATCHED we've returned.  For MISS we continue */

    if ((dnsData = dnsGetFirstAvailable()))
	fqdncache_dnsDispatch(dnsData, f);
    else
	fqdncacheEnqueue(f);
    return 0;
}

static void
fqdncache_dnsDispatch(dnsserver_t * dns, fqdncache_entry * f)
{
    char *buf = NULL;
    if (!fqdncacheHasPending(f)) {
	debug(35, 0, "fqdncache_dnsDispatch: skipping '%s' because no handler.\n",
	    f->name);
	f->status = FQDN_NEGATIVE_CACHED;
	fqdncache_release(f);
	return;
    }
    f->status = FQDN_DISPATCHED;
    buf = xcalloc(1, 256);
    sprintf(buf, "%1.254s\n", f->name);
    dns->flags |= DNS_FLAG_BUSY;
    dns->data = f;
    comm_write(dns->outpipe,
	buf,
	strlen(buf),
	0,			/* timeout */
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	xfree);
    comm_set_select_handler(dns->outpipe,
	COMM_SELECT_READ,
	(PF) fqdncache_dnsHandleRead,
	dns);
    debug(35, 5, "fqdncache_dnsDispatch: Request sent to DNS server #%d.\n",
	dns->id);
    dns->dispatch_time = current_time;
    DnsStats.requests++;
    DnsStats.hist[dns->id - 1]++;
}


/* initialize the fqdncache */
void
fqdncache_init()
{
    debug(35, 3, "Initializing FQDN Cache...\n");
    memset(&FqdncacheStats, '\0', sizeof(FqdncacheStats));
    /* small hash table */
    fqdn_table = hash_create(urlcmp, 229, hash_string);
    fqdncache_high = (long) (((float) MAX_FQDN *
	    (float) FQDN_HIGH_WATER) / (float) 100);
    fqdncache_low = (long) (((float) MAX_FQDN *
	    (float) FQDN_LOW_WATER) / (float) 100);
}

/* clean up the pending entries in dnsserver */
/* return 1 if we found the host, 0 otherwise */
int
fqdncacheUnregister(struct in_addr addr, int fd)
{
    char *name = inet_ntoa(addr);
    fqdncache_entry *f = NULL;
    struct _fqdn_pending *p = NULL;
    int n = 0;

    debug(35, 3, "fqdncache_unregister: FD %d, name '%s'\n", fd, name);
    if ((f = fqdncache_get(name)) == NULL)
	return 0;
    if (f->status == FQDN_PENDING || f->status == FQDN_DISPATCHED) {
	for (p = f->pending_head; p; p = p->next) {
	    if (p->fd == fd && p->handler != NULL) {
		p->handler = NULL;
		p->fd = -1;
		n++;
	    }
	}
    }
    debug(35, 3, "fqdncache_unregister: unregistered %d handlers\n", n);
    return n;
}

char *
fqdncache_gethostbyaddr(struct in_addr addr, int flags)
{
    char *name = inet_ntoa(addr);
    fqdncache_entry *f = NULL;
    struct hostent *hp = NULL;
    unsigned int ip;

    if (!name)
	fatal_dump("fqdncache_gethostbyaddr: NULL name");
    FqdncacheStats.requests++;
    if ((f = fqdncache_get(name))) {
	if (f->status == FQDN_PENDING || f->status == FQDN_DISPATCHED) {
	    FqdncacheStats.pending_hits++;
	    return NULL;
	} else if (f->status == FQDN_NEGATIVE_CACHED) {
	    FqdncacheStats.negative_hits++;
	    dns_error_message = f->error_message;
	    return NULL;
	} else {
	    FqdncacheStats.hits++;
	    f->lastref = squid_curtime;
	    return f->names[0];
	}
    }
    FqdncacheStats.misses++;
    /* check if it's already a FQDN address in text form. */
    if (inet_addr(name) == INADDR_NONE) {
	return name;
    }
    if (flags & FQDN_BLOCKING_LOOKUP) {
	FqdncacheStats.ghba_calls++;
	ip = inet_addr(name);
	hp = gethostbyaddr((char *) &ip, 4, AF_INET);
	if (hp && hp->h_name && (hp->h_name[0] != '\0') && fqdn_table) {
	    /* good address, cached */
	    fqdncache_add(name, fqdncache_create(), hp, 1);
	    f = fqdncache_get(name);
	    return f->names[0];
	}
	/* bad address, negative cached */
	if (fqdn_table)
	    fqdncache_add(name, fqdncache_create(), hp, 0);
	return NULL;
    }
    if (flags & FQDN_LOOKUP_IF_MISS)
	fqdncache_nbgethostbyaddr(addr, -1, dummy_handler, NULL);
    return NULL;
}


/* process objects list */
void
fqdnStats(StoreEntry * sentry)
{
    fqdncache_entry *f = NULL;
    int k;
    int ttl;

    if (!fqdn_table)
	return;

    storeAppendPrintf(sentry, "{FQDN Cache Statistics:\n");
    storeAppendPrintf(sentry, "{FQDNcache Entries: %d}\n",
	meta_data.fqdncache_count);
    storeAppendPrintf(sentry, "{FQDNcache Requests: %d}\n",
	FqdncacheStats.requests);
    storeAppendPrintf(sentry, "{FQDNcache Hits: %d}\n",
	FqdncacheStats.hits);
    storeAppendPrintf(sentry, "{FQDNcache Pending Hits: %d}\n",
	FqdncacheStats.pending_hits);
    storeAppendPrintf(sentry, "{FQDNcache Negative Hits: %d}\n",
	FqdncacheStats.negative_hits);
    storeAppendPrintf(sentry, "{FQDNcache Misses: %d}\n",
	FqdncacheStats.misses);
    storeAppendPrintf(sentry, "{Blocking calls to gethostbyaddr(): %d}\n",
	FqdncacheStats.ghba_calls);
    storeAppendPrintf(sentry, "{dnsserver avg service time: %d msec}\n",
	FqdncacheStats.avg_svc_time);
    storeAppendPrintf(sentry, "}\n\n");
    storeAppendPrintf(sentry, "{FQDN Cache Contents:\n\n");

    for (f = fqdncache_GetFirst(); f; f = fqdncache_GetNext()) {
	if (f->status == FQDN_PENDING || f->status == FQDN_DISPATCHED)
	    ttl = 0;
	else
	    ttl = (f->expires - squid_curtime);
	storeAppendPrintf(sentry, " {%-32.32s %c %6d %d",
	    f->name,
	    fqdncache_status_char[f->status],
	    ttl,
	    (int) f->name_count);
	for (k = 0; k < (int) f->name_count; k++)
	    storeAppendPrintf(sentry, " %s", f->names[k]);
	storeAppendPrintf(sentry, close_bracket);
    }
    storeAppendPrintf(sentry, close_bracket);
}

static void
dummy_handler(int u1, char *u2, void *u3)
{
    return;
}

static int
fqdncacheHasPending(fqdncache_entry * f)
{
    struct _fqdn_pending *p = NULL;
    if (f->status != FQDN_PENDING)
	return 0;
    for (p = f->pending_head; p; p = p->next)
	if (p->handler)
	    return 1;
    return 0;
}

void
fqdncacheReleaseInvalid(char *name)
{
    fqdncache_entry *f;
    if ((f = fqdncache_get(name)) == NULL)
	return;
    if (f->status != FQDN_NEGATIVE_CACHED)
	return;
    fqdncache_release(f);
}

char *
fqdnFromAddr(struct in_addr addr)
{
    char *n;
    static char buf[32];
    if (Config.Log.log_fqdn && (n = fqdncache_gethostbyaddr(addr, 0)))
	return n;
    strncpy(buf, inet_ntoa(addr), 31);
    return buf;
}

int
fqdncacheQueueDrain()
{
    fqdncache_entry *i;
    dnsserver_t *dnsData;
    if (!fqdncacheQueueHead)
	return 0;
    while ((dnsData = dnsGetFirstAvailable()) && (i = fqdncacheDequeue()))
	fqdncache_dnsDispatch(dnsData, i);
    return 1;
}
