/*
 * $Id: stat.cc,v 1.73 1996/09/18 20:12:23 wessels Exp $
 *
 * DEBUG: section 18    Cache Manager Statistics
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
#define max(a,b)  ((a)>(b)? (a): (b))

typedef struct _log_read_data_t {
    StoreEntry *sentry;
} log_read_data_t;

typedef struct _squid_read_data_t {
    StoreEntry *sentry;
    int fd;
} squid_read_data_t;

/* GLOBALS */
Meta_data meta_data;
volatile unsigned long ntcpconn = 0;
volatile unsigned long nudpconn = 0;
struct _iostats IOStats;

char *stat_describe();
char *mem_describe();
char *ttl_describe();
char *flags_describe();
char *elapsed_time();
char *diskFileName();

/* LOCALS */
char *open_bracket = "{\n";
char *close_bracket = "}\n";

static void dummyhandler __P((cacheinfo *, StoreEntry *));
static void info_get __P((cacheinfo *, StoreEntry *));
static void logReadEndHandler __P((int, int, log_read_data_t *));
static void log_clear __P((cacheinfo *, StoreEntry *));
static void log_disable __P((cacheinfo *, StoreEntry *));
static void log_enable __P((cacheinfo *, StoreEntry *));
static void log_get_start __P((cacheinfo *, StoreEntry *));
static void log_status_get __P((cacheinfo *, StoreEntry *));
static void parameter_get __P((cacheinfo *, StoreEntry *));
static void proto_count __P((cacheinfo *, protocol_t, log_type));
static void proto_newobject __P((cacheinfo *, protocol_t, int, int));
static void proto_purgeobject __P((cacheinfo *, protocol_t, int));
static void proto_touchobject __P((cacheinfo *, protocol_t, int));
static void server_list __P((cacheinfo *, StoreEntry *));
static void squidReadEndHandler __P((int, int, squid_read_data_t *));
static void squid_get_start __P((cacheinfo *, StoreEntry *));
static void statFiledescriptors __P((StoreEntry *));
static void stat_get __P((cacheinfo *, char *req, StoreEntry *));
static void stat_io_get __P((StoreEntry *));
static void stat_objects_get __P((cacheinfo *, StoreEntry *, int vm_or_not));
static void stat_utilization_get __P((cacheinfo *, StoreEntry *, char *desc));
static int cache_size_get __P((cacheinfo *));
static int logReadHandler __P((int, char *, int, log_read_data_t *));
static int squidReadHandler __P((int, char *, int, squid_read_data_t *));
static int memoryAccounted __P((void));

#ifdef UNUSED_CODE
static int mallinfoTotal __P((void));
#endif

#ifdef XMALLOC_STATISTICS
static void info_get_mallstat __P((int, int, StoreEntry *));
#endif

/* process utilization information */
static void
stat_utilization_get(cacheinfo * obj, StoreEntry * sentry, char *desc)
{
    protocol_t proto_id;
    proto_stat *p = &obj->proto_stat_data[PROTO_MAX];
    proto_stat *q = NULL;
    int secs = 0;

    secs = (int) (squid_curtime - squid_starttime);
    storeAppendPrintf(sentry, "{ %s\n", desc);	/* } */
    strcpy(p->protoname, "TOTAL");
    p->object_count = 0;
    p->kb.max = 0;
    p->kb.min = 0;
    p->kb.avg = 0;
    p->kb.now = 0;
    p->hit = 0;
    p->miss = 0;
    p->refcount = 0;
    p->transferbyte = 0;
    /* find the total */
    for (proto_id = PROTO_NONE; proto_id < PROTO_MAX; ++proto_id) {
	q = &obj->proto_stat_data[proto_id];
	p->object_count += q->object_count;
	p->kb.max += q->kb.max;
	p->kb.min += q->kb.min;
	p->kb.avg += q->kb.avg;
	p->kb.now += q->kb.now;
	p->hit += q->hit;
	p->miss += q->miss;
	p->refcount += q->refcount;
	p->transferbyte += q->transferbyte;
    }
    /* dump it */
    for (proto_id = PROTO_NONE; proto_id <= PROTO_MAX; ++proto_id) {
	p = &obj->proto_stat_data[proto_id];
	if (p->hit != 0) {
	    p->hitratio =
		(float) p->hit /
		((float) p->hit +
		(float) p->miss);
	}
	storeAppendPrintf(sentry, "{%8.8s %d %d %d %d %4.2f %d %d %d}\n",
	    p->protoname,
	    p->object_count,
	    p->kb.max,
	    p->kb.now,
	    p->kb.min,
	    p->hitratio,
	    (secs ? p->transferbyte / secs : 0),
	    p->refcount,
	    p->transferbyte);
    }
    storeAppendPrintf(sentry, close_bracket);
}

static void
stat_io_get(StoreEntry * sentry)
{
    int i;

    storeAppendPrintf(sentry, open_bracket);
    storeAppendPrintf(sentry, "{HTTP I/O}\n");
    storeAppendPrintf(sentry, "{number of reads: %d}\n", IOStats.Http.reads);
    storeAppendPrintf(sentry, "{deferred reads: %d (%d%%)}\n",
	IOStats.Http.reads_deferred,
	percent(IOStats.Http.reads_deferred, IOStats.Http.reads));
    storeAppendPrintf(sentry, "{Read Histogram:}\n");
    for (i = 0; i < 16; i++) {
	storeAppendPrintf(sentry, "{%5d-%5d: %9d %2d%%}\n",
	    i ? (1 << (i - 1)) + 1 : 1,
	    1 << i,
	    IOStats.Http.read_hist[i],
	    percent(IOStats.Http.read_hist[i], IOStats.Http.reads));
    }

    storeAppendPrintf(sentry, "{}\n");
    storeAppendPrintf(sentry, "{FTP I/O}\n");
    storeAppendPrintf(sentry, "{number of reads: %d}\n", IOStats.Ftp.reads);
    storeAppendPrintf(sentry, "{deferred reads: %d (%d%%)}\n",
	IOStats.Ftp.reads_deferred,
	percent(IOStats.Ftp.reads_deferred, IOStats.Ftp.reads));
    storeAppendPrintf(sentry, "{Read Histogram:}\n");
    for (i = 0; i < 16; i++) {
	storeAppendPrintf(sentry, "{%5d-%5d: %9d %2d%%}\n",
	    i ? (1 << (i - 1)) + 1 : 1,
	    1 << i,
	    IOStats.Ftp.read_hist[i],
	    percent(IOStats.Ftp.read_hist[i], IOStats.Ftp.reads));
    }

    storeAppendPrintf(sentry, "{}\n");
    storeAppendPrintf(sentry, "{Gopher I/O}\n");
    storeAppendPrintf(sentry, "{number of reads: %d}\n", IOStats.Gopher.reads);
    storeAppendPrintf(sentry, "{deferred reads: %d (%d%%)}\n",
	IOStats.Gopher.reads_deferred,
	percent(IOStats.Gopher.reads_deferred, IOStats.Gopher.reads));
    storeAppendPrintf(sentry, "{Read Histogram:}\n");
    for (i = 0; i < 16; i++) {
	storeAppendPrintf(sentry, "{%5d-%5d: %9d %2d%%}\n",
	    i ? (1 << (i - 1)) + 1 : 1,
	    1 << i,
	    IOStats.Gopher.read_hist[i],
	    percent(IOStats.Gopher.read_hist[i], IOStats.Gopher.reads));
    }

    storeAppendPrintf(sentry, "{}\n");
    storeAppendPrintf(sentry, "{WAIS I/O}\n");
    storeAppendPrintf(sentry, "{number of reads: %d}\n", IOStats.Wais.reads);
    storeAppendPrintf(sentry, "{deferred reads: %d (%d%%)}\n",
	IOStats.Wais.reads_deferred,
	percent(IOStats.Wais.reads_deferred, IOStats.Wais.reads));
    storeAppendPrintf(sentry, "{Read Histogram:}\n");
    for (i = 0; i < 16; i++) {
	storeAppendPrintf(sentry, "{%5d-%5d: %9d %2d%%}\n",
	    i ? (1 << (i - 1)) + 1 : 1,
	    1 << i,
	    IOStats.Wais.read_hist[i],
	    percent(IOStats.Wais.read_hist[i], IOStats.Wais.reads));
    }

    storeAppendPrintf(sentry, close_bracket);
}


/* return total bytes of all registered and known objects.
 * may not reflect the retrieving object....
 * something need to be done here to get more accurate cache size */
static int
cache_size_get(cacheinfo * obj)
{
    int size = 0;
    protocol_t proto_id;
    /* sum all size, exclude total */
    for (proto_id = PROTO_NONE; proto_id < PROTO_MAX; proto_id++)
	size += obj->proto_stat_data[proto_id].kb.now;
    return size;
}

/* process objects list */
static void
stat_objects_get(cacheinfo * obj, StoreEntry * sentry, int vm_or_not)
{
    LOCAL_ARRAY(char, space, 40);
    LOCAL_ARRAY(char, space2, 40);
    int npend = 0;
    StoreEntry *entry = NULL;
    int N = 0;
    int obj_size;

    storeAppendPrintf(sentry, open_bracket);

    for (entry = storeGetFirst();
	entry != NULL;
	entry = storeGetNext()) {
	if (vm_or_not && (entry->mem_status == NOT_IN_MEMORY) &&
	    (entry->swap_status == SWAP_OK))
	    continue;
	if ((++N & 0xFF) == 0) {
	    getCurrentTime();
	    debug(18, 3, "stat_objects_get:  Processed %d objects...\n", N);
	}
	obj_size = entry->object_len;
	npend = storePendingNClients(entry);
	if (entry->mem_obj)
	    obj_size = entry->mem_obj->e_current_len;
	storeAppendPrintf(sentry, "{ %s %d %s %s %s %s %d %d %s %s }\n",
	    entry->url,
	    obj_size,
	    elapsed_time(entry, (int) entry->timestamp, space),
	    flags_describe(entry),
	    elapsed_time(entry, (int) entry->lastref, space2),
	    ttl_describe(entry),
	    npend,
	    (int) entry->refcount,
	    mem_describe(entry),
	    stat_describe(entry));
    }
    storeAppendPrintf(sentry, close_bracket);
}


/* process a requested object into a manager format */
static void
stat_get(cacheinfo * obj, char *req, StoreEntry * sentry)
{

    if (strcmp(req, "objects") == 0) {
	stat_objects_get(obj, sentry, 0);
    } else if (strcmp(req, "vm_objects") == 0) {
	stat_objects_get(obj, sentry, 1);
    } else if (strcmp(req, "ipcache") == 0) {
	stat_ipcache_get(sentry);
    } else if (strcmp(req, "fqdncache") == 0) {
	fqdnStats(sentry);
    } else if (strcmp(req, "dns") == 0) {
	dnsStats(sentry);
    } else if (strcmp(req, "redirector") == 0) {
	redirectStats(sentry);
    } else if (strcmp(req, "utilization") == 0) {
	stat_utilization_get(HTTPCacheInfo, sentry, "HTTP");
	stat_utilization_get(ICPCacheInfo, sentry, "ICP");
    } else if (strcmp(req, "io") == 0) {
	stat_io_get(sentry);
    } else if (strcmp(req, "reply_headers") == 0) {
	httpReplyHeaderStats(sentry);
    } else if (strcmp(req, "filedescriptors") == 0) {
	statFiledescriptors(sentry);
    }
}


/* generate logfile status information */
static void
log_status_get(cacheinfo * obj, StoreEntry * sentry)
{
    if (obj->logfile_status == LOG_ENABLE) {
	storeAppendPrintf(sentry, "{\"Logfile is Enabled. Filename: %s\"}\n",
	    obj->logfilename);
    } else {
	storeAppendPrintf(sentry, "{\"Logfile is Disabled.\"}\n");
    }
}



/* log convert handler */
/* call for each line in file, use fileWalk routine */
static int
logReadHandler(int fd_unused, char *buf, int size_unused, log_read_data_t * data)
{
    storeAppendPrintf(data->sentry, "{%s}\n", buf);
    return 0;
}

/* log convert end handler */
/* call when a walk is completed or error. */
static void
logReadEndHandler(int fd, int errflag_unused, log_read_data_t * data)
{
    storeAppendPrintf(data->sentry, close_bracket);
    storeComplete(data->sentry);
    safe_free(data);
    file_close(fd);
}



/* start converting logfile to processed format */
static void
log_get_start(cacheinfo * obj, StoreEntry * sentry)
{
    log_read_data_t *data = NULL;
    int fd;

    if (obj->logfile_status == LOG_DISABLE) {
	/* Manufacture status when logging is disabled */
	log_status_get(obj, sentry);
	storeComplete(sentry);
	return;
    }
    fd = file_open(obj->logfilename, NULL, O_RDONLY);
    if (fd < 0) {
	debug(18, 0, "Cannot open logfile: %s: %s\n",
	    obj->logfilename, xstrerror());
	return;
    }
    data = xcalloc(1, sizeof(log_read_data_t));
    data->sentry = sentry;
    storeAppendPrintf(sentry, "{\n");
    file_walk(fd,
	(FILE_WALK_HD) logReadEndHandler,
	(void *) data,
	(FILE_WALK_LHD) logReadHandler,
	(void *) data);
    return;
}


/* squid convert handler */
/* call for each line in file, use fileWalk routine */
static int
squidReadHandler(int fd_unused, char *buf, int size_unused, squid_read_data_t * data)
{
    storeAppendPrintf(data->sentry, "{\"%s\"}\n", buf);
    return 0;
}

/* squid convert end handler */
/* call when a walk is completed or error. */
static void
squidReadEndHandler(int fd_unused, int errflag_unused, squid_read_data_t * data)
{
    storeAppendPrintf(data->sentry, close_bracket);
    storeComplete(data->sentry);
    file_close(data->fd);
    safe_free(data);
}


/* start convert squid.conf file to processed format */
static void
squid_get_start(cacheinfo * obj, StoreEntry * sentry)
{
    squid_read_data_t *data;

    data = xcalloc(1, sizeof(squid_read_data_t));
    data->sentry = sentry;
    data->fd = file_open((char *) ConfigFile, NULL, O_RDONLY);
    storeAppendPrintf(sentry, open_bracket);
    file_walk(data->fd, (FILE_WALK_HD) squidReadEndHandler, (void *) data,
	(FILE_WALK_LHD) squidReadHandler, (void *) data);
}


static void
dummyhandler(cacheinfo * obj, StoreEntry * sentry)
{
    storeAppendPrintf(sentry, "{ \"Not_Implemented_yet.\"}\n");
}

static void
server_list(cacheinfo * obj, StoreEntry * sentry)
{
    edge *e = NULL;
    dom_list *d = NULL;
    icp_opcode op;

    storeAppendPrintf(sentry, open_bracket);

    if (getFirstEdge() == NULL)
	storeAppendPrintf(sentry, "{There are no neighbors installed.}\n");
    for (e = getFirstEdge(); e; e = getNextEdge(e)) {
	if (e->host == NULL)
	    fatal_dump("Found an edge without a hostname!");
	storeAppendPrintf(sentry, "\n{%-11.11s: %s/%d/%d}\n",
	    e->type == EDGE_PARENT ? "Parent" : "Sibling",
	    e->host,
	    e->http_port,
	    e->icp_port);
	storeAppendPrintf(sentry, "{Status     : %s}\n",
	    e->neighbor_up ? "Up" : "Down");
	storeAppendPrintf(sentry, "{AVG RTT    : %d msec}\n", e->stats.rtt);
	storeAppendPrintf(sentry, "{ACK DEFICIT: %8d}\n", e->stats.ack_deficit);
	storeAppendPrintf(sentry, "{PINGS SENT : %8d}\n", e->stats.pings_sent);
	storeAppendPrintf(sentry, "{PINGS ACKED: %8d %3d%%}\n",
	    e->stats.pings_acked,
	    percent(e->stats.pings_acked, e->stats.pings_sent));
	storeAppendPrintf(sentry, "{Histogram of PINGS ACKED:}\n");
	for (op = ICP_OP_INVALID; op < ICP_OP_END; op++) {
	    if (e->stats.counts[op] == 0)
		continue;
	    storeAppendPrintf(sentry, "{%-10.10s : %8d %3d%%}\n",
		IcpOpcodeStr[op],
		e->stats.counts[op],
		percent(e->stats.counts[op], e->stats.pings_acked));
	}
	storeAppendPrintf(sentry, "{FETCHES    : %8d %3d%%}\n",
	    e->stats.fetches,
	    percent(e->stats.fetches, e->stats.pings_acked));

	if (e->last_fail_time) {
	    storeAppendPrintf(sentry, "{Last failed connect() at: %s}\n",
		mkhttpdlogtime(&(e->last_fail_time)));
	}
	storeAppendPrintf(sentry, "{DOMAIN LIST: ");
	for (d = e->domains; d; d = d->next) {
	    if (d->do_ping)
		storeAppendPrintf(sentry, "%s ", d->domain);
	    else
		storeAppendPrintf(sentry, "!%s ", d->domain);
	}
	storeAppendPrintf(sentry, close_bracket);	/* } */
    }
    storeAppendPrintf(sentry, close_bracket);
}

#if XMALLOC_STATISTICS
static void
info_get_mallstat(int size, number, StoreEntry * sentry)
{
    if (number > 0)
	storeAppendPrintf(sentry, "{\t%d = %d}\n", size, number);
}
#endif

static char *
host_port_fmt(char *host, u_short port)
{
    LOCAL_ARRAY(char, buf, 32);
    sprintf(buf, "%s.%d", host, (int) port);
    return buf;
}

static void
statFiledescriptors(StoreEntry * sentry)
{
    int i;
    int j;
    char *s = NULL;
    int lft;
    int to;

    storeAppendPrintf(sentry, open_bracket);
    storeAppendPrintf(sentry, "{Active file descriptors:}\n");
    storeAppendPrintf(sentry, "{%-4s %-6s %-4s %-4s %-21s %s}\n",
	"File",
	"Type",
	"Lftm",
	"Tout",
	"Remote Address",
	"Description");
    storeAppendPrintf(sentry, "{---- ------ ---- ---- --------------------- ------------------------------}\n");
    for (i = 0; i < FD_SETSIZE; i++) {
	if (!fdstat_isopen(i))
	    continue;
	j = fdstatGetType(i);
	storeAppendPrintf(sentry, "{%4d %-6s ",
	    i,
	    fdstatTypeStr[j]);
	switch (j) {
	case FD_SOCKET:
	    if ((lft = comm_get_fd_lifetime(i)) < 0)
		lft = 0;
	    to = comm_get_fd_timeout(i);
	    if (lft > 0)
		lft = (lft - squid_curtime) / 60;
	    if (to > 0)
		to = (to - squid_curtime) / 60;
	    if (fd_table[i].timeout_handler == NULL)
		to = 0;
	    storeAppendPrintf(sentry, "%4d %4d %-21s %s}\n",
		lft,
		to,
		host_port_fmt(fd_table[i].ipaddr, fd_table[i].remote_port),
		fd_note(i, NULL));
	    break;
	case FD_FILE:
	    storeAppendPrintf(sentry, "%31s %s}\n",
		"",
		(s = diskFileName(i)) ? s : "-");
	    break;
	case FD_PIPE:
	    storeAppendPrintf(sentry, "%31s %s}\n", "", fd_note(i, NULL));
	    break;
	case FD_LOG:
	    storeAppendPrintf(sentry, "%31s %s}\n", "", fd_note(i, NULL));
	    break;
	case FD_UNKNOWN:
	default:
	    storeAppendPrintf(sentry, "%31s %s}\n", "", fd_note(i, NULL));
	    break;
	}
    }
    storeAppendPrintf(sentry, close_bracket);
}

static int
memoryAccounted(void)
{
    return (int)
	meta_data.store_entries * sizeof(StoreEntry) +
	meta_data.ipcache_count * sizeof(ipcache_entry) +
	meta_data.fqdncache_count * sizeof(fqdncache_entry) +
	hash_links_allocated * sizeof(hash_link) +
	sm_stats.total_pages_allocated * sm_stats.page_size +
	disk_stats.total_pages_allocated * disk_stats.page_size +
	request_pool.total_pages_allocated * request_pool.page_size +
	mem_obj_pool.total_pages_allocated * mem_obj_pool.page_size +
	meta_data.url_strings +
	meta_data.misc;
}

#ifdef UNUSED_CODE
static int
mallinfoTotal(void)
{
    int total = 0;
#if HAVE_MALLINFO
    struct mallinfo mp;
    mp = mallinfo();
    total = mp.arena;
#endif
    return total;
}
#endif

static void
info_get(cacheinfo * obj, StoreEntry * sentry)
{
    char *tod = NULL;
    float f;
#if HAVE_MALLINFO
    int t;
#endif

#if defined(HAVE_GETRUSAGE) && defined(RUSAGE_SELF)
    struct rusage rusage;
#endif

#if HAVE_MALLINFO
    struct mallinfo mp;
#endif

    storeAppendPrintf(sentry, open_bracket);
    storeAppendPrintf(sentry, "{Squid Object Cache: Version %s}\n",
	version_string);
    tod = mkrfc850(squid_starttime);
    storeAppendPrintf(sentry, "{Start Time:\t%s}\n", tod);
    tod = mkrfc850(squid_curtime);
    storeAppendPrintf(sentry, "{Current Time:\t%s}\n", tod);
    storeAppendPrintf(sentry, "{Connection information for %s:}\n",
	appname);
    storeAppendPrintf(sentry, "{\tNumber of TCP connections:\t%lu}\n",
	ntcpconn);
    storeAppendPrintf(sentry, "{\tNumber of UDP connections:\t%lu}\n",
	nudpconn);

    f = squid_curtime - squid_starttime;
    storeAppendPrintf(sentry, "{\tConnections per hour:\t%.1f}\n",
	f == 0.0 ? 0.0 : ((ntcpconn + nudpconn) / (f / 3600)));

    storeAppendPrintf(sentry, "{Cache information for %s:}\n",
	appname);
    storeAppendPrintf(sentry, "{\tStorage Swap size:\t%d MB}\n",
	storeGetSwapSize() >> 10);
    storeAppendPrintf(sentry, "{\tStorage Mem size:\t%d KB}\n",
	storeGetMemSize() >> 10);

#if HAVE_GETRUSAGE && defined(RUSAGE_SELF)
    storeAppendPrintf(sentry, "{Resource usage for %s:}\n", appname);
    getrusage(RUSAGE_SELF, &rusage);
    storeAppendPrintf(sentry, "{\tCPU Time: %d seconds (%d user %d sys)}\n",
	(int) rusage.ru_utime.tv_sec + (int) rusage.ru_stime.tv_sec,
	(int) rusage.ru_utime.tv_sec,
	(int) rusage.ru_stime.tv_sec);
    storeAppendPrintf(sentry, "{\tCPU Usage: %d%%}\n",
	percent(rusage.ru_utime.tv_sec + rusage.ru_stime.tv_sec,
	    squid_curtime - squid_starttime));
    storeAppendPrintf(sentry, "{\tProcess Size: rss %ld KB}\n",
	rusage.ru_maxrss * getpagesize() >> 10);
    storeAppendPrintf(sentry, "{\tPage faults with physical i/o: %ld}\n",
	rusage.ru_majflt);
#endif

#if HAVE_MALLINFO
    mp = mallinfo();
    storeAppendPrintf(sentry, "{Memory usage for %s via mallinfo():}\n",
	appname);
    storeAppendPrintf(sentry, "{\tTotal space in arena:  %6d KB}\n",
	mp.arena >> 10);
    storeAppendPrintf(sentry, "{\tOrdinary blocks:       %6d KB %6d blks}\n",
	mp.uordblks >> 10, mp.ordblks);
    storeAppendPrintf(sentry, "{\tSmall blocks:          %6d KB %6d blks}\n",
	mp.usmblks >> 10, mp.smblks);
    storeAppendPrintf(sentry, "{\tHolding blocks:        %6d KB %6d blks}\n",
	mp.hblkhd >> 10, mp.hblks);
    storeAppendPrintf(sentry, "{\tFree Small blocks:     %6d KB}\n",
	mp.fsmblks >> 10);
    storeAppendPrintf(sentry, "{\tFree Ordinary blocks:  %6d KB}\n",
	mp.fordblks >> 10);
    t = mp.uordblks + mp.usmblks + mp.hblkhd;
    storeAppendPrintf(sentry, "{\tTotal in use:          %6d KB %d%%}\n",
	t >> 10, percent(t, mp.arena));
    t = mp.fsmblks + mp.fordblks;
    storeAppendPrintf(sentry, "{\tTotal free:            %6d KB %d%%}\n",
	t >> 10, percent(t, mp.arena));
#ifdef WE_DONT_USE_KEEP
    storeAppendPrintf(sentry, "{\tKeep option:           %6d KB}\n",
	mp.keepcost >> 10);
#endif
#if HAVE_EXT_MALLINFO
    storeAppendPrintf(sentry, "{\tmax size of small blocks:\t%d}\n", mp.mxfast);
    storeAppendPrintf(sentry, "{\tnumber of small blocks in a holding block:\t%d}\n",
	mp.nlblks);
    storeAppendPrintf(sentry, "{\tsmall block rounding factor:\t%d}\n", mp.grain);
    storeAppendPrintf(sentry, "{\tspace (including overhead) allocated in ord. blks:\t%d}\n"
	,mp.uordbytes);
    storeAppendPrintf(sentry, "{\tnumber of ordinary blocks allocated:\t%d}\n",
	mp.allocated);
    storeAppendPrintf(sentry, "{\tbytes used in maintaining the free tree:\t%d}\n",
	mp.treeoverhead);
#endif /* HAVE_EXT_MALLINFO */
#endif /* HAVE_MALLINFO */

    storeAppendPrintf(sentry, "{File descriptor usage for %s:}\n", appname);
    storeAppendPrintf(sentry, "{\tMax number of file desc available:    %4d}\n",
	FD_SETSIZE);
    storeAppendPrintf(sentry, "{\tLargest file desc currently in use:   %4d}\n",
	fdstat_biggest_fd());
    storeAppendPrintf(sentry, "{\tAvailable number of file descriptors: %4d}\n",
	fdstat_are_n_free_fd(0));
    storeAppendPrintf(sentry, "{\tReserved number of file descriptors:  %4d}\n",
	RESERVED_FD);

    storeAppendPrintf(sentry, "{Internal Data Structures:}\n");
    storeAppendPrintf(sentry, "{\t%6d StoreEntries}\n",
	meta_data.store_entries);
    storeAppendPrintf(sentry, "{\t%6d StoreEntries with MemObjects}\n",
	meta_data.mem_obj_count);
    storeAppendPrintf(sentry, "{\t%6d StoreEntries with MemObject Data}\n",
	meta_data.mem_data_count);
    storeAppendPrintf(sentry, "{\t%6d Hot Object Cache Items}\n",
	meta_data.hot_vm);

    storeAppendPrintf(sentry, "{Accounted Memory Usage:}\n");
    storeAppendPrintf(sentry, "{\t%-25.25s %7d x %4d bytes = %6d KB}\n",
	"StoreEntry",
	meta_data.store_entries,
	(int) sizeof(StoreEntry),
	(int) (meta_data.store_entries * sizeof(StoreEntry) >> 10));

    storeAppendPrintf(sentry, "{\t%-25.25s %7d x %4d bytes = %6d KB}\n",
	"IPCacheEntry",
	meta_data.ipcache_count,
	(int) sizeof(ipcache_entry),
	(int) (meta_data.ipcache_count * sizeof(ipcache_entry) >> 10));

    storeAppendPrintf(sentry, "{\t%-25.25s %7d x %4d bytes = %6d KB}\n",
	"FQDNCacheEntry",
	meta_data.fqdncache_count,
	(int) sizeof(fqdncache_entry),
	(int) (meta_data.fqdncache_count * sizeof(fqdncache_entry) >> 10));

    storeAppendPrintf(sentry, "{\t%-25.25s %7d x %4d bytes = %6d KB}\n",
	"Hash link",
	hash_links_allocated,
	(int) sizeof(hash_link),
	(int) (hash_links_allocated * sizeof(hash_link) >> 10));

    storeAppendPrintf(sentry, "{\t%-25.25s                      = %6d KB}\n",
	"URL strings",
	meta_data.url_strings >> 10);

    storeAppendPrintf(sentry, "{\t%-25.25s %7d x %4d bytes = %6d KB (%6d free)}\n",
	"Pool MemObject structures",
	mem_obj_pool.total_pages_allocated,
	mem_obj_pool.page_size,
	mem_obj_pool.total_pages_allocated * mem_obj_pool.page_size >> 10,
	(mem_obj_pool.total_pages_allocated - mem_obj_pool.n_pages_in_use) * mem_obj_pool.page_size >> 10);

    storeAppendPrintf(sentry, "{\t%-25.25s %7d x %4d bytes = %6d KB (%6d free)}\n",
	"Pool for Request structures",
	request_pool.total_pages_allocated,
	request_pool.page_size,
	request_pool.total_pages_allocated * request_pool.page_size >> 10,
	(request_pool.total_pages_allocated - request_pool.n_pages_in_use) * request_pool.page_size >> 10);

    storeAppendPrintf(sentry, "{\t%-25.25s %7d x %4d bytes = %6d KB (%6d free)}\n",
	"Pool for in-memory object data",
	sm_stats.total_pages_allocated,
	sm_stats.page_size,
	sm_stats.total_pages_allocated * sm_stats.page_size >> 10,
	(sm_stats.total_pages_allocated - sm_stats.n_pages_in_use) * sm_stats.page_size >> 10);

    storeAppendPrintf(sentry, "{\t%-25.25s %7d x %4d bytes = %6d KB (%6d free)}\n",
	"Pool for disk I/O",
	disk_stats.total_pages_allocated,
	disk_stats.page_size,
	disk_stats.total_pages_allocated * disk_stats.page_size >> 10,
	(disk_stats.total_pages_allocated - disk_stats.n_pages_in_use) * disk_stats.page_size >> 10);

    storeAppendPrintf(sentry, "{\t%-25.25s                      = %6d KB}\n",
	"Miscellaneous",
	meta_data.misc >> 10);

    storeAppendPrintf(sentry, "{\t%-25.25s                      = %6d KB}\n",
	"Total Accounted",
	memoryAccounted() >> 10);

#if XMALLOC_STATISTICS
    storeAppendPrintf(sentry, "{Memory allocation statistics}\n");
    malloc_statistics(info_get_mallstat, sentry);
#endif

    storeAppendPrintf(sentry, close_bracket);
}

static void
parameter_get(cacheinfo * obj, StoreEntry * sentry)
{
    storeAppendPrintf(sentry, open_bracket);
    storeAppendPrintf(sentry,
	"{VM-Max %d \"# Maximum hot-vm cache (MB)\"}\n",
	Config.Mem.maxSize / (1 << 20));
    storeAppendPrintf(sentry,
	"{VM-High %d \"# High water mark hot-vm cache (%%)\"}\n",
	Config.Mem.highWaterMark);
    storeAppendPrintf(sentry,
	"{VM-Low %d \"# Low water-mark hot-vm cache (%%)\"}\n",
	Config.Mem.lowWaterMark);
    storeAppendPrintf(sentry,
	"{Swap-Max %d \"# Maximum disk cache (MB)\"}\n",
	Config.Swap.maxSize / (1 << 10));
    storeAppendPrintf(sentry,
	"{Swap-High %d \"# High Water mark disk cache (%%)\"}\n",
	Config.Swap.highWaterMark);
    storeAppendPrintf(sentry,
	"{Swap-Low %d \"# Low water mark disk cache (%%)\"}\n",
	Config.Swap.lowWaterMark);
    storeAppendPrintf(sentry,
	"{HTTP-Max %d\"# Maximum size HTTP objects (KB)\"}\n",
	Config.Http.maxObjSize / (1 << 10));
    storeAppendPrintf(sentry,
	"{HTTP-TTL %d \"# Http object default TTL (hrs)\"}\n",
	Config.Http.defaultTtl / 3600);
    storeAppendPrintf(sentry,
	"{Gopher-Max %d \"# Maximum size gopher objects (KB)\"}\n",
	Config.Gopher.maxObjSize / (1 << 10));
    storeAppendPrintf(sentry,
	"{Gopher-TTL %d \"# TTL for gopher objects (hrs)\"}\n",
	Config.Gopher.defaultTtl / 3600);
    storeAppendPrintf(sentry,
	"{FTP-Max %d \"# Maximum size FTP objects (KB)\"}\n",
	Config.Ftp.maxObjSize / (1 << 10));
    storeAppendPrintf(sentry,
	"{FTP-TTL %d \"# TTL for FTP objects (hrs)\"}\n",
	Config.Ftp.defaultTtl / 3600);
    storeAppendPrintf(sentry,
	"{Neg-TTL %d \"# TTL for negative cache (s)\"}\n",
	Config.negativeTtl);
    storeAppendPrintf(sentry,
	"{ReadTimeout %d \"# Maximum idle connection (s)\"}\n",
	Config.readTimeout);
    storeAppendPrintf(sentry,
	"{ClientLifetime %d \"# Lifetime for incoming HTTP requests\"}\n",
	Config.lifetimeDefault);
    storeAppendPrintf(sentry,
	"{CleanRate %d \"# Rate for periodic object expiring\"}\n",
	Config.cleanRate);
    /* Cachemgr.cgi expects an integer in the second field of the string */
    storeAppendPrintf(sentry,
	"{HttpAccelMode %d \"# Is operating as an HTTP accelerator\"}\n",
	httpd_accel_mode);
    storeAppendPrintf(sentry, close_bracket);
}

#if LOG_FULL_HEADERS
static char c2x[] =
{
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f"
    "404142434445464748494a4b4c4d4e4f"
    "505152535455565758595a5b5c5d5e5f"
    "606162636465666768696a6b6c6d6e6f"
    "707172737475767778797a7b7c7d7e7f"
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
};

/* log_quote -- URL-style encoding on MIME headers. */

char *
log_quote(char *header)
{
    int c, i;
    char *buf, *buf_cursor;
    if (header == NULL) {
	buf = xcalloc(1, 1);
	*buf = '\0';
	return buf;
    }
    buf = xcalloc((strlen(header) * 3) + 1, 1);
    buf_cursor = buf;
    /*
     * We escape: \x00-\x1F"#%;<>?{}|\\\\^~`\[\]\x7F-\xFF 
     * which is the default escape list for the CPAN Perl5 URI module
     * modulo the inclusion of space (x40) to make the raw logs a bit
     * more readable.
     */
    while ((c = *header++)) {
	if (c <= 0x1F
	    || c >= 0x7F
	    || c == '"'
	    || c == '#'
	    || c == '%'
	    || c == ';'
	    || c == '<'
	    || c == '>'
	    || c == '?'
	    || c == '{'
	    || c == '}'
	    || c == '|'
	    || c == '\\'
	    || c == '^'
	    || c == '~'
	    || c == '`'
	    || c == '['
	    || c == ']') {
	    *buf_cursor++ = '%';
	    i = c * 2;
	    *buf_cursor++ = c2x[i];
	    *buf_cursor++ = c2x[i + 1];
	} else {
	    *buf_cursor++ = c;
	}
    }
    *buf_cursor = '\0';
    return buf;
}
#endif /* LOG_FULL_HEADERS */


static void
log_append(cacheinfo * obj,
    char *url,
    struct in_addr caddr,
    int size,
    char *action,
    char *method,
    int http_code,
    int msec,
    char *ident,
#if !LOG_FULL_HEADERS
    struct _hierarchyLogData *hierData
#else
    struct _hierarchyLogData *hierData,
    char *request_hdr,
    char *reply_hdr
#endif				/* LOG_FULL_HEADERS */
)
{
#if LOG_FULL_HEADERS
    LOCAL_ARRAY(char, tmp, 10000);	/* MAX_URL is 4096 */
#else
    LOCAL_ARRAY(char, tmp, 6000);	/* MAX_URL is 4096 */
#endif /* LOG_FULL_HEADERS */
    int x;
    char *client = NULL;
    hier_code hier_code = HIER_NONE;
    char *hier_host = dash_str;
    int hier_timeout = 0;

    if (Config.Log.log_fqdn)
	client = fqdncache_gethostbyaddr(caddr, 0);
    if (client == NULL)
	client = inet_ntoa(caddr);

    getCurrentTime();

    if (!method)
	method = dash_str;
    if (!url)
	url = dash_str;
    if (!ident || ident[0] == '\0')
	ident = dash_str;
    if (hierData) {
	hier_code = hierData->code;
	hier_host = hierData->host ? hierData->host : dash_str;
	hier_timeout = hierData->timeout;
    }
    if (obj->logfile_status == LOG_ENABLE) {
	if (Config.commonLogFormat)
	    sprintf(tmp, "%s %s - [%s] \"%s %s\" %s %d\n",
		client,
		ident,
		mkhttpdlogtime(&squid_curtime),
		method,
		url,
		action,
		size);
	else
	    sprintf(tmp, "%9d.%03d %6d %s %s/%03d %d %s %s %s %s%s/%s\n",
		(int) current_time.tv_sec,
		(int) current_time.tv_usec / 1000,
		msec,
		client,
		action,
		http_code,
		size,
		method,
		url,
		ident,
		hier_timeout ? "TIMEOUT_" : "",
		hier_strings[hier_code],
		hier_host);
#if LOG_FULL_HEADERS
	if (Config.logMimeHdrs) {
	    int msize = strlen(tmp);
	    char *ereq = log_quote(request_hdr);
	    char *erep = log_quote(reply_hdr);

	    if (msize + strlen(ereq) + strlen(erep) + 7 <= sizeof(tmp))
		sprintf(tmp + msize - 1, " [%s] [%s]\n", ereq, erep);
	    else
		debug(18, 1, "log_append: Long headers not logged.\n");
	    safe_free(ereq);
	    safe_free(erep);
	}
#endif /* LOG_FULL_HEADERS */
	x = file_write(obj->logfile_fd,
	    xstrdup(tmp),
	    strlen(tmp),
	    obj->logfile_access,
	    NULL,
	    NULL,
	    xfree);
	if (x != DISK_OK)
	    debug(18, 1, "log_append: File write failed.\n");
    }
}

static void
log_enable(cacheinfo * obj, StoreEntry * sentry)
{
    if (obj->logfile_status == LOG_DISABLE) {
	obj->logfile_status = LOG_ENABLE;

	/* open the logfile */
	obj->logfile_fd = file_open(obj->logfilename, NULL, O_WRONLY | O_CREAT);
	if (obj->logfile_fd == DISK_ERROR) {
	    debug(18, 0, "Cannot open logfile: %s\n", obj->logfilename);
	    obj->logfile_status = LOG_DISABLE;
	}
	obj->logfile_access = file_write_lock(obj->logfile_fd);

    }
    /* at the moment, store one char to make a storage manager happy */
    storeAppendPrintf(sentry, " ");
}

static void
log_disable(cacheinfo * obj, StoreEntry * sentry)
{
    if (obj->logfile_status == LOG_ENABLE)
	file_close(obj->logfile_fd);

    obj->logfile_status = LOG_DISABLE;
    /* at the moment, store one char to make a storage manager happy */
    storeAppendPrintf(sentry, " ");
}



static void
log_clear(cacheinfo * obj, StoreEntry * sentry)
{
    /* what should be done here. Erase file ??? or move it to another name?  At the moment, just erase it.  bug here need to be fixed. what if there are still data in memory. Need flush here */
    if (obj->logfile_status == LOG_ENABLE)
	file_close(obj->logfile_fd);

    unlink(obj->logfilename);

    /* reopen it anyway */
    obj->logfile_fd = file_open(obj->logfilename, NULL, O_WRONLY | O_CREAT);
    if (obj->logfile_fd == DISK_ERROR) {
	debug(18, 0, "Cannot open logfile: %s\n", obj->logfilename);
	obj->logfile_status = LOG_DISABLE;
    }
    /* at the moment, store one char to make a storage manager happy */
    storeAppendPrintf(sentry, " ");
}



static void
proto_newobject(cacheinfo * obj, protocol_t proto_id, int size, int restart)
{
    proto_stat *p = &obj->proto_stat_data[proto_id];

    p->object_count++;

    /* Account for 1KB granularity */
    p->kb.now += ((size + 1023) >> 10);

    if (p->kb.now > p->kb.max)
	p->kb.max = p->kb.now;
    if (restart)
	p->kb.min = p->kb.now;
}


static void
proto_purgeobject(cacheinfo * obj, protocol_t proto_id, int size)
{
    proto_stat *p = &obj->proto_stat_data[proto_id];

    p->object_count--;

    /* Scale down to KB */
    p->kb.now -= ((size + 1023) >> 10);

    if (p->kb.now < p->kb.min)
	p->kb.min = p->kb.now;
}

/* update stat for each particular protocol when an object is fetched */
static void
proto_touchobject(cacheinfo * obj, protocol_t proto_id, int size)
{
    obj->proto_stat_data[proto_id].refcount++;
    obj->proto_stat_data[proto_id].transferbyte += (1023 + size) >> 10;
}

static void
proto_count(cacheinfo * obj, protocol_t proto_id, log_type type)
{
    switch (type) {
    case LOG_TCP_HIT:
    case LOG_TCP_IMS_HIT:
    case LOG_TCP_EXPIRED_HIT:
    case LOG_UDP_HIT:
    case LOG_UDP_HIT_OBJ:
	obj->proto_stat_data[proto_id].hit++;
	break;
    default:
	obj->proto_stat_data[proto_id].miss++;
	break;
    }
}


void
stat_init(cacheinfo ** object, char *logfilename)
{
    cacheinfo *obj = NULL;
    int i;

    debug(18, 5, "stat_init: Initializing...\n");
    obj = xcalloc(1, sizeof(cacheinfo));
    obj->stat_get = stat_get;
    obj->info_get = info_get;
    obj->cache_size_get = cache_size_get;
    obj->log_get_start = log_get_start;
    obj->log_status_get = log_status_get;
    obj->log_append = log_append;
    obj->log_clear = log_clear;
    obj->log_enable = log_enable;
    obj->log_disable = log_disable;
    obj->logfile_status = LOG_ENABLE;
    obj->squid_get_start = squid_get_start;
    obj->parameter_get = parameter_get;
    obj->server_list = server_list;
    if (logfilename) {
	memset(obj->logfilename, '0', MAX_FILE_NAME_LEN);
	strncpy(obj->logfilename, logfilename, MAX_FILE_NAME_LEN - 1);
	obj->logfile_fd = file_open(obj->logfilename, NULL, O_WRONLY | O_CREAT);
	if (obj->logfile_fd == DISK_ERROR) {
	    debug(18, 0, "%s: %s\n", obj->logfilename, xstrerror());
	    fatal("Cannot open logfile.");
	}
	obj->logfile_access = file_write_lock(obj->logfile_fd);
    }
    obj->proto_id = urlParseProtocol;
    obj->proto_newobject = proto_newobject;
    obj->proto_purgeobject = proto_purgeobject;
    obj->proto_touchobject = proto_touchobject;
    obj->proto_count = proto_count;
    obj->NotImplement = dummyhandler;
    for (i = PROTO_NONE; i <= PROTO_MAX; i++) {
	switch (i) {
	case PROTO_HTTP:
	    strcpy(obj->proto_stat_data[i].protoname, "HTTP");
	    break;
	case PROTO_GOPHER:
	    strcpy(obj->proto_stat_data[i].protoname, "GOPHER");
	    break;
	case PROTO_FTP:
	    strcpy(obj->proto_stat_data[i].protoname, "FTP");
	    break;
	case PROTO_WAIS:
	    strcpy(obj->proto_stat_data[i].protoname, "WAIS");
	    break;
	case PROTO_CACHEOBJ:
	    strcpy(obj->proto_stat_data[i].protoname, "CACHE_OBJ");
	    break;
	case PROTO_MAX:
	    strcpy(obj->proto_stat_data[i].protoname, "TOTAL");
	    break;
	case PROTO_NONE:
	default:
	    strcpy(obj->proto_stat_data[i].protoname, "OTHER");
	    break;
	}
	obj->proto_stat_data[i].object_count = 0;
	obj->proto_stat_data[i].hit = 0;
	obj->proto_stat_data[i].miss = 0;
	obj->proto_stat_data[i].hitratio = 0.0;
	obj->proto_stat_data[i].transferrate = 0;
	obj->proto_stat_data[i].refcount = 0;
	obj->proto_stat_data[i].transferbyte = 0;
	obj->proto_stat_data[i].kb.max = 0;
	obj->proto_stat_data[i].kb.min = 0;
	obj->proto_stat_data[i].kb.avg = 0;
	obj->proto_stat_data[i].kb.now = 0;
    }
    *object = obj;
}

char *
stat_describe(StoreEntry * entry)
{
    LOCAL_ARRAY(char, state, 256);

    state[0] = '\0';
    sprintf(state, "%s/%s",
	storeStatusStr[entry->store_status],
	pingStatusStr[entry->ping_status]);
    return (state);
}

char *
mem_describe(StoreEntry * entry)
{
    LOCAL_ARRAY(char, where, 100);

    where[0] = '\0';
    sprintf(where, "D%d/%s/%s",
	entry->swap_file_number,
	swapStatusStr[entry->swap_status],
	memStatusStr[entry->mem_status]);
    return (where);
}


char *
ttl_describe(StoreEntry * entry)
{
    int hh, mm, ss;
    LOCAL_ARRAY(char, TTL, 60);
    int ttl;

    TTL[0] = '\0';
    strcpy(TTL, "UNKNOWN");	/* sometimes the TTL isn't set below */
    ttl = entry->expires - squid_curtime;
    if (ttl < 0)
	strcpy(TTL, "EXPIRED");
    else {

	hh = ttl / 3600;
	ttl -= hh * 3600;
	mm = ttl / 60;
	ttl -= mm * 60;
	ss = ttl;

	sprintf(TTL, "% 6d:%02d:%02d", hh, mm, ss);
    }
    return (TTL);
}

char *
elapsed_time(StoreEntry * entry, int since, char *TTL)
{
    int hh, mm, ss, ttl;

    TTL[0] = '\0';
    strcpy(TTL, "UNKNOWN");	/* sometimes TTL doesn't get set */
    ttl = squid_curtime - since;
    if (since == 0) {
	strcpy(TTL, "NEVER");
    } else if (ttl < 0) {
	strcpy(TTL, "EXPIRED");
    } else {
	hh = ttl / 3600;
	ttl -= hh * 3600;
	mm = ttl / 60;
	ttl -= mm * 60;
	ss = ttl;
	sprintf(TTL, "% 6d:%02d:%02d", hh, mm, ss);
    }
    return (TTL);
}


char *
flags_describe(StoreEntry * entry)
{
    LOCAL_ARRAY(char, FLAGS, 32);
    char LOCK_CNT[32];

    strcpy(FLAGS, "F:");
    if (BIT_TEST(entry->flag, KEY_CHANGE))
	strncat(FLAGS, "K", sizeof(FLAGS) - 1);
    if (BIT_TEST(entry->flag, ENTRY_CACHABLE))
	strncat(FLAGS, "C", sizeof(FLAGS) - 1);
    if (BIT_TEST(entry->flag, REFRESH_REQUEST))
	strncat(FLAGS, "R", sizeof(FLAGS) - 1);
    if (BIT_TEST(entry->flag, RELEASE_REQUEST))
	strncat(FLAGS, "Z", sizeof(FLAGS) - 1);
    if (BIT_TEST(entry->flag, ABORT_MSG_PENDING))
	strncat(FLAGS, "A", sizeof(FLAGS) - 1);
    if (BIT_TEST(entry->flag, DELAY_SENDING))
	strncat(FLAGS, "D", sizeof(FLAGS) - 1);
    if (BIT_TEST(entry->flag, IP_LOOKUP_PENDING))
	strncat(FLAGS, "P", sizeof(FLAGS) - 1);
    if (entry->lock_count)
	strncat(FLAGS, "L", sizeof(FLAGS) - 1);
    if (entry->lock_count) {
	sprintf(LOCK_CNT, "%d", entry->lock_count);
	strncat(FLAGS, LOCK_CNT, sizeof(FLAGS) - 1);
    }
    return (FLAGS);
}

void
stat_rotate_log(void)
{
    int i;
    LOCAL_ARRAY(char, from, MAXPATHLEN);
    LOCAL_ARRAY(char, to, MAXPATHLEN);
    char *fname = NULL;

    if ((fname = HTTPCacheInfo->logfilename) == NULL)
	return;

    debug(18, 1, "stat_rotate_log: Rotating\n");

    /* Rotate numbers 0 through N up one */
    for (i = Config.Log.rotateNumber; i > 1;) {
	i--;
	sprintf(from, "%s.%d", fname, i - 1);
	sprintf(to, "%s.%d", fname, i);
	rename(from, to);
    }
    /* Rotate the current log to .0 */
    if (Config.Log.rotateNumber > 0) {
	sprintf(to, "%s.%d", fname, 0);
	rename(fname, to);
    }
    /* Close and reopen the log.  It may have been renamed "manually"
     * before HUP'ing us. */
    file_close(HTTPCacheInfo->logfile_fd);
    HTTPCacheInfo->logfile_fd = file_open(fname, NULL, O_WRONLY | O_CREAT);
    if (HTTPCacheInfo->logfile_fd == DISK_ERROR) {
	debug(18, 0, "stat_rotate_log: Cannot open logfile: %s\n", fname);
	HTTPCacheInfo->logfile_status = LOG_DISABLE;
	fatal("Cannot open logfile.");
    }
    HTTPCacheInfo->logfile_access = file_write_lock(HTTPCacheInfo->logfile_fd);
}

void
statCloseLog(void)
{
    file_close(HTTPCacheInfo->logfile_fd);
}
