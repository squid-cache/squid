/*
 * $Id: stat.cc,v 1.42 1996/07/18 20:27:10 wessels Exp $
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

extern int emulate_httpd_log;

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
unsigned long ntcpconn = 0;
unsigned long nudpconn = 0;
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
static void statFiledescriptors _PARAMS((StoreEntry *));

/* process utilization information */
void stat_utilization_get(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
{
    protocol_t proto_id;
    proto_stat *p = &obj->proto_stat_data[PROTO_MAX];
    proto_stat *q = NULL;
    int secs = 0;

    secs = (int) (squid_curtime - squid_starttime);

    storeAppendPrintf(sentry, open_bracket);

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

void stat_io_get(sentry)
     StoreEntry *sentry;
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

    storeAppendPrintf(sentry, close_bracket);
}


/* return total bytes of all registered and known objects.
 * may not reflect the retrieving object....
 * something need to be done here to get more accurate cache size */
int cache_size_get(obj)
     cacheinfo *obj;
{
    int size = 0;
    protocol_t proto_id;
    /* sum all size, exclude total */
    for (proto_id = PROTO_NONE; proto_id < PROTO_MAX; proto_id++)
	size += obj->proto_stat_data[proto_id].kb.now;
    return size;
}

/* process objects list */
void stat_objects_get(obj, sentry, vm_or_not)
     cacheinfo *obj;
     StoreEntry *sentry;
     int vm_or_not;
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
void stat_get(obj, req, sentry)
     cacheinfo *obj;
     char *req;
     StoreEntry *sentry;
{

    if (strcmp(req, "objects") == 0) {
	stat_objects_get(obj, sentry, 0);
    } else if (strcmp(req, "vm_objects") == 0) {
	stat_objects_get(obj, sentry, 1);
    } else if (strcmp(req, "general") == 0) {
	stat_ipcache_get(sentry);
    } else if (strcmp(req, "redirector") == 0) {
	redirectStats(sentry);
    } else if (strcmp(req, "utilization") == 0) {
	stat_utilization_get(obj, sentry);
    } else if (strcmp(req, "io") == 0) {
	stat_io_get(sentry);
    } else if (strcmp(req, "reply_headers") == 0) {
	httpReplyHeaderStats(sentry);
    } else if (strcmp(req, "filedescriptors") == 0) {
	statFiledescriptors(sentry);
    }
}


/* generate logfile status information */
void log_status_get(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
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
int logReadHandler(fd_unused, buf, size_unused, data)
     int fd_unused;
     char *buf;
     int size_unused;
     log_read_data_t *data;
{
    storeAppendPrintf(data->sentry, "{%s}\n", buf);
    return 0;
}

/* log convert end handler */
/* call when a walk is completed or error. */
void logReadEndHandler(fd, errflag_unused, data)
     int fd;
     int errflag_unused;
     log_read_data_t *data;
{
    storeAppendPrintf(data->sentry, close_bracket);
    storeComplete(data->sentry);
    safe_free(data);
    file_close(fd);
}



/* start converting logfile to processed format */
void log_get_start(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
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
int squidReadHandler(fd_unused, buf, size_unused, data)
     int fd_unused;
     char *buf;
     int size_unused;
     squid_read_data_t *data;
{
    storeAppendPrintf(data->sentry, "{\"%s\"}\n", buf);
    return 0;
}

/* squid convert end handler */
/* call when a walk is completed or error. */
void squidReadEndHandler(fd_unused, errflag_unused, data)
     int fd_unused;
     int errflag_unused;
     squid_read_data_t *data;
{
    storeAppendPrintf(data->sentry, close_bracket);
    storeComplete(data->sentry);
    file_close(data->fd);
    safe_free(data);
}


/* start convert squid.conf file to processed format */
void squid_get_start(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
{
    squid_read_data_t *data;

    data = xcalloc(1, sizeof(squid_read_data_t));
    data->sentry = sentry;
    data->fd = file_open((char *) ConfigFile, NULL, O_RDONLY);
    storeAppendPrintf(sentry, open_bracket);
    file_walk(data->fd, (FILE_WALK_HD) squidReadEndHandler, (void *) data,
	(FILE_WALK_LHD) squidReadHandler, (void *) data);
}


void dummyhandler(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
{
    storeAppendPrintf(sentry, "{ \"Not_Implemented_yet.\"}\n");
}

void server_list(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
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
void info_get_mallstat(size, number, sentry)
     int size, number;
     StoreEntry *sentry;
{
    if (number > 0)
	storeAppendPrintf(sentry, "{\t%d = %d}\n", size, number);
}
#endif

static char *host_port_fmt(host, port)
     char *host;
     u_short port;
{
    LOCAL_ARRAY(char, buf, 32);
    sprintf(buf, "%s.%d", host, (int) port);
    return buf;
}

static void statFiledescriptors(sentry)
     StoreEntry *sentry;
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
    storeAppendPrintf(sentry, "{}\n");
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

int memoryAccounted()
{
    return (int)
	meta_data.store_entries * sizeof(StoreEntry) +
	meta_data.ipcache_count * sizeof(ipcache_entry) +
	meta_data.hash_links * sizeof(hash_link) +
	sm_stats.total_pages_allocated * sm_stats.page_size +
	disk_stats.total_pages_allocated * disk_stats.page_size +
	request_pool.total_pages_allocated * request_pool.page_size +
	mem_obj_pool.total_pages_allocated * mem_obj_pool.page_size +
	meta_data.url_strings +
	meta_data.misc;
}

int mallinfoTotal()
{
    int total = 0;
#if HAVE_MALLINFO
    struct mallinfo mp;
    mp = mallinfo();
    total = mp.arena;
#endif
    return total;
}

void info_get(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
{
    char *tod = NULL;
    wordlist *p = NULL;
    float f;
#ifdef HAVE_MALLINFO
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
    tod = mkrfc850(&squid_starttime);
    storeAppendPrintf(sentry, "{Start Time:\t%s}\n", tod);
    tod = mkrfc850(&squid_curtime);
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
    tod = mkrfc850(&next_cleaning);
    storeAppendPrintf(sentry, "{\tStorage Expiration at:\t%s}\n", tod);

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

    storeAppendPrintf(sentry, "{Stop List:}\n");
    if ((p = getHttpStoplist())) {
	storeAppendPrintf(sentry, "{\tHTTP:}\n");
	while (p) {
	    storeAppendPrintf(sentry, "{\t\t%s}\n", p->key);
	    p = p->next;
	}
    }
    if ((p = getGopherStoplist())) {
	storeAppendPrintf(sentry, "{\tGOPHER:}\n");
	while (p) {
	    storeAppendPrintf(sentry, "{\t\t%s}\n", p->key);
	    p = p->next;
	}
    }
    if ((p = getFtpStoplist())) {
	storeAppendPrintf(sentry, "{\tFTP:}\n");
	while (p) {
	    storeAppendPrintf(sentry, "{\t\t%s}\n", p->key);
	    p = p->next;
	}
    }
    storeAppendPrintf(sentry, "{Internal Data Structures:}\n");
    storeAppendPrintf(sentry, "{\tHot Object Cache Items %d}\n",
	meta_data.hot_vm);
    storeAppendPrintf(sentry, "{\tStoreEntries with MemObjects %d}\n",
	meta_data.store_in_mem_objects);

    storeAppendPrintf(sentry, "{Meta Data:}\n");
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
	"Hash link",
	meta_data.hash_links = hash_links_allocated,
	(int) sizeof(hash_link),
	(int) (meta_data.hash_links * sizeof(hash_link) >> 10));

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

void parameter_get(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
{
    storeAppendPrintf(sentry, open_bracket);
    storeAppendPrintf(sentry,
	"{VM-Max %d \"# Maximum hot-vm cache (MB)\"}\n",
	getCacheMemMax() / (1 << 20));
    storeAppendPrintf(sentry,
	"{VM-High %d \"# High water mark hot-vm cache (%%)\"}\n",
	getCacheMemHighWaterMark());
    storeAppendPrintf(sentry,
	"{VM-Low %d \"# Low water-mark hot-vm cache (%%)\"}\n",
	getCacheMemLowWaterMark());
    storeAppendPrintf(sentry,
	"{Swap-Max %d \"# Maximum disk cache (MB)\"}\n",
	getCacheSwapMax() / (1 << 10));
    storeAppendPrintf(sentry,
	"{Swap-High %d \"# High Water mark disk cache (%%)\"}\n",
	getCacheSwapHighWaterMark());
    storeAppendPrintf(sentry,
	"{Swap-Low %d \"# Low water mark disk cache (%%)\"}\n",
	getCacheSwapLowWaterMark());
    storeAppendPrintf(sentry,
	"{HTTP-Max %d\"# Maximum size HTTP objects (KB)\"}\n",
	getHttpMax() / (1 << 10));
    storeAppendPrintf(sentry,
	"{HTTP-TTL %d \"# Http object default TTL (hrs)\"}\n",
	getHttpTTL() / 3600);
    storeAppendPrintf(sentry,
	"{Gopher-Max %d \"# Maximum size gopher objects (KB)\"}\n",
	getGopherMax() / (1 << 10));
    storeAppendPrintf(sentry,
	"{Gopher-TTL %d \"# TTL for gopher objects (hrs)\"}\n",
	getGopherTTL() / 3600);
    storeAppendPrintf(sentry,
	"{FTP-Max %d \"# Maximum size FTP objects (KB)\"}\n",
	getFtpMax() / (1 << 10));
    storeAppendPrintf(sentry,
	"{FTP-TTL %d \"# TTL for FTP objects (hrs)\"}\n",
	getFtpTTL() / 3600);
    storeAppendPrintf(sentry,
	"{Neg-TTL %d \"# TTL for negative cache (s)\"}\n",
	getNegativeTTL());
    storeAppendPrintf(sentry,
	"{ReadTimeout %d \"# Maximum idle connection (s)\"}\n",
	getReadTimeout());
    storeAppendPrintf(sentry,
	"{ClientLifetime %d \"# Lifetime for incoming HTTP requests\"}\n",
	getClientLifetime());
    storeAppendPrintf(sentry,
	"{CleanRate %d \"# Rate for periodic object expiring\"}\n",
	getCleanRate());
    /* Cachemgr.cgi expects an integer in the second field of the string */
    storeAppendPrintf(sentry,
	"{HttpAccelMode %d \"# Is operating as an HTTP accelerator\"}\n",
	httpd_accel_mode);
    storeAppendPrintf(sentry, close_bracket);
}


void log_append(obj, url, id, size, action, method, http_code, msec, ident, hier)
     cacheinfo *obj;
     char *url;
     char *id;
     int size;
     char *action;
     char *method;
     int http_code;
     int msec;
     char *ident;
     hier_code hier;
{
    LOCAL_ARRAY(char, tmp, 6000);	/* MAX_URL is 4096 */
    char *buf = NULL;
    int x;

    getCurrentTime();

#ifdef LOG_FQDN
    /* ENABLE THIS IF YOU WANT A *SLOW* CACHE, OR
     * JUST WRITE A PERL SCRIPT TO MUCK YOUR LOGS */
    {
	int ipx[4];
	unsigned long ipy;
	struct hostent *h = NULL;
	if (sscanf(id, "%d.%d.%d.%d", &ipx[0], &ipx[1], &ipx[2], &ipx[3]) == 4) {
	    ipy = inet_addr(id);
	    if (h = gethostbyaddr((char *) &ipy, 4, AF_INET)) {
		id = xstrdup(h->h_name);
	    }
	}
    }
#endif

    if (!method)
	method = "-";
    if (!url)
	url = "-";
    if (!ident || ident[0] == '\0')
	ident = "-";

    if (obj->logfile_status == LOG_ENABLE) {
	if (emulate_httpd_log)
	    sprintf(tmp, "%s %s - [%s] \"%s %s\" %s %d\n",
		id,
		ident,
		mkhttpdlogtime(&squid_curtime),
		method,
		url,
		action,
		size);
	else
	    sprintf(tmp, "%9d.%03d %6d %s %s/%03d/%s %d %s %s %s\n",
		(int) current_time.tv_sec,
		(int) current_time.tv_usec / 1000,
		msec,
		id,
		action,
		http_code,
		hier_strings[hier],
		size,
		method,
		url,
		ident);
	x = file_write(obj->logfile_fd,
	    buf = xstrdup(tmp),
	    strlen(tmp),
	    obj->logfile_access,
	    NULL,
	    NULL,
	    xfree);
	if (x != DISK_OK) {
	    debug(18, 1, "log_append: File write failed.\n");
	    safe_free(buf);
	}
    }
}

void log_enable(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
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

void log_disable(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
{
    if (obj->logfile_status == LOG_ENABLE)
	file_close(obj->logfile_fd);

    obj->logfile_status = LOG_DISABLE;
    /* at the moment, store one char to make a storage manager happy */
    storeAppendPrintf(sentry, " ");
}



void log_clear(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
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



void proto_newobject(obj, proto_id, size, restart)
     cacheinfo *obj;
     protocol_t proto_id;
     int size;
     int restart;
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


void proto_purgeobject(obj, proto_id, size)
     cacheinfo *obj;
     protocol_t proto_id;
     int size;
{
    proto_stat *p = &obj->proto_stat_data[proto_id];

    p->object_count--;

    /* Scale down to KB */
    p->kb.now -= ((size + 1023) >> 10);

    if (p->kb.now < p->kb.min)
	p->kb.min = p->kb.now;
}

/* update stat for each particular protocol when an object is fetched */
void proto_touchobject(obj, proto_id, size)
     cacheinfo *obj;
     protocol_t proto_id;
     int size;
{
    obj->proto_stat_data[proto_id].refcount++;
    obj->proto_stat_data[proto_id].transferbyte += (1023 + size) >> 10;
}

void proto_hit(obj, proto_id)
     cacheinfo *obj;
     protocol_t proto_id;
{
    obj->proto_stat_data[proto_id].hit++;
}

void proto_miss(obj, proto_id)
     cacheinfo *obj;
     protocol_t proto_id;
{
    obj->proto_stat_data[proto_id].miss++;
}


void stat_init(object, logfilename)
     cacheinfo **object;
     char *logfilename;
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

    xmemcpy(obj->logfilename, logfilename, (int) (strlen(logfilename) + 1) % 256);
    obj->logfile_fd = file_open(obj->logfilename, NULL, O_WRONLY | O_CREAT);
    if (obj->logfile_fd == DISK_ERROR) {
	debug(18, 0, "%s: %s\n", obj->logfilename, xstrerror());
	fatal("Cannot open logfile.");
    }
    obj->logfile_access = file_write_lock(obj->logfile_fd);

    obj->proto_id = urlParseProtocol;
    obj->proto_newobject = proto_newobject;
    obj->proto_purgeobject = proto_purgeobject;
    obj->proto_touchobject = proto_touchobject;
    obj->proto_hit = proto_hit;
    obj->proto_miss = proto_miss;
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

char *stat_describe(entry)
     StoreEntry *entry;
{
    LOCAL_ARRAY(char, state, 256);

    state[0] = '\0';
    switch (entry->store_status) {
    case STORE_OK:
	strncat(state, "STORE-OK", sizeof(state));
	break;
    case STORE_PENDING:
	strncat(state, "ST-PEND", sizeof(state));
	break;
    case STORE_ABORTED:
	strncat(state, "ABORTED", sizeof(state));
	break;
    default:
	strncat(state, "YEEHAH", sizeof(state));
	break;
    }
    strncat(state, "/", sizeof(state));

    switch (entry->ping_status) {
    case PING_WAITING:
	strncat(state, "PING-WAIT", sizeof(state));
	break;
    case PING_TIMEOUT:
	strncat(state, "PING-TIMEOUT", sizeof(state));
	break;
    case PING_DONE:
	strncat(state, "PING-DONE", sizeof(state));
	break;
    case PING_NONE:
	strncat(state, "NO-PING", sizeof(state));
	break;
    default:
	strncat(state, "HELP!!", sizeof(state));
	break;
    }
    return (state);
}

char *mem_describe(entry)
     StoreEntry *entry;
{
    LOCAL_ARRAY(char, where, 100);

    where[0] = '\0';
    if (entry->swap_file_number >= 0)
	storeAppendPrintf(entry, "D%d", entry->swap_file_number);
    if (entry->swap_status == SWAPPING_OUT)
	strncat(where, "/SWAP-OUT", sizeof(where));
    if (entry->swap_status == SWAP_OK)
	strncat(where, "/SWAP-OK", sizeof(where));
    else
	strncat(where, "/NO-SWAP", sizeof(where));

    if (entry->mem_status == SWAPPING_IN)
	strncat(where, "/SWAP-IN", sizeof(where));
    else if (entry->mem_status == IN_MEMORY)
	strncat(where, "/IN-MEM", sizeof(where));
    else			/* STORE_PENDING */
	strncat(where, "/OUT-MEM", sizeof(where));
    return (where);
}


char *ttl_describe(entry)
     StoreEntry *entry;
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

char *elapsed_time(entry, since, TTL)
     StoreEntry *entry;
     int since;
     char *TTL;
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


char *flags_describe(entry)
     StoreEntry *entry;
{
    LOCAL_ARRAY(char, FLAGS, 32);
    char LOCK_CNT[32];

    strcpy(FLAGS, "F:");
    if (BIT_TEST(entry->flag, KEY_CHANGE))
	strncat(FLAGS, "K", sizeof(FLAGS) - 1);
    if (BIT_TEST(~entry->flag, CACHABLE))
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

void stat_rotate_log()
{
    int i;
    LOCAL_ARRAY(char, from, MAXPATHLEN);
    LOCAL_ARRAY(char, to, MAXPATHLEN);
    char *fname = NULL;

    if ((fname = CacheInfo->logfilename) == NULL)
	return;

    debug(18, 1, "stat_rotate_log: Rotating\n");

    /* Rotate numbers 0 through N up one */
    for (i = getLogfileRotateNumber(); i > 1;) {
	i--;
	sprintf(from, "%s.%d", fname, i - 1);
	sprintf(to, "%s.%d", fname, i);
	rename(from, to);
    }
    /* Rotate the current log to .0 */
    if (getLogfileRotateNumber() > 0) {
	sprintf(to, "%s.%d", fname, 0);
	rename(fname, to);
    }
    /* Close and reopen the log.  It may have been renamed "manually"
     * before HUP'ing us. */
    file_close(CacheInfo->logfile_fd);
    CacheInfo->logfile_fd = file_open(fname, NULL, O_WRONLY | O_CREAT);
    if (CacheInfo->logfile_fd == DISK_ERROR) {
	debug(18, 0, "stat_rotate_log: Cannot open logfile: %s\n", fname);
	CacheInfo->logfile_status = LOG_DISABLE;
	fatal("Cannot open logfile.");
    }
    CacheInfo->logfile_access = file_write_lock(CacheInfo->logfile_fd);
}
