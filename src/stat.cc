
/*
 * $Id: stat.cc,v 1.146 1997/06/26 22:35:57 wessels Exp $
 *
 * DEBUG: section 18    Cache Manager Statistics
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
const char *const open_bracket = "{\n";
const char *const close_bracket = "}\n";

extern int unlinkd_count;
extern int fileno_stack_count;

/* LOCALS */
static const char *describeStatuses _PARAMS((const StoreEntry *));
static const char *describeFlags _PARAMS((const StoreEntry *));
static const char *describeTimestamps _PARAMS((const StoreEntry *));
static void proto_count _PARAMS((cacheinfo *, protocol_t, log_type));
static void proto_newobject _PARAMS((cacheinfo *, protocol_t, int, int));
static void proto_purgeobject _PARAMS((cacheinfo *, protocol_t, int));
static void proto_touchobject _PARAMS((cacheinfo *, protocol_t, int));
static void statFiledescriptors _PARAMS((StoreEntry *));
static void stat_io_get _PARAMS((StoreEntry *));
static void stat_objects_get _PARAMS((StoreEntry *, int vm_or_not));
static void stat_utilization_get _PARAMS((cacheinfo *, StoreEntry *, const char *desc));
static int memoryAccounted _PARAMS((void));

#ifdef XMALLOC_STATISTICS
static void info_get_mallstat _PARAMS((int, int, StoreEntry *));
#endif

/* process utilization information */
static void
stat_utilization_get(cacheinfo * obj, StoreEntry * sentry, const char *desc)
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

static const char *
describeStatuses(const StoreEntry * entry)
{
    LOCAL_ARRAY(char, buf, 256);
    sprintf(buf, "%-13s %-13s %-12s %-12s",
	storeStatusStr[entry->store_status],
	memStatusStr[entry->mem_status],
	swapStatusStr[entry->swap_status],
	pingStatusStr[entry->ping_status]);
    return buf;
}

static const char *
describeFlags(const StoreEntry * entry)
{
    LOCAL_ARRAY(char, buf, 256);
    int flags = (int) entry->flag;
    char *t;
    buf[0] = '\0';
#ifdef OLD_CODE
    if (BIT_TEST(flags, IP_LOOKUP_PENDING))
	strcat(buf, "IP,");
#endif
    if (BIT_TEST(flags, DELETE_BEHIND))
	strcat(buf, "DB,");
#ifdef OLD_CODE
    if (BIT_TEST(flags, CLIENT_ABORT_REQUEST))
	strcat(buf, "CA,");
#endif
    if (BIT_TEST(flags, DELAY_SENDING))
	strcat(buf, "DS,");
    if (BIT_TEST(flags, ABORT_MSG_PENDING))
	strcat(buf, "AP,");
    if (BIT_TEST(flags, RELEASE_REQUEST))
	strcat(buf, "RL,");
    if (BIT_TEST(flags, REFRESH_REQUEST))
	strcat(buf, "RF,");
    if (BIT_TEST(flags, ENTRY_CACHABLE))
	strcat(buf, "EC,");
    if (BIT_TEST(flags, KEY_CHANGE))
	strcat(buf, "KC,");
    if (BIT_TEST(flags, KEY_URL))
	strcat(buf, "KU,");
    if (BIT_TEST(flags, ENTRY_HTML))
	strcat(buf, "HT,");
    if (BIT_TEST(flags, ENTRY_DISPATCHED))
	strcat(buf, "ED,");
    if (BIT_TEST(flags, KEY_PRIVATE))
	strcat(buf, "KP,");
    if (BIT_TEST(flags, HIERARCHICAL))
	strcat(buf, "HI,");
    if (BIT_TEST(flags, ENTRY_NEGCACHED))
	strcat(buf, "NG,");
    if (BIT_TEST(flags, READ_DEFERRED))
	strcat(buf, "RD,");
    if ((t = strrchr(buf, ',')))
	*t = '\0';
    return buf;
}

static const char *
describeTimestamps(const StoreEntry * entry)
{
    LOCAL_ARRAY(char, buf, 256);
    sprintf(buf, "LV:%-9d LU:%-9d LM:%-9d EX:%-9d",
	(int) entry->timestamp,
	(int) entry->lastref,
	(int) entry->lastmod,
	(int) entry->expires);
    return buf;
}

/* process objects list */
static void
stat_objects_get(StoreEntry * sentry, int vm_or_not)
{
    StoreEntry *entry = NULL;
    MemObject *mem;
    int N = 0;

    storeAppendPrintf(sentry, open_bracket);

    for (entry = storeGetFirst(); entry != NULL; entry = storeGetNext()) {
	mem = entry->mem_obj;
	if (vm_or_not && mem == NULL)
	    continue;
	if ((++N & 0xFF) == 0) {
	    debug(18, 3) ("stat_objects_get:  Processed %d objects...\n", N);
	}
	storeAppendPrintf(sentry, "{%s %dL %-25s %s %3d %2d %8d %s}\n",
	    describeStatuses(entry),
	    (int) entry->lock_count,
	    describeFlags(entry),
	    describeTimestamps(entry),
	    (int) entry->refcount,
	    storePendingNClients(entry),
	    mem ? mem->e_current_len : entry->object_len,
	    entry->url);
    }
    storeAppendPrintf(sentry, close_bracket);
}


/* process a requested object into a manager format */
void
stat_get(const char *req, StoreEntry * sentry)
{

    if (strcmp(req, "objects") == 0) {
	stat_objects_get(sentry, 0);
    } else if (strcmp(req, "vm_objects") == 0) {
	stat_objects_get(sentry, 1);
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
    } else if (strcmp(req, "netdb") == 0) {
	netdbDump(sentry);
    } else if (strcmp(req, "storedir") == 0) {
	storeDirStats(sentry);
    } else if (strcmp(req, "cbdata") == 0) {
	cbdataDump(sentry);
    }
}

void
server_list(StoreEntry * sentry)
{
    peer *e = NULL;
    struct _domain_ping *d = NULL;
    icp_opcode op;

    storeAppendPrintf(sentry, open_bracket);

    if (getFirstPeer() == NULL)
	storeAppendPrintf(sentry, "{There are no neighbors installed.}\n");
    for (e = getFirstPeer(); e; e = getNextPeer(e)) {
	if (e->host == NULL)
	    fatal_dump("Found an peer without a hostname!");
	storeAppendPrintf(sentry, "\n{%-11.11s: %s/%d/%d}\n",
	    neighborTypeStr(e),
	    e->host,
	    e->http_port,
	    e->icp_port);
	storeAppendPrintf(sentry, "{Status     : %s}\n",
	    neighborUp(e) ? "Up" : "Down");
	storeAppendPrintf(sentry, "{AVG RTT    : %d msec}\n", e->stats.rtt);
	storeAppendPrintf(sentry, "{ACK DEFICIT: %8d}\n", e->stats.ack_deficit);
	storeAppendPrintf(sentry, "{PINGS SENT : %8d}\n", e->stats.pings_sent);
	storeAppendPrintf(sentry, "{PINGS ACKED: %8d %3d%%}\n",
	    e->stats.pings_acked,
	    percent(e->stats.pings_acked, e->stats.pings_sent));
	storeAppendPrintf(sentry, "{FETCHES    : %8d %3d%%}\n",
	    e->stats.fetches,
	    percent(e->stats.fetches, e->stats.pings_acked));
	storeAppendPrintf(sentry, "{IGNORED    : %8d %3d%%}\n",
	    e->stats.ignored_replies,
	    percent(e->stats.ignored_replies, e->stats.pings_acked));
	storeAppendPrintf(sentry, "{Histogram of PINGS ACKED:}\n");
	for (op = ICP_OP_INVALID; op < ICP_OP_END; op++) {
	    if (e->stats.counts[op] == 0)
		continue;
	    storeAppendPrintf(sentry, "{    %12.12s : %8d %3d%%}\n",
		IcpOpcodeStr[op],
		e->stats.counts[op],
		percent(e->stats.counts[op], e->stats.pings_acked));
	}
	if (e->last_fail_time) {
	    storeAppendPrintf(sentry, "{Last failed connect() at: %s}\n",
		mkhttpdlogtime(&(e->last_fail_time)));
	}
	storeAppendPrintf(sentry, "{DOMAIN LIST: ");
	for (d = e->pinglist; d; d = d->next) {
	    if (d->do_ping)
		storeAppendPrintf(sentry, "%s ", d->domain);
	    else
		storeAppendPrintf(sentry, "!%s ", d->domain);
	}
	storeAppendPrintf(sentry, close_bracket);	/* } */
    }
    storeAppendPrintf(sentry, close_bracket);
}

#ifdef XMALLOC_STATISTICS
static void
info_get_mallstat(int size, int number, StoreEntry * sentry)
{
    if (number > 0)
	storeAppendPrintf(sentry, "{\t%d = %d}\n", size, number);
}
#endif

static const char *
fdRemoteAddr(const FD_ENTRY * f)
{
    LOCAL_ARRAY(char, buf, 32);
    if (f->type != FD_SOCKET)
	return null_string;
    sprintf(buf, "%s.%d", f->ipaddr, (int) f->remote_port);
    return buf;
}

static void
statFiledescriptors(StoreEntry * sentry)
{
    int i;
    FD_ENTRY *f;

    storeAppendPrintf(sentry, open_bracket);
    storeAppendPrintf(sentry, "{Active file descriptors:}\n");
    storeAppendPrintf(sentry, "{%-4s %-6s %-4s %-7s %-7s %-21s %s}\n",
	"File",
	"Type",
	"Tout",
	"Nread",
	"Nwrite",
	"Remote Address",
	"Description");
    storeAppendPrintf(sentry, "{---- ------ ---- ------- ------- --------------------- ------------------------------}\n");
    for (i = 0; i < Squid_MaxFD; i++) {
	f = &fd_table[i];
	if (!f->open)
	    continue;
	storeAppendPrintf(sentry, "{%4d %-6.6s %4d %7d %7d %-21s %s}\n",
	    i,
	    fdstatTypeStr[f->type],
	    f->timeout_handler ? (f->timeout - squid_curtime) / 60 : 0,
	    f->bytes_read,
	    f->bytes_written,
	    fdRemoteAddr(f),
	    f->desc);
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
	meta_data.netdb_addrs * sizeof(netdbEntry) +
	meta_data.netdb_hosts * sizeof(struct _net_db_name) +
                 meta_data.netdb_peers * sizeof(struct _net_db_peer) +
                 meta_data.client_info * client_info_sz +
                 meta_data.misc;
}

void
info_get(StoreEntry * sentry)
{
    const char *tod = NULL;
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
    tod = mkrfc1123(squid_starttime);
    storeAppendPrintf(sentry, "{Start Time:\t%s}\n", tod);
    tod = mkrfc1123(squid_curtime);
    storeAppendPrintf(sentry, "{Current Time:\t%s}\n", tod);
    storeAppendPrintf(sentry, "{Connection information for %s:}\n",
	appname);
    storeAppendPrintf(sentry, "{\tNumber of TCP connections:\t%lu}\n",
	ntcpconn);
    storeAppendPrintf(sentry, "{\tNumber of UDP connections:\t%lu}\n",
	nudpconn);


    f = (float) (squid_curtime - squid_starttime);
    storeAppendPrintf(sentry, "{\tConnections per hour:\t%.1f}\n",
	f == 0.0 ? 0.0 : ((ntcpconn + nudpconn) / (f / 3600.0)));
    storeAppendPrintf(sentry, "{\tSelect loop called: %d times, %0.3f ms avg}\n",
	select_loops, 1000.0 * f / select_loops);

    storeAppendPrintf(sentry, "{Cache information for %s:}\n",
	appname);
    storeAppendPrintf(sentry, "{\tStorage Swap size:\t%d KB}\n",
	store_swap_size);
    storeAppendPrintf(sentry, "{\tStorage Mem size:\t%d KB}\n",
	store_mem_size >> 10);
    storeAppendPrintf(sentry, "{\tStorage LRU Expiration Age:\t%6.2f days}\n",
	(double) storeExpiredReferenceAge() / 86400.0);
    storeAppendPrintf(sentry, "{\tRequests given to unlinkd:\t%d}\n",
	unlinkd_count);
    storeAppendPrintf(sentry, "{\tUnused fileno stack count:\t%d}\n",
	fileno_stack_count);

#if HAVE_GETRUSAGE && defined(RUSAGE_SELF)
    storeAppendPrintf(sentry, "{Resource usage for %s:}\n", appname);
#ifdef _SQUID_SOLARIS_
    /* Solaris 2.5 has getrusage() permission bug -- Arjan de Vet */
    enter_suid();
#endif
    getrusage(RUSAGE_SELF, &rusage);
#ifdef _SQUID_SOLARIS_
    leave_suid();
#endif
    storeAppendPrintf(sentry, "{\tCPU Time: %d seconds (%d user %d sys)}\n",
	(int) rusage.ru_utime.tv_sec + (int) rusage.ru_stime.tv_sec,
	(int) rusage.ru_utime.tv_sec,
	(int) rusage.ru_stime.tv_sec);
    storeAppendPrintf(sentry, "{\tCPU Usage: %d%%}\n",
	percent(rusage.ru_utime.tv_sec + rusage.ru_stime.tv_sec,
	    squid_curtime - squid_starttime));
#if defined(_SQUID_SGI_) || defined(_SQUID_OSF_) || defined(BSD4_4)
    storeAppendPrintf(sentry, "{\tMaximum Resident Size: %ld KB}\n",
	rusage.ru_maxrss);
#else
    storeAppendPrintf(sentry, "{\tMaximum Resident Size: %ld KB}\n",
	(rusage.ru_maxrss * getpagesize()) >> 10);
#endif
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
	Squid_MaxFD);
    storeAppendPrintf(sentry, "{\tLargest file desc currently in use:   %4d}\n",
	Biggest_FD);
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

    storeAppendPrintf(sentry, "{\t%-25.25s                      = %6d KB}\n",
	"URL strings",
	meta_data.url_strings >> 10);

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

    storeAppendPrintf(sentry, "{\t%-25.25s %7d x %4d bytes = %6d KB}\n",
	"NetDB Address Entries",
	meta_data.netdb_addrs,
	(int) sizeof(netdbEntry),
	(int) (meta_data.netdb_addrs * sizeof(netdbEntry) >> 10));

    storeAppendPrintf(sentry, "{\t%-25.25s %7d x %4d bytes = %6d KB}\n",
	"NetDB Host Entries",
	meta_data.netdb_hosts,
	(int) sizeof(struct _net_db_name),
	             (int) (meta_data.netdb_hosts * sizeof(struct _net_db_name) >> 10));

    storeAppendPrintf(sentry, "{\t%-25.25s %7d x %4d bytes = %6d KB}\n",
	"NetDB Peer Entries",
	meta_data.netdb_peers,
	(int) sizeof(struct _net_db_peer),
	             (int) (meta_data.netdb_peers * sizeof(struct _net_db_peer) >> 10));

    storeAppendPrintf(sentry, "{\t%-25.25s %7d x %4d bytes = %6d KB}\n",
	"ClientDB Entries",
	meta_data.client_info,
	client_info_sz,
	(int) (meta_data.client_info * client_info_sz >> 10));

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

void
parameter_get(StoreEntry * sentry)
{
    storeAppendPrintf(sentry, open_bracket);
    storeAppendPrintf(sentry,
	"{VM-Max %d \"# Maximum hot-vm cache (MB)\"}\n",
	Config.Mem.maxSize / (1 << 20));
    storeAppendPrintf(sentry,
	"{VM-High %d \"# High water mark hot-vm cache (%%)\"}\n",
	Config.Mem.highWaterMark);
    storeAppendPrintf(sentry,
	"{VM-Low %d \"# Low water mark hot-vm cache (%%)\"}\n",
	Config.Mem.lowWaterMark);
    storeAppendPrintf(sentry,
	"{Swap-Max %d \"# Maximum disk cache (MB)\"}\n",
	Config.Swap.maxSize / (1 << 10));
    storeAppendPrintf(sentry,
	"{Swap-High %d \"# High water mark disk cache (%%)\"}\n",
	Config.Swap.highWaterMark);
    storeAppendPrintf(sentry,
	"{Swap-Low %d \"# Low water mark disk cache (%%)\"}\n",
	Config.Swap.lowWaterMark);
    storeAppendPrintf(sentry,
	"{Neg-TTL %d \"# TTL for negative cache (s)\"}\n",
	Config.negativeTtl);
    storeAppendPrintf(sentry,
	"{ReadTimeout %d \"# Maximum idle connection (s)\"}\n",
	Config.Timeout.read);
    storeAppendPrintf(sentry, "{DeferTimeout %d\n", Config.Timeout.defer);
    storeAppendPrintf(sentry, "{ClientLifetime %d\n", Config.Timeout.lifetime);
    storeAppendPrintf(sentry,
	"{CleanRate %d \"# Rate for periodic object expiring\"}\n",
	Config.cleanRate);
    /* Cachemgr.cgi expects an integer in the second field of the string */
    storeAppendPrintf(sentry,
	"{HttpAccelMode %d \"# Is operating as an HTTP accelerator\"}\n",
	httpd_accel_mode);
    storeAppendPrintf(sentry, close_bracket);
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
    case LOG_TCP_REFRESH_HIT:
    case LOG_TCP_REFRESH_FAIL_HIT:
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
stat_init(cacheinfo ** object, const char *logfilename)
{
    cacheinfo *obj = NULL;
    int i;

    debug(18, 5) ("stat_init: Initializing...\n");
    obj = xcalloc(1, sizeof(cacheinfo));
    if (logfilename)
	accessLogOpen(logfilename);
    obj->proto_id = urlParseProtocol;
    obj->proto_newobject = proto_newobject;
    obj->proto_purgeobject = proto_purgeobject;
    obj->proto_touchobject = proto_touchobject;
    obj->proto_count = proto_count;
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
