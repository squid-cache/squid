
/*
 * $Id: stat.cc,v 1.169 1997/11/12 00:09:06 wessels Exp $
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

/* LOCALS */
static const char *describeStatuses(const StoreEntry *);
static const char *describeFlags(const StoreEntry *);
static const char *describeTimestamps(const StoreEntry *);
static void proto_count(cacheinfo *, protocol_t, log_type);
static void proto_newobject(cacheinfo *, protocol_t, int, int);
static void proto_purgeobject(cacheinfo *, protocol_t, int);
static void proto_touchobject(cacheinfo *, protocol_t, int);
static int memoryAccounted(void);

#ifdef XMALLOC_STATISTICS
static void info_get_mallstat(int, int, StoreEntry *);
#endif

#define PCONN_HIST_SZ 256
int client_pconn_hist[PCONN_HIST_SZ];
int server_pconn_hist[PCONN_HIST_SZ];

/* process utilization information */
static void
statUtilization(cacheinfo * obj, StoreEntry * sentry, const char *desc)
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

void
stat_utilization_get(StoreEntry * e)
{
    statUtilization(HTTPCacheInfo, e, "HTTP");
    statUtilization(ICPCacheInfo, e, "ICP");
}

void
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
    snprintf(buf, 256, "%-13s %-13s %-12s %-12s",
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
    if (EBIT_TEST(flags, DELAY_SENDING))
	strcat(buf, "DS,");
    if (EBIT_TEST(flags, RELEASE_REQUEST))
	strcat(buf, "RL,");
    if (EBIT_TEST(flags, REFRESH_REQUEST))
	strcat(buf, "RF,");
    if (EBIT_TEST(flags, ENTRY_CACHABLE))
	strcat(buf, "EC,");
    if (EBIT_TEST(flags, ENTRY_DISPATCHED))
	strcat(buf, "ED,");
    if (EBIT_TEST(flags, KEY_PRIVATE))
	strcat(buf, "KP,");
    if (EBIT_TEST(flags, HIERARCHICAL))
	strcat(buf, "HI,");
    if (EBIT_TEST(flags, ENTRY_NEGCACHED))
	strcat(buf, "NG,");
    if ((t = strrchr(buf, ',')))
	*t = '\0';
    return buf;
}

static const char *
describeTimestamps(const StoreEntry * entry)
{
    LOCAL_ARRAY(char, buf, 256);
    snprintf(buf, 256, "LV:%-9d LU:%-9d LM:%-9d EX:%-9d",
	(int) entry->timestamp,
	(int) entry->lastref,
	(int) entry->lastmod,
	(int) entry->expires);
    return buf;
}

/* process objects list */
static void
statObjects(StoreEntry * sentry, int vm_or_not)
{
    StoreEntry *entry = NULL;
    MemObject *mem;
    int N = 0;
    int i;
    struct _store_client *sc;
    for (entry = storeGetFirst(); entry != NULL; entry = storeGetNext()) {
	mem = entry->mem_obj;
	if (vm_or_not && mem == NULL)
	    continue;
	if ((++N & 0xFF) == 0) {
	    debug(18, 3) ("stat_objects_get:  Processed %d objects...\n", N);
	}
	EBIT_SET(sentry->flag, DELAY_SENDING);
	storeAppendPrintf(sentry, "KEY %s\n", storeKeyText(entry->key));
	storeAppendPrintf(sentry, "\t%s %s\n",
	    RequestMethodStr[entry->method], storeUrl(entry));
	storeAppendPrintf(sentry, "\t%s\n", describeStatuses(entry));
	storeAppendPrintf(sentry, "\t%s\n", describeFlags(entry));
	storeAppendPrintf(sentry, "\t%s\n", describeTimestamps(entry));
	storeAppendPrintf(sentry, "\t%d locks, %d clients, %d refs\n",
	    (int) entry->lock_count,
	    storePendingNClients(entry),
	    (int) entry->refcount);
	storeAppendPrintf(sentry, "\tSwap File %#08X\n",
	    entry->swap_file_number);
	if (mem == NULL)
	    continue;
	storeAppendPrintf(sentry, "\tinmem_lo: %d\n", (int) mem->inmem_lo);
	storeAppendPrintf(sentry, "\tinmem_hi: %d\n", (int) mem->inmem_hi);
	storeAppendPrintf(sentry, "\tswapout: %d bytes done, %d queued, FD %d\n",
	    mem->swapout.done_offset,
	    mem->swapout.queue_offset,
	    mem->swapout.fd);
	for (i = 0; i < mem->nclients; i++) {
	    sc = &mem->clients[i];
	    if (sc->callback_data == NULL)
		continue;
	    storeAppendPrintf(sentry, "\tClient #%d\n", i);
	    storeAppendPrintf(sentry, "\t\tcopy_offset: %d\n",
		(int) sc->copy_offset);
	    storeAppendPrintf(sentry, "\t\tseen_offset: %d\n",
		(int) sc->seen_offset);
	    storeAppendPrintf(sentry, "\t\tcopy_size: %d\n",
		(int) sc->copy_size);
	    storeAppendPrintf(sentry, "\t\tswapin_fd: %d\n",
		(int) sc->swapin_fd);
	}
	EBIT_CLR(sentry->flag, DELAY_SENDING);
	storeAppendPrintf(sentry, "\n");
    }
}

void
stat_objects_get(StoreEntry * e)
{
    statObjects(e, 0);
}

void
stat_vmobjects_get(StoreEntry * e)
{
    statObjects(e, 1);
}

void
server_list(StoreEntry * sentry)
{
    dump_peers(sentry, Config.peers);
}

void
dump_peers(StoreEntry * sentry, peer * peers)
{
    peer *e = NULL;
    struct _domain_ping *d = NULL;
    icp_opcode op;
    storeAppendPrintf(sentry, open_bracket);
    if (peers == NULL)
	storeAppendPrintf(sentry, "{There are no neighbors installed.}\n");
    for (e = peers; e; e = e->next) {
	assert(e->host != NULL);
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
	storeAppendPrintf(sentry, "{Keep-Alive Ratio: %d%%}\n",
	    percent(e->stats.n_keepalives_recv, e->stats.n_keepalives_sent));
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
fdRemoteAddr(const fde * f)
{
    LOCAL_ARRAY(char, buf, 32);
    if (f->type != FD_SOCKET)
	return null_string;
    snprintf(buf, 32, "%s.%d", f->ipaddr, (int) f->remote_port);
    return buf;
}

void
statFiledescriptors(StoreEntry * sentry)
{
    int i;
    fde *f;
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
	meta_data.store_keys +
	meta_data.ipcache_count * sizeof(ipcache_entry) +
	meta_data.fqdncache_count * sizeof(fqdncache_entry) +
	hash_links_allocated * sizeof(hash_link) +
	sm_stats.total_pages_allocated * sm_stats.page_size +
	disk_stats.total_pages_allocated * disk_stats.page_size +
	request_pool.total_pages_allocated * request_pool.page_size +
	mem_obj_pool.total_pages_allocated * mem_obj_pool.page_size +
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
#if defined(HAVE_GETRUSAGE) && defined(RUSAGE_SELF)
    struct rusage rusage;
#endif
#if HAVE_MSTATS && HAVE_GNUMALLOC_H
    struct mstats ms;
#elif HAVE_MALLINFO
    struct mallinfo mp;
    int t;
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

#if HAVE_MSTATS && HAVE_GNUMALLOC_H
    ms = mstats();
    storeAppendPrintf(sentry, "{Memory usage for %s via mstats():}\n",
	appname);
    storeAppendPrintf(sentry, "{\tTotal space in arena:  %6d KB}\n",
	ms.bytes_total >> 10);
    storeAppendPrintf(sentry, "{\tTotal free:            %6d KB %d%%}\n",
	ms.bytes_free >> 10, percent(ms.bytes_free, ms.bytes_total));
#elif HAVE_MALLINFO
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
    storeAppendPrintf(sentry, "{\tMaximum number of file descriptors:   %4d}\n",
	Squid_MaxFD);
    storeAppendPrintf(sentry, "{\tLargest file desc currently in use:   %4d}\n",
	Biggest_FD);
    storeAppendPrintf(sentry, "{\tNumber of file desc currently in use: %4d}\n",
	Number_FD);
    storeAppendPrintf(sentry, "{\tAvailable number of file descriptors: %4d}\n",
	Squid_MaxFD - Number_FD);
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
	"StoreEntry Keys",
	meta_data.store_keys >> 10);

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
    for (i = 0; i < PCONN_HIST_SZ; i++) {
	client_pconn_hist[i] = 0;
	server_pconn_hist[i] = 0;
    }
}

void
pconnHistCount(int what, int i)
{
    if (i >= PCONN_HIST_SZ)
	i = PCONN_HIST_SZ - 1;
    /* what == 0 for client, 1 for server */
    if (what == 0)
	client_pconn_hist[i]++;
    else if (what == 1)
	server_pconn_hist[i]++;
    else
	fatal_dump("pconnHistCount: bad 'what' arg");
}

void
pconnHistDump(StoreEntry * e)
{
    int i;
    storeAppendPrintf(e,
	"Client-side persistent connection counts:\n"
	"\n"
	"\treq/\n"
	"\tconn      count\n"
	"\t----  ---------\n");
    for (i = 0; i < PCONN_HIST_SZ; i++) {
	if (client_pconn_hist[i] == 0)
	    continue;
	storeAppendPrintf(e, "\t%4d  %9d\n", i, client_pconn_hist[i]);
    }
    storeAppendPrintf(e,
	"\n"
	"Server-side persistent connection counts:\n"
	"\n"
	"\treq/\n"
	"\tconn      count\n"
	"\t----  ---------\n");
    for (i = 0; i < PCONN_HIST_SZ; i++) {
	if (server_pconn_hist[i] == 0)
	    continue;
	storeAppendPrintf(e, "\t%4d  %9d\n", i, server_pconn_hist[i]);
    }
}
