
/*
 * $Id: stat.cc,v 1.203 1998/02/22 12:05:24 kostas Exp $
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

/* LOCALS */
static const char *describeStatuses(const StoreEntry *);
static const char *describeFlags(const StoreEntry *);
static const char *describeTimestamps(const StoreEntry *);
static void statAvgTick(void *notused);
static void statAvgDump(StoreEntry *, int minutes);
static void statCountersDump(StoreEntry * sentry);
static void statCounterInit(StatCounters *);
void statLogHistInit(StatLogHist *, double, double);
static int statLogHistBin(StatLogHist *, double);
static double statLogHistVal(StatLogHist *, double);
static double statLogHistDeltaMedian(StatLogHist * A, StatLogHist * B);
static void statLogHistDump(StoreEntry * sentry, StatLogHist * H);
static OBJH stat_io_get;
static OBJH stat_objects_get;
static OBJH stat_vmobjects_get;
static OBJH info_get;
static OBJH statFiledescriptors;
static OBJH statCounters;
static OBJH statAvg5min;
static OBJH statAvg60min;

#ifdef XMALLOC_STATISTICS
static void info_get_mallstat(int, int, StoreEntry *);
#endif

/*
 * An hour's worth, plus the 'current' counter
 */
#define N_COUNT_HIST 61
StatCounters CountHist[N_COUNT_HIST];
static int NCountHist = 0;

void
stat_io_get(StoreEntry * sentry)
{
    int i;

    storeAppendPrintf(sentry, "HTTP I/O\n");
    storeAppendPrintf(sentry, "number of reads: %d\n", IOStats.Http.reads);
    storeAppendPrintf(sentry, "deferred reads: %d (%d%%)\n",
	IOStats.Http.reads_deferred,
	percent(IOStats.Http.reads_deferred, IOStats.Http.reads));
    storeAppendPrintf(sentry, "Read Histogram:\n");
    for (i = 0; i < 16; i++) {
	storeAppendPrintf(sentry, "%5d-%5d: %9d %2d%%\n",
	    i ? (1 << (i - 1)) + 1 : 1,
	    1 << i,
	    IOStats.Http.read_hist[i],
	    percent(IOStats.Http.read_hist[i], IOStats.Http.reads));
    }

    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "FTP I/O\n");
    storeAppendPrintf(sentry, "number of reads: %d\n", IOStats.Ftp.reads);
    storeAppendPrintf(sentry, "deferred reads: %d (%d%%)\n",
	IOStats.Ftp.reads_deferred,
	percent(IOStats.Ftp.reads_deferred, IOStats.Ftp.reads));
    storeAppendPrintf(sentry, "Read Histogram:\n");
    for (i = 0; i < 16; i++) {
	storeAppendPrintf(sentry, "%5d-%5d: %9d %2d%%\n",
	    i ? (1 << (i - 1)) + 1 : 1,
	    1 << i,
	    IOStats.Ftp.read_hist[i],
	    percent(IOStats.Ftp.read_hist[i], IOStats.Ftp.reads));
    }

    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "Gopher I/O\n");
    storeAppendPrintf(sentry, "number of reads: %d\n", IOStats.Gopher.reads);
    storeAppendPrintf(sentry, "deferred reads: %d (%d%%)\n",
	IOStats.Gopher.reads_deferred,
	percent(IOStats.Gopher.reads_deferred, IOStats.Gopher.reads));
    storeAppendPrintf(sentry, "Read Histogram:\n");
    for (i = 0; i < 16; i++) {
	storeAppendPrintf(sentry, "%5d-%5d: %9d %2d%%\n",
	    i ? (1 << (i - 1)) + 1 : 1,
	    1 << i,
	    IOStats.Gopher.read_hist[i],
	    percent(IOStats.Gopher.read_hist[i], IOStats.Gopher.reads));
    }

    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "WAIS I/O\n");
    storeAppendPrintf(sentry, "number of reads: %d\n", IOStats.Wais.reads);
    storeAppendPrintf(sentry, "deferred reads: %d (%d%%)\n",
	IOStats.Wais.reads_deferred,
	percent(IOStats.Wais.reads_deferred, IOStats.Wais.reads));
    storeAppendPrintf(sentry, "Read Histogram:\n");
    for (i = 0; i < 16; i++) {
	storeAppendPrintf(sentry, "%5d-%5d: %9d %2d%%\n",
	    i ? (1 << (i - 1)) + 1 : 1,
	    1 << i,
	    IOStats.Wais.read_hist[i],
	    percent(IOStats.Wais.read_hist[i], IOStats.Wais.reads));
    }
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
    StoreEntry *next = NULL;
    MemObject *mem;
    int N = 0;
    int i;
    struct _store_client *sc;
    next = (StoreEntry *) hash_first(store_table);
    while ((entry = next) != NULL) {
	next = (StoreEntry *) hash_next(store_table);
	mem = entry->mem_obj;
	if (vm_or_not && mem == NULL)
	    continue;
	if ((++N & 0xFF) == 0) {
	    debug(18, 3) ("statObjects:  Processed %d objects...\n", N);
	}
	storeBuffer(sentry);
	storeAppendPrintf(sentry, "KEY %s\n", storeKeyText(entry->key));
	if (mem)
	    storeAppendPrintf(sentry, "\t%s %s\n",
		RequestMethodStr[mem->method], mem->url);
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
	storeAppendPrintf(sentry, "\n");
	storeBufferFlush(sentry);
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

#ifdef XMALLOC_STATISTICS
static void
info_get_mallstat(int size, int number, StoreEntry * sentry)
{
    if (number > 0)
	storeAppendPrintf(sentry, "\t%d = %d\n", size, number);
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
    storeAppendPrintf(sentry, "Active file descriptors:\n");
    storeAppendPrintf(sentry, "%-4s %-6s %-4s %-7s %-7s %-21s %s\n",
	"File",
	"Type",
	"Tout",
	"Nread",
	"Nwrite",
	"Remote Address",
	"Description");
    storeAppendPrintf(sentry, "---- ------ ---- ------- ------- --------------------- ------------------------------\n");
    for (i = 0; i < Squid_MaxFD; i++) {
	f = &fd_table[i];
	if (!f->open)
	    continue;
	storeAppendPrintf(sentry, "%4d %-6.6s %4d %7d %7d %-21s %s\n",
	    i,
	    fdTypeStr[f->type],
	    f->timeout_handler ? (f->timeout - squid_curtime) / 60 : 0,
	    f->bytes_read,
	    f->bytes_written,
	    fdRemoteAddr(f),
	    f->desc);
    }
}

int
statMemoryAccounted(void)
{
    return (int)
	meta_data.store_keys +
	meta_data.ipcache_count * sizeof(ipcache_entry) +
	meta_data.fqdncache_count * sizeof(fqdncache_entry) +
	hash_links_allocated * sizeof(hash_link) +
	meta_data.netdb_peers * sizeof(struct _net_db_peer) +
                 meta_data.client_info * client_info_sz +
                 meta_data.misc;
}

void
info_get(StoreEntry * sentry)
{
    struct rusage rusage;
    double cputime;
    double runtime;
#if HAVE_MSTATS && HAVE_GNUMALLOC_H
    struct mstats ms;
#elif HAVE_MALLINFO
    struct mallinfo mp;
    int t;
#endif

    runtime = tvSubDsec(squid_start, current_time);
    if (runtime == 0.0)
	runtime = 1.0;
    storeAppendPrintf(sentry, "Squid Object Cache: Version %s\n",
	version_string);
    storeAppendPrintf(sentry, "Start Time:\t%s\n",
	mkrfc1123(squid_start.tv_sec));
    storeAppendPrintf(sentry, "Current Time:\t%s\n",
	mkrfc1123(current_time.tv_sec));
    storeAppendPrintf(sentry, "Connection information for %s:\n",
	appname);
    storeAppendPrintf(sentry, "\tNumber of HTTP requests received:\t%u\n",
	Counter.client_http.requests);
    storeAppendPrintf(sentry, "\tNumber of ICP messages received:\t%u\n",
	Counter.icp.pkts_recv);
    storeAppendPrintf(sentry, "\tNumber of ICP messages sent:\t%u\n",
	Counter.icp.pkts_sent);
    storeAppendPrintf(sentry, "\tRequest failure ratio:\t%5.2f%%\n",
	request_failure_ratio);

    storeAppendPrintf(sentry, "\tHTTP requests per minute:\t%.1f\n",
	Counter.client_http.requests / (runtime / 60.0));
    storeAppendPrintf(sentry, "\tICP messages per minute:\t%.1f\n",
	(Counter.icp.pkts_sent + Counter.icp.pkts_recv) / (runtime / 60.0));
    storeAppendPrintf(sentry, "\tSelect loop called: %d times, %0.3f ms avg\n",
	Counter.select_loops, 1000.0 * runtime / Counter.select_loops);

    storeAppendPrintf(sentry, "Cache information for %s:\n",
	appname);
    storeAppendPrintf(sentry, "\tStorage Swap size:\t%d KB\n",
	store_swap_size);
    storeAppendPrintf(sentry, "\tStorage Mem size:\t%d KB\n",
	store_mem_size >> 10);
    storeAppendPrintf(sentry, "\tStorage LRU Expiration Age:\t%6.2f days\n",
	(double) storeExpiredReferenceAge() / 86400.0);
    storeAppendPrintf(sentry, "\tRequests given to unlinkd:\t%d\n",
	Counter.unlink.requests);

    squid_getrusage(&rusage);
    cputime = rusage_cputime(&rusage);
    storeAppendPrintf(sentry, "Resource usage for %s:\n", appname);
    storeAppendPrintf(sentry, "\tUP Time:\t%.3f seconds\n", runtime);
    storeAppendPrintf(sentry, "\tCPU Time:\t%.3f seconds\n", cputime);
    storeAppendPrintf(sentry, "\tCPU Usage:\t%.2f%%\n",
	dpercent(cputime, runtime));
    storeAppendPrintf(sentry, "\tMaximum Resident Size: %ld KB\n",
	rusage_maxrss(&rusage));
    storeAppendPrintf(sentry, "\tPage faults with physical i/o: %ld\n",
	rusage_pagefaults(&rusage));

#if HAVE_MSTATS && HAVE_GNUMALLOC_H
    ms = mstats();
    storeAppendPrintf(sentry, "Memory usage for %s via mstats():\n",
	appname);
    storeAppendPrintf(sentry, "\tTotal space in arena:  %6d KB\n",
	ms.bytes_total >> 10);
    storeAppendPrintf(sentry, "\tTotal free:            %6d KB %d%%\n",
	ms.bytes_free >> 10, percent(ms.bytes_free, ms.bytes_total));
#elif HAVE_MALLINFO
    mp = mallinfo();
    storeAppendPrintf(sentry, "Memory usage for %s via mallinfo():\n",
	appname);
    storeAppendPrintf(sentry, "\tTotal space in arena:  %6d KB\n",
	mp.arena >> 10);
    storeAppendPrintf(sentry, "\tOrdinary blocks:       %6d KB %6d blks\n",
	mp.uordblks >> 10, mp.ordblks);
    storeAppendPrintf(sentry, "\tSmall blocks:          %6d KB %6d blks\n",
	mp.usmblks >> 10, mp.smblks);
    storeAppendPrintf(sentry, "\tHolding blocks:        %6d KB %6d blks\n",
	mp.hblkhd >> 10, mp.hblks);
    storeAppendPrintf(sentry, "\tFree Small blocks:     %6d KB\n",
	mp.fsmblks >> 10);
    storeAppendPrintf(sentry, "\tFree Ordinary blocks:  %6d KB\n",
	mp.fordblks >> 10);
    t = mp.uordblks + mp.usmblks + mp.hblkhd;
    storeAppendPrintf(sentry, "\tTotal in use:          %6d KB %d%%\n",
	t >> 10, percent(t, mp.arena));
    t = mp.fsmblks + mp.fordblks;
    storeAppendPrintf(sentry, "\tTotal free:            %6d KB %d%%\n",
	t >> 10, percent(t, mp.arena));
#if HAVE_EXT_MALLINFO
    storeAppendPrintf(sentry, "\tmax size of small blocks:\t%d\n", mp.mxfast);
    storeAppendPrintf(sentry, "\tnumber of small blocks in a holding block:\t%d\n",
	mp.nlblks);
    storeAppendPrintf(sentry, "\tsmall block rounding factor:\t%d\n", mp.grain);
    storeAppendPrintf(sentry, "\tspace (including overhead) allocated in ord. blks:\t%d\n"
	,mp.uordbytes);
    storeAppendPrintf(sentry, "\tnumber of ordinary blocks allocated:\t%d\n",
	mp.allocated);
    storeAppendPrintf(sentry, "\tbytes used in maintaining the free tree:\t%d\n",
	mp.treeoverhead);
#endif /* HAVE_EXT_MALLINFO */
#endif /* HAVE_MALLINFO */

    storeAppendPrintf(sentry, "File descriptor usage for %s:\n", appname);
    storeAppendPrintf(sentry, "\tMaximum number of file descriptors:   %4d\n",
	Squid_MaxFD);
    storeAppendPrintf(sentry, "\tLargest file desc currently in use:   %4d\n",
	Biggest_FD);
    storeAppendPrintf(sentry, "\tNumber of file desc currently in use: %4d\n",
	Number_FD);
    storeAppendPrintf(sentry, "\tAvailable number of file descriptors: %4d\n",
	Squid_MaxFD - Number_FD);
    storeAppendPrintf(sentry, "\tReserved number of file descriptors:  %4d\n",
	RESERVED_FD);

    storeAppendPrintf(sentry, "Internal Data Structures:\n");
    storeAppendPrintf(sentry, "\t%6d StoreEntries\n",
	memInUse(MEM_STOREENTRY));
    storeAppendPrintf(sentry, "\t%6d StoreEntries with MemObjects\n",
	memInUse(MEM_MEMOBJECT));
    storeAppendPrintf(sentry, "\t%6d StoreEntries with MemObject Data\n",
	memInUse(MEM_MEM_HDR));
    storeAppendPrintf(sentry, "\t%6d Hot Object Cache Items\n",
	meta_data.hot_vm);

    storeAppendPrintf(sentry, "\t%-25.25s                      = %6d KB\n",
	"StoreEntry Keys",
	meta_data.store_keys >> 10);

    storeAppendPrintf(sentry, "\t%-25.25s %7d x %4d bytes = %6d KB\n",
	"IPCacheEntry",
	meta_data.ipcache_count,
	(int) sizeof(ipcache_entry),
	(int) (meta_data.ipcache_count * sizeof(ipcache_entry) >> 10));

    storeAppendPrintf(sentry, "\t%-25.25s %7d x %4d bytes = %6d KB\n",
	"FQDNCacheEntry",
	meta_data.fqdncache_count,
	(int) sizeof(fqdncache_entry),
	(int) (meta_data.fqdncache_count * sizeof(fqdncache_entry) >> 10));

    storeAppendPrintf(sentry, "\t%-25.25s %7d x %4d bytes = %6d KB\n",
	"Hash link",
	hash_links_allocated,
	(int) sizeof(hash_link),
	(int) (hash_links_allocated * sizeof(hash_link) >> 10));

    storeAppendPrintf(sentry, "\t%-25.25s %7d x %4d bytes = %6d KB\n",
	"NetDB Peer Entries",
	meta_data.netdb_peers,
	(int) sizeof(struct _net_db_peer),
	             (int) (meta_data.netdb_peers * sizeof(struct _net_db_peer) >> 10));

    storeAppendPrintf(sentry, "\t%-25.25s %7d x %4d bytes = %6d KB\n",
	"ClientDB Entries",
	meta_data.client_info,
	client_info_sz,
	(int) (meta_data.client_info * client_info_sz >> 10));

    storeAppendPrintf(sentry, "\t%-25.25s                      = %6d KB\n",
	"Miscellaneous",
	meta_data.misc >> 10);

    storeAppendPrintf(sentry, "\t%-25.25s                      = %6d KB\n",
	"Total Accounted",
	statMemoryAccounted() >> 10);

#if XMALLOC_STATISTICS
    storeAppendPrintf(sentry, "Memory allocation statistics\n");
    malloc_statistics(info_get_mallstat, sentry);
#endif
}

static void
statCountersDump(StoreEntry * sentry)
{
    StatCounters *f = &Counter;
    struct rusage rusage;
    squid_getrusage(&rusage);
    f->page_faults = rusage_pagefaults(&rusage);
    f->cputime = rusage_cputime(&rusage);
    storeAppendPrintf(sentry, "client_http.requests = %d\n",
	f->client_http.requests);
    storeAppendPrintf(sentry, "client_http.hits = %d\n",
	f->client_http.hits);
    storeAppendPrintf(sentry, "client_http.errors = %d\n",
	f->client_http.errors);
    storeAppendPrintf(sentry, "client_http.kbytes_in = %d\n",
	(int) f->client_http.kbytes_in.kb);
    storeAppendPrintf(sentry, "client_http.kbytes_out = %d\n",
	(int) f->client_http.kbytes_out.kb);
    storeAppendPrintf(sentry, "client_http.svc_time histogram:\n");
    statLogHistDump(sentry, &f->client_http.svc_time);
    storeAppendPrintf(sentry, "icp.pkts_sent = %d\n",
	f->icp.pkts_sent);
    storeAppendPrintf(sentry, "icp.pkts_recv = %d\n",
	f->icp.pkts_recv);
    storeAppendPrintf(sentry, "icp.kbytes_sent = %d\n",
	(int) f->icp.kbytes_sent.kb);
    storeAppendPrintf(sentry, "icp.kbytes_recv = %d\n",
	(int) f->icp.kbytes_recv.kb);
    storeAppendPrintf(sentry, "icp.svc_time histogram:\n");
    statLogHistDump(sentry, &f->icp.svc_time);
    storeAppendPrintf(sentry, "dns.svc_time histogram:\n");
    statLogHistDump(sentry, &f->dns.svc_time);
    storeAppendPrintf(sentry, "unlink.requests = %d\n",
	f->unlink.requests);
    storeAppendPrintf(sentry, "page_faults = %d\n",
	f->page_faults);
    storeAppendPrintf(sentry, "select_loops = %d\n",
	f->select_loops);
    storeAppendPrintf(sentry, "cpu_time = %f\n",
	f->cputime);
    storeAppendPrintf(sentry, "wall_time = %f\n",
	tvSubDsec(f->timestamp, current_time));
}

#define XAVG(X) (dt ? (double) (f->X - l->X) / dt : 0.0)
static void
statAvgDump(StoreEntry * sentry, int minutes)
{
    StatCounters *f;
    StatCounters *l;
    double dt;
    double ct;
    double x;
    assert(N_COUNT_HIST > 1);
    assert(minutes > 0);
    f = &CountHist[0];
    if (minutes > N_COUNT_HIST - 1)
	minutes = N_COUNT_HIST - 1;
    l = &CountHist[minutes];
    dt = tvSubDsec(l->timestamp, f->timestamp);
    ct = f->cputime - l->cputime;
    storeAppendPrintf(sentry, "client_http.requests = %f/sec\n",
	XAVG(client_http.requests));
    storeAppendPrintf(sentry, "client_http.hits = %f/sec\n",
	XAVG(client_http.hits));
    storeAppendPrintf(sentry, "client_http.errors = %f/sec\n",
	XAVG(client_http.errors));
    storeAppendPrintf(sentry, "client_http.kbytes_in = %f/sec\n",
	XAVG(client_http.kbytes_in.kb));
    storeAppendPrintf(sentry, "client_http.kbytes_out = %f/sec\n",
	XAVG(client_http.kbytes_out.kb));
    x = statLogHistDeltaMedian(&l->client_http.svc_time, &f->client_http.svc_time);
    storeAppendPrintf(sentry, "client_http.median_svc_time = %f seconds\n",
	x / 1000.0);
    storeAppendPrintf(sentry, "icp.pkts_sent = %f/sec\n",
	XAVG(icp.pkts_sent));
    storeAppendPrintf(sentry, "icp.pkts_recv = %f/sec\n",
	XAVG(icp.pkts_recv));
    storeAppendPrintf(sentry, "icp.kbytes_sent = %f/sec\n",
	XAVG(icp.kbytes_sent.kb));
    storeAppendPrintf(sentry, "icp.kbytes_recv = %f/sec\n",
	XAVG(icp.kbytes_recv.kb));
    x = statLogHistDeltaMedian(&l->icp.svc_time, &f->icp.svc_time);
    storeAppendPrintf(sentry, "icp.median_svc_time = %f seconds\n",
	x / 1000000.0);
    x = statLogHistDeltaMedian(&l->dns.svc_time, &f->dns.svc_time);
    storeAppendPrintf(sentry, "dns.median_svc_time = %f seconds\n",
	x / 1000.0);
    storeAppendPrintf(sentry, "unlink.requests = %f/sec\n",
	XAVG(unlink.requests));
    storeAppendPrintf(sentry, "page_faults = %f/sec\n",
	XAVG(page_faults));
    storeAppendPrintf(sentry, "select_loops = %f/sec\n",
	XAVG(select_loops));
    storeAppendPrintf(sentry, "cpu_time = %f seconds\n", ct);
    storeAppendPrintf(sentry, "wall_time = %f seconds\n", dt);
    storeAppendPrintf(sentry, "cpu_usage = %f%%\n", dpercent(ct, dt));
}

static void
statCounterInit(StatCounters * C)
{
    C->timestamp = current_time;
    /*
     * HTTP svc_time hist is kept in milli-seconds; max of 3 hours.
     */
    statLogHistInit(&C->client_http.svc_time, 0.0, 3600000.0 * 3.0);
    /*
     * ICP svc_time hist is kept in micro-seconds; max of 1 minute.
     */
    statLogHistInit(&C->icp.svc_time, 0.0, 1000000.0 * 60.0);
    /*
     * DNS svc_time hist is kept in milli-seconds; max of 10 minutes.
     */
    statLogHistInit(&C->dns.svc_time, 0.0, 60000.0 * 10.0);
}

void
statInit(void)
{
    int i;
    debug(18, 5) ("statInit: Initializing...\n");
    memset(CountHist, '\0', N_COUNT_HIST * sizeof(StatCounters));
    for (i = 0; i < N_COUNT_HIST; i++)
	statCounterInit(&CountHist[i]);
    statCounterInit(&Counter);
    eventAdd("statAvgTick", statAvgTick, NULL, 60);
    cachemgrRegister("info",
	"General Runtime Information",
	info_get, 0);
    cachemgrRegister("filedescriptors",
	"Process Filedescriptor Allocation",
	statFiledescriptors, 0);
    cachemgrRegister("objects",
	"All Cache Objects",
	stat_objects_get, 0);
    cachemgrRegister("vm_objects",
	"In-Memory and In-Transit Objects",
	stat_vmobjects_get, 0);
    cachemgrRegister("io",
	"Server-side network read() size histograms",
	stat_io_get, 0);
    cachemgrRegister("counters",
	"Traffic and Resource Counters",
	statCounters, 0);
    cachemgrRegister("5min",
	"5 Minute Average of Counters",
	statAvg5min, 0);
    cachemgrRegister("60min",
	"60 Minute Average of Counters",
	statAvg60min, 0);
}

static void
statAvgTick(void *notused)
{
    StatCounters *t = &CountHist[0];
    StatCounters *p = &CountHist[1];
    StatCounters *c = &Counter;
    struct rusage rusage;
    eventAdd("statAvgTick", statAvgTick, NULL, 60);
    squid_getrusage(&rusage);
    c->page_faults = rusage_pagefaults(&rusage);
    c->cputime = rusage_cputime(&rusage);
    c->timestamp = current_time;
    xmemmove(p, t, (N_COUNT_HIST - 1) * sizeof(StatCounters));
    memcpy(t, c, sizeof(StatCounters));
    NCountHist++;
}

void
statCounters(StoreEntry * e)
{
    statCountersDump(e);
}

void
statAvg5min(StoreEntry * e)
{
    statAvgDump(e, 5);
}

void
statAvg60min(StoreEntry * e)
{
    statAvgDump(e, 60);
}

void
statLogHistInit(StatLogHist * H, double min, double max)
{
    H->min = min;
    H->max = max;
    H->scale = (STAT_LOG_HIST_BINS - 1) / log(1.0 + max - min);
}

void
statLogHistCount(StatLogHist * H, double val)
{
    int bin = statLogHistBin(H, val);
    assert(H->scale != 0.0);	/* make sure it got initialized */
    assert(0 <= bin && bin < STAT_LOG_HIST_BINS);
    H->bins[bin]++;
}

double
statLogHistDeltaMedian(StatLogHist * A, StatLogHist * B)
{
    StatLogHist D;
    int i;
    int s1 = 0;
    int h = 0;
    int a = 0;
    int b = 0;
    int I = 0;
    int J = STAT_LOG_HIST_BINS;
    int K;
    double f;
    memset(&D, '\0', sizeof(StatLogHist));
    for (i = 0; i < STAT_LOG_HIST_BINS; i++) {
	assert(B->bins[i] >= A->bins[i]);
	D.bins[i] = B->bins[i] - A->bins[i];
    }
    for (i = 0; i < STAT_LOG_HIST_BINS; i++)
	s1 += D.bins[i];
    h = s1 >> 1;
    for (i = 0; i < STAT_LOG_HIST_BINS; i++) {
	J = i;
	b += D.bins[J];
	if (a <= h && h <= b)
	    break;
	I = i;
	a += D.bins[I];
    }
    if (s1 == 0)
	return 0.0;
    if (a > h) {
	debug(0, 0) ("statLogHistDeltaMedian: a=%d, h=%d\n", a, h);
	return 0.0;
    }
    if (a >= b) {
	debug(0, 0) ("statLogHistDeltaMedian: a=%d, b=%d\n", a, b);
	return 0.0;
    }
    if (I >= J) {
	debug(0, 0) ("statLogHistDeltaMedian: I=%d, J=%d\n", I, J);
	return 0.0;
    }
    f = (h - a) / (b - a);
    K = f * (double) (J - I) + I;
    return statLogHistVal(A, K);
}

static int
statLogHistBin(StatLogHist * H, double v)
{
    int bin;
    double x = 1.0 + v - H->min;
    if (x < 0.0)
	return 0;
    bin = (int) (H->scale * log(x) + 0.5);
    if (bin < 0)
	bin = 0;
    if (bin > STAT_LOG_HIST_BINS - 1)
	bin = STAT_LOG_HIST_BINS - 1;
    return bin;
}

static double
statLogHistVal(StatLogHist * H, double bin)
{
    return exp(bin / H->scale) + H->min - 1.0;
}

enum { HTTP_SVC, ICP_SVC, DNS_SVC };

int 
get_median_svc(int interval, int which)
{
    StatCounters *f;
    StatCounters *l;
    double x;

    f = &CountHist[0];
    l = &CountHist[interval];
	assert(f);
	assert(l);
    switch (which) {
    case HTTP_SVC:
        x = statLogHistDeltaMedian(&l->client_http.svc_time, &f->client_http.svc_time);
        break;
    case ICP_SVC:
        x = statLogHistDeltaMedian(&l->icp.svc_time, &f->icp.svc_time);
        break;
    case DNS_SVC:
        x = statLogHistDeltaMedian(&l->dns.svc_time, &f->dns.svc_time);
        break;
    default:
        debug(49,5)("get_median_val: unknown type.\n");
        x=0;
    }
    return (int)x;
}
static void
statLogHistDump(StoreEntry * sentry, StatLogHist * H)
{
    int i;
    for (i = 0; i < STAT_LOG_HIST_BINS; i++) {
	if (H->bins[i] == 0)
	    continue;
	storeAppendPrintf(sentry, "\t%3d/%f\t%d\n",
	    i,
	    statLogHistVal(H, 0.5 + i),
	    H->bins[i]);
    }
}
