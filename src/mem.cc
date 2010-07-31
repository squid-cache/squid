/*
 * $Id$
 *
 * DEBUG: section 13    High Level Memory Pool Management
 * AUTHOR: Harvest Derived
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
#include "event.h"
#include "CacheManager.h"
#include "ClientInfo.h"
#include "Mem.h"
#include "memMeter.h"
#include "Store.h"
#include "StoreEntryStream.h"
#include "MemBuf.h"
#include "SquidTime.h"

#if HAVE_IOMANIP
#include <iomanip>
#endif
#if HAVE_OSTREAM
#include <ostream>
#endif

/* module globals */

/* local prototypes */
static void memStringStats(std::ostream &);

/* module locals */
static MemAllocator *MemPools[MEM_MAX];
static double xm_time = 0;
static double xm_deltat = 0;

/* string pools */
#define mem_str_pool_count 3

static const struct {
    const char *name;
    size_t obj_size;
}

StrPoolsAttrs[mem_str_pool_count] = {

    {
        "Short Strings", MemAllocator::RoundedSize(36),
    },				/* to fit rfc1123 and similar */
    {
        "Medium Strings", MemAllocator::RoundedSize(128),
    },				/* to fit most urls */
    {
        "Long Strings", MemAllocator::RoundedSize(512)
    }				/* other */
};

static struct {
    MemAllocator *pool;
}

StrPools[mem_str_pool_count];
static MemMeter StrCountMeter;
static MemMeter StrVolumeMeter;

static MemMeter HugeBufCountMeter;
static MemMeter HugeBufVolumeMeter;

/* local routines */

static void
memStringStats(std::ostream &stream)
{
    int i;
    int pooled_count = 0;
    size_t pooled_volume = 0;
    /* heading */
    stream << "String Pool\t Impact\t\t\n \t (%strings)\t (%volume)\n";
    /* table body */

    for (i = 0; i < mem_str_pool_count; i++) {
        const MemAllocator *pool = StrPools[i].pool;
        const int plevel = pool->getMeter().inuse.level;
        stream << std::setw(20) << std::left << pool->objectType();
        stream << std::right << "\t " << xpercentInt(plevel, StrCountMeter.level);
        stream << "\t " << xpercentInt(plevel * pool->objectSize(), StrVolumeMeter.level) << "\n";
        pooled_count += plevel;
        pooled_volume += plevel * pool->objectSize();
    }

    /* malloc strings */
    stream << std::setw(20) << std::left << "Other Strings";

    stream << std::right << "\t ";

    stream << xpercentInt(StrCountMeter.level - pooled_count, StrCountMeter.level) << "\t ";

    stream << xpercentInt(StrVolumeMeter.level - pooled_volume, StrVolumeMeter.level) << "\n\n";
}

static void
memBufStats(std::ostream & stream)
{
    stream << "Large buffers: " <<
    HugeBufCountMeter.level << " (" <<
    HugeBufVolumeMeter.level / 1024 << " KB)\n";
}

void
Mem::Stats(StoreEntry * sentry)
{
    StoreEntryStream stream(sentry);
    Report(stream);
    memStringStats(stream);
    memBufStats(stream);
#if WITH_VALGRIND
    if (RUNNING_ON_VALGRIND) {
        long int leaked = 0, dubious = 0, reachable = 0, suppressed = 0;
        stream << "Valgrind Report:\n";
        stream << "Type\tAmount\n";
        debugs(13, 1, "Asking valgrind for memleaks");
        VALGRIND_DO_LEAK_CHECK;
        debugs(13, 1, "Getting valgrind statistics");
        VALGRIND_COUNT_LEAKS(leaked, dubious, reachable, suppressed);
        stream << "Leaked\t" << leaked << "\n";
        stream << "Dubious\t" << dubious << "\n";
        stream << "Reachable\t" << reachable << "\n";
        stream << "Suppressed\t" << suppressed << "\n";
    }
#endif
    stream.flush();
}

/*
 * public routines
 */

/*
 * we have a limit on _total_ amount of idle memory so we ignore
 * max_pages for now
 */
void
memDataInit(mem_type type, const char *name, size_t size, int max_pages_notused, bool zeroOnPush)
{
    assert(name && size);
    assert(MemPools[type] == NULL);
    MemPools[type] = memPoolCreate(name, size);
    MemPools[type]->zeroOnPush(zeroOnPush);
}


/* find appropriate pool and use it (pools always init buffer with 0s) */
void *
memAllocate(mem_type type)
{
    return MemPools[type]->alloc();
}

/* give memory back to the pool */
void
memFree(void *p, int type)
{
    MemPools[type]->free(p);
}

/* allocate a variable size buffer using best-fit pool */
void *
memAllocString(size_t net_size, size_t * gross_size)
{
    int i;
    MemAllocator *pool = NULL;
    assert(gross_size);

    for (i = 0; i < mem_str_pool_count; i++) {
        if (net_size <= StrPoolsAttrs[i].obj_size) {
            pool = StrPools[i].pool;
            break;
        }
    }

    *gross_size = pool ? StrPoolsAttrs[i].obj_size : net_size;
    assert(*gross_size >= net_size);
    memMeterInc(StrCountMeter);
    memMeterAdd(StrVolumeMeter, *gross_size);
    return pool ? pool->alloc() : xcalloc(1, net_size);
}

extern size_t memStringCount();
size_t
memStringCount()
{
    size_t result = 0;

    for (int counter = 0; counter < mem_str_pool_count; ++counter)
        result += memPoolInUseCount(StrPools[counter].pool);

    return result;
}

/* free buffer allocated with memAllocString() */
void
memFreeString(size_t size, void *buf)
{
    int i;
    MemAllocator *pool = NULL;
    assert(size && buf);

    for (i = 0; i < mem_str_pool_count; i++) {
        if (size <= StrPoolsAttrs[i].obj_size) {
            assert(size == StrPoolsAttrs[i].obj_size);
            pool = StrPools[i].pool;
            break;
        }
    }

    memMeterDec(StrCountMeter);
    memMeterDel(StrVolumeMeter, size);
    pool ? pool->free(buf) : xfree(buf);
}

/* Find the best fit MEM_X_BUF type */
static mem_type
memFindBufSizeType(size_t net_size, size_t * gross_size)
{
    mem_type type;
    size_t size;

    if (net_size <= 2 * 1024) {
        type = MEM_2K_BUF;
        size = 2 * 1024;
    } else if (net_size <= 4 * 1024) {
        type = MEM_4K_BUF;
        size = 4 * 1024;
    } else if (net_size <= 8 * 1024) {
        type = MEM_8K_BUF;
        size = 8 * 1024;
    } else if (net_size <= 16 * 1024) {
        type = MEM_16K_BUF;
        size = 16 * 1024;
    } else if (net_size <= 32 * 1024) {
        type = MEM_32K_BUF;
        size = 32 * 1024;
    } else if (net_size <= 64 * 1024) {
        type = MEM_64K_BUF;
        size = 64 * 1024;
    } else {
        type = MEM_NONE;
        size = net_size;
    }

    if (gross_size)
        *gross_size = size;

    return type;
}

/* allocate a variable size buffer using best-fit pool */
void *
memAllocBuf(size_t net_size, size_t * gross_size)
{
    mem_type type = memFindBufSizeType(net_size, gross_size);

    if (type != MEM_NONE)
        return memAllocate(type);
    else {
        memMeterInc(HugeBufCountMeter);
        memMeterAdd(HugeBufVolumeMeter, *gross_size);
        return xcalloc(1, net_size);
    }
}

/* resize a variable sized buffer using best-fit pool */
void *
memReallocBuf(void *oldbuf, size_t net_size, size_t * gross_size)
{
    /* XXX This can be optimized on very large buffers to use realloc() */
    /* TODO: if the existing gross size is >= new gross size, do nothing */
    size_t new_gross_size;
    void *newbuf = memAllocBuf(net_size, &new_gross_size);

    if (oldbuf) {
        size_t data_size = *gross_size;

        if (data_size > net_size)
            data_size = net_size;

        memcpy(newbuf, oldbuf, data_size);

        memFreeBuf(*gross_size, oldbuf);
    }

    *gross_size = new_gross_size;
    return newbuf;
}

/* free buffer allocated with memAllocBuf() */
void
memFreeBuf(size_t size, void *buf)
{
    mem_type type = memFindBufSizeType(size, NULL);

    if (type != MEM_NONE)
        memFree(buf, type);
    else {
        xfree(buf);
        memMeterDec(HugeBufCountMeter);
        memMeterDel(HugeBufVolumeMeter, size);
    }
}

static double clean_interval = 15.0;	/* time to live of idle chunk before release */

void
Mem::CleanIdlePools(void *unused)
{
    MemPools::GetInstance().clean(static_cast<time_t>(clean_interval));
    eventAdd("memPoolCleanIdlePools", CleanIdlePools, NULL, clean_interval, 1);
}

void
memConfigure(void)
{
    int64_t new_pool_limit;

    /** Set to configured value first */
    if (!Config.onoff.mem_pools)
        new_pool_limit = 0;
    else if (Config.MemPools.limit > 0)
        new_pool_limit = Config.MemPools.limit;
    else {
        if (Config.MemPools.limit == 0)
            debugs(13, 1, "memory_pools_limit 0 has been chagned to memory_pools_limit none. Please update your config");
        new_pool_limit = -1;
    }

#if 0
    /** \par
     * DPW 2007-04-12
     * No debugging here please because this method is called before
     * the debug log is configured and we'll get the message on
     * stderr when doing things like 'squid -k reconfigure'
     */
    if (MemPools::GetInstance().idleLimit() > new_pool_limit)
        debugs(13, 1, "Shrinking idle mem pools to "<< std::setprecision(3) << toMB(new_pool_limit) << " MB");
#endif

    MemPools::GetInstance().setIdleLimit(new_pool_limit);
}

/* XXX make these classes do their own memory management */
#include "HttpHdrContRange.h"

void
Mem::Init(void)
{
    int i;

    /** \par
     * NOTE: Mem::Init() is called before the config file is parsed
     * and before the debugging module has been initialized.  Any
     * debug messages here at level 0 or 1 will always be printed
     * on stderr.
     */

    /** \par
     * Set all pointers to null. */
    memset(MemPools, '\0', sizeof(MemPools));
    /**
     * Then initialize all pools.
     * \par
     * Starting with generic 2kB - 64kB buffr pools, then specific object types.
     * \par
     * It does not hurt much to have a lot of pools since sizeof(MemPool) is
     * small; someday we will figure out what to do with all the entries here
     * that are never used or used only once; perhaps we should simply use
     * malloc() for those? @?@
     */
    memDataInit(MEM_2K_BUF, "2K Buffer", 2048, 10, false);
    memDataInit(MEM_4K_BUF, "4K Buffer", 4096, 10, false);
    memDataInit(MEM_8K_BUF, "8K Buffer", 8192, 10, false);
    memDataInit(MEM_16K_BUF, "16K Buffer", 16384, 10, false);
    memDataInit(MEM_32K_BUF, "32K Buffer", 32768, 10, false);
    memDataInit(MEM_64K_BUF, "64K Buffer", 65536, 10, false);
    memDataInit(MEM_ACL_DENY_INFO_LIST, "acl_deny_info_list",
                sizeof(acl_deny_info_list), 0);
    memDataInit(MEM_ACL_NAME_LIST, "acl_name_list", sizeof(acl_name_list), 0);
#if USE_CACHE_DIGESTS

    memDataInit(MEM_CACHE_DIGEST, "CacheDigest", sizeof(CacheDigest), 0);
#endif

    memDataInit(MEM_LINK_LIST, "link_list", sizeof(link_list), 10);
    memDataInit(MEM_DLINK_NODE, "dlink_node", sizeof(dlink_node), 10);
    memDataInit(MEM_DREAD_CTRL, "dread_ctrl", sizeof(dread_ctrl), 0);
    memDataInit(MEM_DWRITE_Q, "dwrite_q", sizeof(dwrite_q), 0);
    memDataInit(MEM_HTTP_HDR_CC, "HttpHdrCc", sizeof(HttpHdrCc), 0);
    memDataInit(MEM_HTTP_HDR_CONTENT_RANGE, "HttpHdrContRange", sizeof(HttpHdrContRange), 0);
    memDataInit(MEM_NETDBENTRY, "netdbEntry", sizeof(netdbEntry), 0);
    memDataInit(MEM_NET_DB_NAME, "net_db_name", sizeof(net_db_name), 0);
    memDataInit(MEM_RELIST, "relist", sizeof(relist), 0);
    memDataInit(MEM_CLIENT_INFO, "ClientInfo", sizeof(ClientInfo), 0);
    memDataInit(MEM_MD5_DIGEST, "MD5 digest", SQUID_MD5_DIGEST_LENGTH, 0);
    MemPools[MEM_MD5_DIGEST]->setChunkSize(512 * 1024);

    /** Lastly init the string pools. */
    for (i = 0; i < mem_str_pool_count; i++) {
        StrPools[i].pool = memPoolCreate(StrPoolsAttrs[i].name, StrPoolsAttrs[i].obj_size);
        StrPools[i].pool->zeroOnPush(false);

        if (StrPools[i].pool->objectSize() != StrPoolsAttrs[i].obj_size)
            debugs(13, 1, "Notice: " << StrPoolsAttrs[i].name << " is " << StrPools[i].pool->objectSize() << " bytes instead of requested " << StrPoolsAttrs[i].obj_size << " bytes");
    }

    /** \par
     * finally register with the cache manager */
    RegisterWithCacheManager();
}

void
Mem::Report()
{
    debugs(13, 3, "Memory pools are '" <<
           (Config.onoff.mem_pools ? "on" : "off")  << "'; limit: " <<
           std::setprecision(3) << toMB(MemPools::GetInstance().idleLimit()) <<
           " MB");
}

void
Mem::RegisterWithCacheManager(void)
{
    CacheManager::GetInstance()->registerAction("mem", "Memory Utilization",
            Mem::Stats, 0, 1);
}

mem_type &operator++ (mem_type &aMem)
{
    int tmp = (int)aMem;
    aMem = (mem_type)(++tmp);
    return aMem;
}

/*
 * Test that all entries are initialized
 */
void
memCheckInit(void)
{
    mem_type t;

    for (t = MEM_NONE, ++t; t < MEM_MAX; ++t) {
        if (MEM_DONTFREE == t)
            continue;

        /*
         * If you hit this assertion, then you forgot to add a
         * memDataInit() line for type 't'.
         */
        assert(MemPools[t]);
    }
}

void
memClean(void)
{
    MemPoolGlobalStats stats;
    MemPools::GetInstance().setIdleLimit(0);
    MemPools::GetInstance().clean(0);
    memPoolGetGlobalStats(&stats);

    if (stats.tot_items_inuse)
        debugs(13, 2, "memCleanModule: " << stats.tot_items_inuse <<
               " items in " << stats.tot_chunks_inuse << " chunks and " <<
               stats.tot_pools_inuse << " pools are left dirty");
}

int
memInUse(mem_type type)
{
    return memPoolInUseCount(MemPools[type]);
}

/* ick */

void
memFree2K(void *p)
{
    memFree(p, MEM_2K_BUF);
}

void
memFree4K(void *p)
{
    memFree(p, MEM_4K_BUF);
}

void
memFree8K(void *p)
{
    memFree(p, MEM_8K_BUF);
}

void
memFree16K(void *p)
{
    memFree(p, MEM_16K_BUF);
}

void
memFree32K(void *p)
{
    memFree(p, MEM_32K_BUF);
}

void
memFree64K(void *p)
{
    memFree(p, MEM_64K_BUF);
}

FREE *
memFreeBufFunc(size_t size)
{
    switch (size) {

    case 2 * 1024:
        return memFree2K;

    case 4 * 1024:
        return memFree4K;

    case 8 * 1024:
        return memFree8K;

    case 16 * 1024:
        return memFree16K;

    case 32 * 1024:
        return memFree32K;

    case 64 * 1024:
        return memFree64K;

    default:
        memMeterDec(HugeBufCountMeter);
        memMeterDel(HugeBufVolumeMeter, size);
        return xfree;
    }
}

/* MemPoolMeter */

void
Mem::PoolReport(const MemPoolStats * mp_st, const MemPoolMeter * AllMeter, std::ostream &stream)
{
    int excess = 0;
    int needed = 0;
    MemPoolMeter *pm = mp_st->meter;
    const char *delim = "\t ";

#if HAVE_IOMANIP
    stream.setf(std::ios_base::fixed);
#endif
    stream << std::setw(20) << std::left << mp_st->label << delim;
    stream << std::setw(4) << std::right << mp_st->obj_size << delim;

    /* Chunks */
    if (mp_st->chunk_capacity) {
        stream << std::setw(4) << toKB(mp_st->obj_size * mp_st->chunk_capacity) << delim;
        stream << std::setw(4) << mp_st->chunk_capacity << delim;

        needed = mp_st->items_inuse / mp_st->chunk_capacity;

        if (mp_st->items_inuse % mp_st->chunk_capacity)
            needed++;

        excess = mp_st->chunks_inuse - needed;

        stream << std::setw(4) << mp_st->chunks_alloc << delim;
        stream << std::setw(4) << mp_st->chunks_inuse << delim;
        stream << std::setw(4) << mp_st->chunks_free << delim;
        stream << std::setw(4) << mp_st->chunks_partial << delim;
        stream << std::setprecision(3) << xpercent(excess, needed) << delim;
    } else {
        stream << delim;
        stream << delim;
        stream << delim;
        stream << delim;
        stream << delim;
        stream << delim;
        stream << delim;
    }
    /*
     *  Fragmentation calculation:
     *    needed = inuse.level / chunk_capacity
     *    excess = used - needed
     *    fragmentation = excess / needed * 100%
     *
     *    Fragm = (alloced - (inuse / obj_ch) ) / alloced
     */
    /* allocated */
    stream << mp_st->items_alloc << delim;
    stream << toKB(mp_st->obj_size * pm->alloc.level) << delim;
    stream << toKB(mp_st->obj_size * pm->alloc.hwater_level) << delim;
    stream << std::setprecision(2) << ((squid_curtime - pm->alloc.hwater_stamp) / 3600.) << delim;
    stream << std::setprecision(3) << xpercent(mp_st->obj_size * pm->alloc.level, AllMeter->alloc.level) << delim;
    /* in use */
    stream << mp_st->items_inuse << delim;
    stream << toKB(mp_st->obj_size * pm->inuse.level) << delim;
    stream << toKB(mp_st->obj_size * pm->inuse.hwater_level) << delim;
    stream << std::setprecision(2) << ((squid_curtime - pm->inuse.hwater_stamp) / 3600.) << delim;
    stream << std::setprecision(3) << xpercent(pm->inuse.level, pm->alloc.level) << delim;
    /* idle */
    stream << mp_st->items_idle << delim;
    stream << toKB(mp_st->obj_size * pm->idle.level) << delim;
    stream << toKB(mp_st->obj_size * pm->idle.hwater_level) << delim;
    /* saved */
    stream << (int)pm->gb_saved.count << delim;
    stream << std::setprecision(3) << xpercent(pm->gb_saved.count, AllMeter->gb_allocated.count) << delim;
    stream << std::setprecision(3) << xpercent(pm->gb_saved.bytes, AllMeter->gb_allocated.bytes) << delim;
    stream << std::setprecision(3) << xdiv(pm->gb_allocated.count - pm->gb_oallocated.count, xm_deltat) << "\n";
    pm->gb_oallocated.count = pm->gb_allocated.count;
}

static int
MemPoolReportSorter(const void *a, const void *b)
{
    const MemPoolStats *A =  (MemPoolStats *) a;
    const MemPoolStats *B =  (MemPoolStats *) b;

    // use this to sort on %Total Allocated
    //
    double pa = (double) A->obj_size * A->meter->alloc.level;
    double pb = (double) B->obj_size * B->meter->alloc.level;

    if (pa > pb)
        return -1;

    if (pb > pa)
        return 1;

#if 0
    // use this to sort on In Use high(hrs)
    //
    if (A->meter->inuse.hwater_stamp > B->meter->inuse.hwater_stamp)
        return -1;

    if (B->meter->inuse.hwater_stamp > A->meter->inuse.hwater_stamp)
        return 1;

#endif

    return 0;
}

void
Mem::Report(std::ostream &stream)
{
    static char buf[64];
    static MemPoolStats mp_stats;
    static MemPoolGlobalStats mp_total;
    int not_used = 0;
    MemPoolIterator *iter;
    MemAllocator *pool;

    /* caption */
    stream << "Current memory usage:\n";
    /* heading */
    stream << "Pool\t Obj Size\t"
    "Chunks\t\t\t\t\t\t\t"
    "Allocated\t\t\t\t\t"
    "In Use\t\t\t\t\t"
    "Idle\t\t\t"
    "Allocations Saved\t\t\t"
    "Rate\t"
    "\n"
    " \t (bytes)\t"
    "KB/ch\t obj/ch\t"
    "(#)\t used\t free\t part\t %Frag\t "
    "(#)\t (KB)\t high (KB)\t high (hrs)\t %Tot\t"
    "(#)\t (KB)\t high (KB)\t high (hrs)\t %alloc\t"
    "(#)\t (KB)\t high (KB)\t"
    "(#)\t %cnt\t %vol\t"
    "(#)/sec\t"
    "\n";
    xm_deltat = current_dtime - xm_time;
    xm_time = current_dtime;

    /* Get stats for Totals report line */
    memPoolGetGlobalStats(&mp_total);

    MemPoolStats *sortme = (MemPoolStats *) xcalloc(mp_total.tot_pools_alloc ,sizeof(*sortme));
    int npools = 0;

    /* main table */
    iter = memPoolIterate();

    while ((pool = memPoolIterateNext(iter))) {
        pool->getStats(&mp_stats);

        if (!mp_stats.pool)	/* pool destroyed */
            continue;

        if (mp_stats.pool->getMeter().gb_allocated.count > 0)	/* this pool has been used */
            sortme[npools++] = mp_stats;
        else
            not_used++;
    }

    memPoolIterateDone(&iter);

    qsort(sortme, npools, sizeof(*sortme), MemPoolReportSorter);

    for (int i = 0; i< npools; i++) {
        PoolReport(&sortme[i], mp_total.TheMeter, stream);
    }

    xfree(sortme);

    mp_stats.pool = NULL;
    mp_stats.label = "Total";
    mp_stats.meter = mp_total.TheMeter;
    mp_stats.obj_size = 1;
    mp_stats.chunk_capacity = 0;
    mp_stats.chunk_size = 0;
    mp_stats.chunks_alloc = mp_total.tot_chunks_alloc;
    mp_stats.chunks_inuse = mp_total.tot_chunks_inuse;
    mp_stats.chunks_partial = mp_total.tot_chunks_partial;
    mp_stats.chunks_free = mp_total.tot_chunks_free;
    mp_stats.items_alloc = mp_total.tot_items_alloc;
    mp_stats.items_inuse = mp_total.tot_items_inuse;
    mp_stats.items_idle = mp_total.tot_items_idle;
    mp_stats.overhead = mp_total.tot_overhead;

    PoolReport(&mp_stats, mp_total.TheMeter, stream);

    /* Cumulative */
    stream << "Cumulative allocated volume: "<< double_to_str(buf, 64, mp_total.TheMeter->gb_allocated.bytes) << "\n";
    /* overhead */
    stream << "Current overhead: " << mp_total.tot_overhead << " bytes (" <<
    std::setprecision(3) << xpercent(mp_total.tot_overhead, mp_total.TheMeter->inuse.level) << "%)\n";
    /* limits */
    if (mp_total.mem_idle_limit >= 0)
        stream << "Idle pool limit: " << std::setprecision(2) << toMB(mp_total.mem_idle_limit) << " MB\n";
    /* limits */
    stream << "Total Pools created: " << mp_total.tot_pools_alloc << "\n";
    stream << "Pools ever used:     " << mp_total.tot_pools_alloc - not_used << " (shown above)\n";
    stream << "Currently in use:    " << mp_total.tot_pools_inuse << "\n";
}
