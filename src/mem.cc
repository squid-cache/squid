
/*
 * $Id: mem.cc,v 1.28 1998/07/20 17:19:52 wessels Exp $
 *
 * DEBUG: section 13    High Level Memory Pool Management
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *  
 */

#include "squid.h"

/* module globals */

static MemPool *MemPools[MEM_MAX];

/* string pools */
#define mem_str_pool_count 3
static const struct {
    const char *name;
    size_t obj_size;
} StrPoolsAttrs[mem_str_pool_count] = {

    {
	"Short Strings", 36,
    },				/* to fit rfc1123 and similar */
    {
	"Medium Strings", 128,
    },				/* to fit most urls */
    {
	"Long Strings", 512
    }				/* other */
};
static struct {
    MemPool *pool;
} StrPools[mem_str_pool_count];
static MemMeter StrCountMeter;
static MemMeter StrVolumeMeter;


/* local routines */

/*
 * we have a limit on _total_ amount of idle memory so we ignore
 * max_pages for now
 */
static void
memDataInit(mem_type type, const char *name, size_t size, int max_pages_notused)
{
    assert(name && size);
    MemPools[type] = memPoolCreate(name, size);
}

static void
memStringStats(StoreEntry * sentry)
{
    const char *pfmt = "%-20s\t %d\t %d\n";
    int i;
    int pooled_count = 0;
    size_t pooled_volume = 0;
    /* heading */
    storeAppendPrintf(sentry,
	"String Pool\t Impact\t\t\n"
	" \t (%%strings)\t (%%volume)\n");
    /* table body */
    for (i = 0; i < mem_str_pool_count; i++) {
	const MemPool *pool = StrPools[i].pool;
	const int plevel = pool->meter.inuse.level;
	storeAppendPrintf(sentry, pfmt,
	    pool->label,
	    xpercentInt(plevel, StrCountMeter.level),
	    xpercentInt(plevel * pool->obj_size, StrVolumeMeter.level));
	pooled_count += plevel;
	pooled_volume += plevel * pool->obj_size;
    }
    /* malloc strings */
    storeAppendPrintf(sentry, pfmt,
	"Other Strings",
	xpercentInt(StrCountMeter.level - pooled_count, StrCountMeter.level),
	xpercentInt(StrVolumeMeter.level - pooled_volume, StrVolumeMeter.level));
}

static void
memStats(StoreEntry * sentry)
{
    storeBuffer(sentry);
    memReport(sentry);
    memStringStats(sentry);
    storeBufferFlush(sentry);
}


/*
 * public routines
 */


/* find appropriate pool and use it (pools always init buffer with 0s) */
void *
memAllocate(mem_type type)
{
    return memPoolAlloc(MemPools[type]);
}

/* find appropriate pool and use it */
void
memFree(mem_type type, void *p)
{
    memPoolFree(MemPools[type], p);
}

/* allocate a variable size buffer using best-fit pool */
void *
memAllocBuf(size_t net_size, size_t * gross_size)
{
    int i;
    MemPool *pool = NULL;
    assert(gross_size);
    for (i = 0; i < mem_str_pool_count; i++) {
	if (net_size <= StrPoolsAttrs[i].obj_size) {
	    pool = StrPools[i].pool;
	    break;
	}
    }
    *gross_size = pool ? pool->obj_size : net_size;
    assert(*gross_size >= net_size);
    memMeterInc(StrCountMeter);
    memMeterAdd(StrVolumeMeter, *gross_size);
    return pool ? memPoolAlloc(pool) : xcalloc(1, net_size);
}

/* free buffer allocated with memAllocBuf() */
void
memFreeBuf(size_t size, void *buf)
{
    int i;
    MemPool *pool = NULL;
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
    pool ? memPoolFree(pool, buf) : xfree(buf);
}

void
memInit(void)
{
    int i;
    mem_type t;
    memInitModule();
    /* set all pointers to null */
    memset(MemPools, '\0', sizeof(MemPools));
    /*
     * it does not hurt much to have a lot of pools since sizeof(MemPool) is
     * small; someday we will figure out what to do with all the entries here
     * that are never used or used only once; perhaps we should simply use
     * malloc() for those? @?@
     */
    memDataInit(MEM_2K_BUF, "2K Buffer", 2048, 10);
    memDataInit(MEM_4K_BUF, "4K Buffer", 4096, 10);
    memDataInit(MEM_8K_BUF, "8K Buffer", 8192, 10);
    memDataInit(MEM_ACCESSLOGENTRY, "AccessLogEntry",
	sizeof(AccessLogEntry), 10);
    memDataInit(MEM_ACL, "acl", sizeof(acl), 0);
    memDataInit(MEM_ACLCHECK_T, "aclCheck_t", sizeof(aclCheck_t), 0);
    memDataInit(MEM_ACL_ACCESS, "acl_access", sizeof(acl_access), 0);
    memDataInit(MEM_ACL_DENY_INFO_LIST, "acl_deny_info_list",
	sizeof(acl_deny_info_list), 0);
    memDataInit(MEM_ACL_IP_DATA, "acl_ip_data", sizeof(acl_ip_data), 0);
    memDataInit(MEM_ACL_LIST, "acl_list", sizeof(acl_list), 0);
    memDataInit(MEM_ACL_NAME_LIST, "acl_name_list", sizeof(acl_name_list), 0);
    memDataInit(MEM_ACL_TIME_DATA, "acl_time_data", sizeof(acl_time_data), 0);
    memDataInit(MEM_ACL_PROXY_AUTH_USER, "acl_proxy_auth_user",
	sizeof(acl_proxy_auth_user), 0);
    memDataInit(MEM_AIO_RESULT_T, "aio_result_t", sizeof(aio_result_t), 0);
    memDataInit(MEM_CACHEMGR_PASSWD, "cachemgr_passwd",
	sizeof(cachemgr_passwd), 0);
    memDataInit(MEM_CACHE_DIGEST, "CacheDigest", sizeof(CacheDigest), 0);
    memDataInit(MEM_CLIENTHTTPREQUEST, "clientHttpRequest",
	sizeof(clientHttpRequest), 0);
    memDataInit(MEM_CLOSE_HANDLER, "close_handler", sizeof(close_handler), 0);
    memDataInit(MEM_COMMWRITESTATEDATA, "CommWriteStateData",
	sizeof(CommWriteStateData), 0);
    memDataInit(MEM_CONNSTATEDATA, "ConnStateData", sizeof(ConnStateData), 0);
    memDataInit(MEM_DISK_BUF, "Disk I/O Buffer", DISK_PAGE_SIZE, 200);
    memDataInit(MEM_DLINK_LIST, "dlink_list", sizeof(dlink_list), 10);
    memDataInit(MEM_DLINK_NODE, "dlink_node", sizeof(dlink_node), 10);
    memDataInit(MEM_DNSSERVER_T, "dnsserver_t", sizeof(dnsserver_t), 0);
    memDataInit(MEM_DNSSTATDATA, "dnsStatData", sizeof(dnsStatData), 0);
    memDataInit(MEM_DOMAIN_PING, "domain_ping", sizeof(domain_ping), 0);
    memDataInit(MEM_DOMAIN_TYPE, "domain_type", sizeof(domain_type), 0);
    memDataInit(MEM_DREAD_CTRL, "dread_ctrl", sizeof(dread_ctrl), 0);
    memDataInit(MEM_DWRITE_Q, "dwrite_q", sizeof(dwrite_q), 0);
    memDataInit(MEM_ERRORSTATE, "ErrorState", sizeof(ErrorState), 0);
    memDataInit(MEM_FILEMAP, "fileMap", sizeof(fileMap), 0);
    memDataInit(MEM_FQDNCACHE_ENTRY, "fqdncache_entry",
	sizeof(fqdncache_entry), 0);
    memDataInit(MEM_FQDNCACHE_PENDING, "fqdn_pending",
	sizeof(fqdn_pending), 0);
    memDataInit(MEM_FWD_STATE, "FwdState", sizeof(FwdState), 0);
    memDataInit(MEM_FWD_SERVER, "FwdServer", sizeof(FwdServer), 0);
    memDataInit(MEM_HASH_LINK, "hash_link", sizeof(hash_link), 0);
    memDataInit(MEM_HASH_TABLE, "hash_table", sizeof(hash_table), 0);
    memDataInit(MEM_HIERARCHYLOGENTRY, "HierarchyLogEntry",
	sizeof(HierarchyLogEntry), 0);
    memDataInit(MEM_HTTP_STATE_DATA, "HttpStateData", sizeof(HttpStateData), 0);
    memDataInit(MEM_HTTP_REPLY, "HttpReply", sizeof(HttpReply), 0);
    memDataInit(MEM_HTTP_HDR_ENTRY, "HttpHeaderEntry", sizeof(HttpHeaderEntry), 0);
    memDataInit(MEM_HTTP_HDR_CC, "HttpHdrCc", sizeof(HttpHdrCc), 0);
    memDataInit(MEM_HTTP_HDR_RANGE_SPEC, "HttpHdrRangeSpec", sizeof(HttpHdrRangeSpec), 0);
    memDataInit(MEM_HTTP_HDR_RANGE, "HttpHdrRange", sizeof(HttpHdrRange), 0);
    memDataInit(MEM_HTTP_HDR_CONTENT_RANGE, "HttpHdrContRange", sizeof(HttpHdrContRange), 0);
    memDataInit(MEM_ICPUDPDATA, "icpUdpData", sizeof(icpUdpData), 0);
    memDataInit(MEM_ICP_COMMON_T, "icp_common_t", sizeof(icp_common_t), 0);
    memDataInit(MEM_ICP_PING_DATA, "icp_ping_data", sizeof(icp_ping_data), 0);
    memDataInit(MEM_INTLIST, "intlist", sizeof(intlist), 0);
    memDataInit(MEM_IOSTATS, "iostats", sizeof(iostats), 0);
    memDataInit(MEM_IPCACHE_PENDING, "ip_pending", sizeof(ip_pending), 0);
    memDataInit(MEM_IPCACHE_ENTRY, "ipcache_entry", sizeof(ipcache_entry), 0);
    memDataInit(MEM_MEMOBJECT, "MemObject", sizeof(MemObject),
	Squid_MaxFD >> 3);
    memDataInit(MEM_MEM_NODE, "mem_node", sizeof(mem_node), 0);
    memDataInit(MEM_NETDBENTRY, "netdbEntry", sizeof(netdbEntry), 0);
    memDataInit(MEM_NET_DB_NAME, "net_db_name", sizeof(net_db_name), 0);
    memDataInit(MEM_NET_DB_PEER, "net_db_peer", sizeof(net_db_peer), 0);
    memDataInit(MEM_DIGEST_FETCH_STATE, "DigestFetchState", sizeof(DigestFetchState), 0);
    memDataInit(MEM_PEER, "peer", sizeof(peer), 0);
    memDataInit(MEM_PINGERECHODATA, "pingerEchoData",
	sizeof(pingerEchoData), 0);
    memDataInit(MEM_PINGERREPLYDATA, "pingerReplyData",
	sizeof(pingerReplyData), 0);
    memDataInit(MEM_PS_STATE, "ps_state", sizeof(ps_state), 0);
    memDataInit(MEM_REFRESH_T, "refresh_t", sizeof(refresh_t), 0);
    memDataInit(MEM_RELIST, "relist", sizeof(relist), 0);
    memDataInit(MEM_REQUEST_T, "request_t", sizeof(request_t),
	Squid_MaxFD >> 3);
    memDataInit(MEM_SQUIDCONFIG, "SquidConfig", sizeof(SquidConfig), 0);
    memDataInit(MEM_SQUIDCONFIG2, "SquidConfig2", sizeof(SquidConfig2), 0);
    memDataInit(MEM_STATCOUNTERS, "StatCounters", sizeof(StatCounters), 0);
    memDataInit(MEM_STMEM_BUF, "Store Mem Buffer", SM_PAGE_SIZE,
	Config.Mem.maxSize / SM_PAGE_SIZE);
    memDataInit(MEM_STOREENTRY, "StoreEntry", sizeof(StoreEntry), 0);
    memDataInit(MEM_STORE_CLIENT, "store_client", sizeof(store_client), 0);
    memDataInit(MEM_SWAPDIR, "SwapDir", sizeof(SwapDir), 0);
    memDataInit(MEM_USHORTLIST, "ushort_list", sizeof(ushortlist), 0);
    memDataInit(MEM_WORDLIST, "wordlist", sizeof(wordlist), 0);
    memDataInit(MEM_CLIENT_INFO, "ClientInfo", sizeof(ClientInfo), 0);
    /* test that all entries are initialized */
    for (t = MEM_NONE + 1; t < MEM_MAX; t++) {
	if (MEM_DONTFREE == t)
	    continue;
	/*
	 * If you hit this assertion, then you forgot to add a
	 * memDataInit() line for type 't' above.
	 */
	assert(MemPools[t]);
    }
    /* init string pools */
    for (i = 0; i < mem_str_pool_count; i++) {
	StrPools[i].pool = memPoolCreate(StrPoolsAttrs[i].name, StrPoolsAttrs[i].obj_size);
    }
    cachemgrRegister("mem",
	"Memory Utilization",
	memStats, 0);
}

void
memClean()
{
    memCleanModule();
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
    memFree(MEM_2K_BUF, p);
}

void
memFree4K(void *p)
{
    memFree(MEM_4K_BUF, p);
}

void
memFree8K(void *p)
{
    memFree(MEM_8K_BUF, p);
}

void
memFreeDISK(void *p)
{
    memFree(MEM_DISK_BUF, p);
}
