
/*
 * $Id: mem.cc,v 1.9 1998/03/03 22:17:54 rousskov Exp $
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

/* module globals */

static MemPool *MemPools[MEM_MAX];

/* all pools share common memory chunks so it is probably better to ignore max_pages */
static void
memDataInit(mem_type type, const char *name, size_t size, int max_pages_notused)
{
    assert(name && size);
    MemPools[type] = memPoolCreate(name, size);
}

static void
memStats(StoreEntry * sentry)
{
    storeBuffer(sentry);
    memReport(sentry);
    /* memStringStats(sentry); */
    storeBufferFlush(sentry);
}



/*
 * PUBLIC ROUTINES
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

void
memInit(void)
{
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
    memDataInit(MEM_AIO_RESULT_T, "aio_result_t", sizeof(aio_result_t), 0);
    memDataInit(MEM_CACHEMGR_PASSWD, "cachemgr_passwd",
	sizeof(cachemgr_passwd), 0);
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
    memDataInit(MEM_HASH_LINK, "hash_link", sizeof(hash_link), 0);
    memDataInit(MEM_HASH_TABLE, "hash_table", sizeof(hash_table), 0);
    memDataInit(MEM_HIERARCHYLOGENTRY, "HierarchyLogEntry",
	sizeof(HierarchyLogEntry), 0);
    memDataInit(MEM_HTTPSTATEDATA, "HttpStateData", sizeof(HttpStateData), 0);
    memDataInit(MEM_HTTPREPLY, "http_reply", sizeof(http_reply), 0);
    memDataInit(MEM_HTTP_SCC, "HttpScc", sizeof(HttpScc), 0);
    memDataInit(MEM_ICPUDPDATA, "icpUdpData", sizeof(icpUdpData), 0);
    memDataInit(MEM_ICP_COMMON_T, "icp_common_t", sizeof(icp_common_t), 0);
    memDataInit(MEM_ICP_PING_DATA, "icp_ping_data", sizeof(icp_ping_data), 0);
    memDataInit(MEM_INTLIST, "intlist", sizeof(intlist), 0);
    memDataInit(MEM_IOSTATS, "iostats", sizeof(iostats), 0);
    memDataInit(MEM_IPCACHE_ADDRS, "ipcache_addrs", sizeof(ipcache_addrs), 0);
    memDataInit(MEM_IPCACHE_ENTRY, "ipcache_entry", sizeof(ipcache_entry), 0);
    memDataInit(MEM_MEMOBJECT, "MemObject", sizeof(MemObject),
	Squid_MaxFD >> 3);
    memDataInit(MEM_MEM_HDR, "mem_hdr", sizeof(mem_hdr), 0);
    memDataInit(MEM_MEM_NODE, "mem_node", sizeof(mem_node), 0);
    memDataInit(MEM_META_DATA, "mem_data", sizeof(meta_data), 0);
    memDataInit(MEM_NETDBENTRY, "netdbEntry", sizeof(netdbEntry), 0);
    memDataInit(MEM_NET_DB_NAME, "net_db_name", sizeof(net_db_name), 0);
    memDataInit(MEM_NET_DB_PEER, "net_db_peer", sizeof(net_db_peer), 0);
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
#if SQUID_SNMP
    memDataInit(MEM_SNMPCONF, "snmpconf", sizeof(snmpconf), 0);
#endif
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
    /* test that all entries are initialized */
    for (t = MEM_NONE + 1; t < MEM_MAX; t++) {
	/*
	 * If you hit this assertion, then you forgot to add a
	 * memDataInit() line for type 't' above.
	 */
	assert(MemPools[t]);
    }
    cachemgrRegister("mem",
	"Memory Utilization",
	memStats, 0);
}

void
memClean()
{
    mem_type t;
    int dirty_count = 0;
    for (t = MEM_NONE + 1; t < MEM_MAX; t++) {
	MemPool *pool = MemPools[t];
	if (memPoolInUseCount(pool)) {
	    memPoolDescribe(pool);
	    dirty_count++;
	}
    }
    if (dirty_count)
	debug(13, 2) ("memClean: %d pools are left dirty\n", dirty_count);
    else
	memCleanModule(); /* will free chunks and stuff */
}


int
memInUse(mem_type type)
{
    return memPoolInUseCount(MemPools[type]);
}

/* ick */

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
