
/*
 * $Id: mem.cc,v 1.6 1998/02/21 00:56:58 rousskov Exp $
 *
 * DEBUG: section 13    Memory Pool Management
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

#define stackSize(S) ((S)->top - (S)->base)

typedef struct {
    void **base;
    void **top;
    int max_size;
} Stack;

typedef struct {
    char *name;
    int n_allocated;
    size_t size;
    int n_used;
    Stack Stack;
} memData;

static memData MemData[MEM_MAX];

static void * stackPop(Stack * s);
static int stackFull(Stack * s);
static int stackEmpty(Stack * s);
static void stackPush(Stack * s, void *p);
static void memDataInit(mem_type , const char *, size_t , int );
static OBJH memStats;

static int
stackEmpty(Stack * s)
{
    return s->top == s->base;
}

static int
stackFull(Stack * s)
{
    return (stackSize(s) == s->max_size);
}

static void *
stackPop(Stack * s)
{
    void *p;
    assert(s->top != s->base);
    s->top--;
    p = *s->top;
    *s->top = NULL;
    return p;
}

static void
stackPush(Stack * s, void *p)
{
    if (stackSize(s) == s->max_size) {
	xfree(p);
    } else {
	*s->top = p;
	s->top++;
    }
}

static void
memDataInit(mem_type type, const char *name, size_t size, int max_pages)
{
    memData *m = &MemData[type];
    m->size = size;
    m->name = xstrdup(name);
#if !PURIFY
    if (Config.onoff.mem_pools) {
	m->Stack.max_size = max_pages;
	m->Stack.base = xcalloc(max_pages, sizeof(void **));
	m->Stack.top = m->Stack.base;
    }
#endif
}

/*
 * PUBLIC ROUTINES
 */

void *
memAllocate(mem_type type, int clear)
{
    void *p = NULL;
    memData *m = &MemData[type];
    if (!stackEmpty(&m->Stack)) {
	p = stackPop(&m->Stack);
	assert(p != NULL);
    } else {
	p = xmalloc(m->size);
	m->n_allocated++;
    }
    m->n_used++;
    if (clear)
	memset(p, '\0', m->size);
    return p;
}

void
memFree(mem_type type, void *p)
{
    memData *m = &MemData[type];
    assert(p != NULL);
    m->n_used--;
    if (stackFull(&m->Stack)) {
	xfree(p);
	m->n_allocated--;
    } else {
	stackPush(&m->Stack, p);
    }
}

void
memInit(void)
{
    mem_type t;
    memData *m;
    memset(MemData, '\0', MEM_MAX * sizeof(memData));
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
    for (t = MEM_NONE + 1; t < MEM_MAX; t++) {
	m = &MemData[t];
	/*
	 * If you hit this assertion, then you forgot to add a
	 * memDataInit() line for type 't' above.
	 */
	assert(m->size);
    }
    cachemgrRegister("mem",
	"Memory Utilization",
	memStats, 0);
}

void
memFreeMemory(void)
{
    mem_type t;
    memData *m;
    void *p;
    for (t = MEM_NONE + 1; t < MEM_MAX; t++) {
	m = &MemData[t];
	while (!stackEmpty(&m->Stack)) {
	    p = stackPop(&m->Stack);
	    xfree(p);
	}
	xfree(m->Stack.base);
    }
}

static void
memStats(StoreEntry * sentry)
{
    mem_type t;
    memData *m;
    size_t in_use = 0;
    size_t not_in_use = 0;
    size_t allocated = 0;
    storeBuffer(sentry);
    storeAppendPrintf(sentry, "%25s %6s %15s %15s\n",
	"NAME",
	"SIZE",
	"NOT-USED",
	"ALLOCATED");
    for (t = MEM_NONE + 1; t < MEM_MAX; t++) {
	m = &MemData[t];
	if (m->n_allocated == 0)
	    continue;
	storeAppendPrintf(sentry, "%25.25s %6d %6d %5d KB  %6d %5d KB\n",
	    m->name,
	    m->size,
	    stackSize(&m->Stack),
	    m->size * stackSize(&m->Stack) >> 10,
	    m->n_allocated,
	    m->size * m->n_allocated >> 10);
	in_use += m->size * m->n_used;
	not_in_use += m->size * stackSize(&m->Stack);
	allocated += m->size * m->n_allocated;
    }
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "Total Memory In Use      %6d KB\n",
	(int) in_use >> 10);
    storeAppendPrintf(sentry, "Total Memory Not In Use  %6d KB\n",
	(int) not_in_use >> 10);
    storeAppendPrintf(sentry, "Total Memory Allocated   %6d KB\n",
	(int) allocated >> 10);
    storeBufferFlush(sentry);
}

int
memInUse(mem_type type)
{
    return MemData[type].n_used;
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
