/* $Id: stat.cc,v 1.34 1996/05/15 05:13:25 wessels Exp $ */

/*
 * DEBUG: Section 18          stat
 */


#include "squid.h"

#ifdef _SQUID_HPUX_
#define getrusage(a, b)  syscall(SYS_GETRUSAGE, a, b)
#define getpagesize( )   sysconf(_SC_PAGE_SIZE)
#endif /* _SQUID_HPUX_ */

extern int emulate_httpd_log;

#define MIN_BUFSIZE (4096)
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

char *stat_describe();
char *mem_describe();
char *ttl_describe();
char *flags_describe();
char *elapsed_time();
char *diskFileName();

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

    storeAppendPrintf(sentry, "{\n");

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
    for (proto_id = 0; proto_id < PROTO_MAX; ++proto_id) {
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
    for (proto_id = 0; proto_id <= PROTO_MAX; ++proto_id) {
	p = &obj->proto_stat_data[proto_id];
	if (p->hit != 0) {
	    p->hitratio =
		(float) p->hit /
		((float) p->hit +
		(float) p->miss);
	}
	storeAppendPrintf(sentry, "{%s %d %d %d %d %4.2f %d %d %d}\n",
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

    storeAppendPrintf(sentry, "}\n");
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
    for (proto_id = 0; proto_id < PROTO_MAX; proto_id++)
	size += obj->proto_stat_data[proto_id].kb.now;
    return size;
}

/* process general IP cache information */
void stat_general_get(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
{
    /* have to use old method for this guy, 
     * otherwise we have to make ipcache know about StoreEntry */
    stat_ipcache_get(sentry, obj);
}


/* process objects list */
void stat_objects_get(obj, sentry, vm_or_not)
     cacheinfo *obj;
     StoreEntry *sentry;
     int vm_or_not;
{
    static char space[40];
    static char space2[40];
    int npend = 0;
    StoreEntry *entry = NULL;
    int N = 0;
    int obj_size;

    storeAppendPrintf(sentry, "{\n");

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
    storeAppendPrintf(sentry, "}\n");
}


/* process a requested object into a manager format */
void stat_get(obj, req, sentry)
     cacheinfo *obj;
     char *req;
     StoreEntry *sentry;
{

    if (strncmp(req, "objects", strlen("objects")) == 0) {
	stat_objects_get(obj, sentry, 0);
    } else if (strncmp(req, "vm_objects", strlen("vm_objects")) == 0) {
	stat_objects_get(obj, sentry, 1);
    } else if (strncmp(req, "general", strlen("general")) == 0) {
	stat_general_get(obj, sentry);
    } else if (strncmp(req, "utilization", strlen("utilization")) == 0) {
	stat_utilization_get(obj, sentry);
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
void logReadEndHandler(fd_unused, errflag_unused, data)
     int fd_unused;
     int errflag_unused;
     log_read_data_t *data;
{
    storeAppendPrintf(data->sentry, "}\n");
    storeComplete(data->sentry);
    safe_free(data);
}



/* start converting logfile to processed format */
void log_get_start(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
{
    log_read_data_t *data = NULL;

    if (obj->logfile_status == LOG_DISABLE) {
	/* Manufacture status when logging is disabled */
	log_status_get(obj, sentry);
	storeComplete(sentry);
	return;
    }
    data = (log_read_data_t *) xmalloc(sizeof(log_read_data_t));
    memset(data, '\0', sizeof(log_read_data_t));
    data->sentry = sentry;
    storeAppendPrintf(sentry, "{\n");
    file_walk(obj->logfile_fd, (FILE_WALK_HD) logReadEndHandler,
	(void *) data, (FILE_WALK_LHD) logReadHandler, (void *) data);
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
    static char tempbuf[MAX_LINELEN];
    tempbuf[0] = '\0';
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
    storeAppendPrintf(data->sentry, "}\n");
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

    data = (squid_read_data_t *) xmalloc(sizeof(squid_read_data_t));
    memset(data, '\0', sizeof(squid_read_data_t));
    data->sentry = sentry;
    data->fd = file_open((char *) ConfigFile, NULL, O_RDONLY);
    storeAppendPrintf(sentry, "{\n");
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

    storeAppendPrintf(sentry, "{\n");

    if (getFirstEdge() == (edge *) NULL) {
	storeAppendPrintf(sentry, "{There are no neighbors installed.}\n");
    }
    for (e = getFirstEdge(); e; e = getNextEdge(e)) {
	if (e->host == NULL)
	    fatal_dump("Found an edge without a hostname!");
	storeAppendPrintf(sentry, "\n{Hostname:    %s}\n", e->host);
	storeAppendPrintf(sentry, "{Edge type:   %s}\n",
	    e->type == EDGE_PARENT ? "parent" : "neighbor");
	storeAppendPrintf(sentry, "{Status:      %s}\n",
	    e->neighbor_up ? "Up" : "Down");
	storeAppendPrintf(sentry, "{UDP PORT:    %d}\n", e->udp_port);
	storeAppendPrintf(sentry, "{ASCII PORT:  %d}\n", e->ascii_port);
	storeAppendPrintf(sentry, "{ACK DEFICIT: %d}\n", e->ack_deficit);
	storeAppendPrintf(sentry, "{PINGS SENT:  %d}\n", e->num_pings);
	storeAppendPrintf(sentry, "{PINGS ACKED: %d}\n", e->pings_acked);
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
	storeAppendPrintf(sentry, "}\n");
    }
    storeAppendPrintf(sentry, "}\n");
}



void info_get(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
{
    char *tod = NULL;
    static char line[MAX_LINELEN];
    wordlist *p = NULL;

#if defined(HAVE_GETRUSAGE) && defined(RUSAGE_SELF)
    struct rusage rusage;
#endif

#if HAVE_MALLINFO
    struct mallinfo mp;
#endif

    memset(line, '\0', SM_PAGE_SIZE);

    storeAppendPrintf(sentry, "{\n");

    storeAppendPrintf(sentry, "{Squid Object Cache: Version %s}\n", version_string);

    tod = mkrfc850(&squid_starttime);

    storeAppendPrintf(sentry, "{Start Time:\t%s}\n", tod);

    tod = mkrfc850(&squid_curtime);
    storeAppendPrintf(sentry, "{Current Time:\t%s}\n", tod);

    /* -------------------------------------------------- */

    storeAppendPrintf(sentry, "{Connection information for %s:}\n",
	appname);
    storeAppendPrintf(sentry, "{\tNumber of TCP connections:\t%lu}\n",
	ntcpconn);
    storeAppendPrintf(sentry, "{\tNumber of UDP connections:\t%lu}\n",
	nudpconn);

    {
	float f;
	f = squid_curtime - squid_starttime;
	storeAppendPrintf(sentry, "{\tConnections per hour:\t%.1f}\n",
	    f == 0.0 ? 0.0 :
	    ((ntcpconn + nudpconn) / (f / 3600)));
    }

    /* -------------------------------------------------- */

    storeAppendPrintf(sentry, "{Cache information for %s:}\n", appname);

    storeAppendPrintf(sentry, "{\tStorage Swap size:\t%d MB}\n", storeGetSwapSize() >> 10);

    storeAppendPrintf(sentry, "{\tStorage Mem size:\t%d KB}\n", storeGetMemSize() >> 10);

    tod = mkrfc850(&next_cleaning);
    storeAppendPrintf(sentry, "{\tStorage Expiration at:\t%s}\n", tod);

#if defined(HAVE_GETRUSAGE) && defined(RUSAGE_SELF)
    storeAppendPrintf(sentry, "{Resource usage for %s:}\n", appname);

    getrusage(RUSAGE_SELF, &rusage);
    storeAppendPrintf(sentry, "{\tCPU Usage: user %d sys %d}\n{\tProcess Size: rss %d KB}\n",
	rusage.ru_utime.tv_sec, rusage.ru_stime.tv_sec,
	rusage.ru_maxrss * getpagesize() >> 10);

    storeAppendPrintf(sentry, "{\tPage faults with physical i/o:\t%d}\n",
	rusage.ru_majflt);

#endif

#if HAVE_MALLINFO
    mp = mallinfo();

    storeAppendPrintf(sentry, "{Memory usage for %s via mallinfo():}\n", appname);

    storeAppendPrintf(sentry, "{\ttotal space in arena:\t%d KB}\n", mp.arena >> 10);
    storeAppendPrintf(sentry, "{\tnumber of ordinary blocks:\t%d}\n", mp.ordblks);
    storeAppendPrintf(sentry, "{\tnumber of small blocks:\t%d}\n", mp.smblks);
    if (mp.hblks) {
	storeAppendPrintf(sentry, "{\tnumber of holding blocks:\t%d}\n", mp.hblks);
    }
    if (mp.hblkhd) {
	storeAppendPrintf(sentry, "{\tspace in holding block headers:\t%d}\n", mp.hblkhd);
    }
    if (mp.usmblks) {
	storeAppendPrintf(sentry, "{\tspace in small blocks in use:\t%d}\n", mp.usmblks);
    }
    if (mp.fsmblks) {
	storeAppendPrintf(sentry, "{\tspace in free blocks:\t%d}\n", mp.fsmblks);
    }
    storeAppendPrintf(sentry, "{\tspace in ordinary blocks in use:\t%d KB}\n",
	mp.uordblks >> 10);
    storeAppendPrintf(sentry, "{\tspace in free ordinary blocks:\t%d KB}\n", mp.fordblks >> 10);
    if (mp.keepcost) {
	storeAppendPrintf(sentry, "{\tcost of enabling keep option:\t%d}\n", mp.keepcost);
    }
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

    storeAppendPrintf(sentry, "{\tMax number of file desc available:\t%d}\n", getMaxFD());

    storeAppendPrintf(sentry, "{\tLargest file desc currently in use:\t%d}\n",
	fdstat_biggest_fd());

    storeAppendPrintf(sentry, "{\tAvailable number of file descriptors :\t%d}\n",
	fdstat_are_n_free_fd(0));

    storeAppendPrintf(sentry, "{\tReserved number of file descriptors :\t%d}\n",
	RESERVED_FD);

    {
	int i, max_fd = getMaxFD();
	char *s = NULL;

	storeAppendPrintf(sentry, "{\tActive file descriptors:}\n");

	for (i = 0; i < max_fd; i++) {
	    int lft, to;
	    if (!fdstat_isopen(i))
		continue;
	    line[0] = '\0';
	    switch (fdstat_type(i)) {
	    case Socket:
		/* the lifetime should be greater than curtime */
		lft = comm_get_fd_lifetime(i);
		to = comm_get_fd_timeout(i);
		storeAppendPrintf(sentry, "{\t\t(%3d = %3d, %3d) NET %s}\n",
		    i,
		    (int) (lft > 0 ? lft - squid_curtime : -1),
		    (int) max((to - squid_curtime), 0),
		    fd_note(i, NULL));
		break;
	    case File:
		storeAppendPrintf(sentry, "{\t\t(%3d = FILE) %s}\n", i,
		    (s = diskFileName(i)) ? s : "Unknown");
		break;
	    case Pipe:
		storeAppendPrintf(sentry, "{\t\t(%3d = PIPE) %s}\n", i, fd_note(i, NULL));
		break;
	    case LOG:
		storeAppendPrintf(sentry, "{\t\t(%3d = LOG) %s}\n", i, fd_note(i, NULL));
		break;
	    case Unknown:
	    default:
		storeAppendPrintf(sentry, "{\t\t(%3d = UNKNOWN) %s}\n", i, fd_note(i, NULL));
		break;
	    }
	}
    }


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
    storeAppendPrintf(sentry, "{Meta Data:}\n");

    storeAppendPrintf(sentry, "{\t\tStoreEntry %d x %d bytes = %d KB}\n",
	meta_data.store_entries,
	(int) sizeof(StoreEntry),
	(int) (meta_data.store_entries * sizeof(StoreEntry) >> 10));

    storeAppendPrintf(sentry, "{\t\tStoreMemObject %d x %d bytes = %d KB}\n",
	meta_data.store_in_mem_objects,
	(int) sizeof(MemObject),
	(int) (meta_data.store_in_mem_objects * sizeof(MemObject) >> 10));

    storeAppendPrintf(sentry, "{\t\tIPCacheEntry %d x %d bytes = %d KB}\n",
	meta_data.ipcache_count,
	(int) sizeof(ipcache_entry),
	(int) (meta_data.ipcache_count * sizeof(ipcache_entry) >> 10));

    storeAppendPrintf(sentry, "{\t\tHash link  %d x %d bytes = %d KB}\n",
	meta_data.hash_links = hash_links_allocated,
	(int) sizeof(hash_link),
	(int) (meta_data.hash_links * sizeof(hash_link) >> 10));

    storeAppendPrintf(sentry, "{\t\tURL strings %d KB}\n",
	meta_data.url_strings >> 10);

    storeAppendPrintf(sentry, "{\t\tHot Object Cache Items %d}\n", meta_data.hot_vm);

    storeAppendPrintf(sentry, "{\t\tPool for disk I/O %d KB (Free %d KB)}\n",
	disk_stats.total_pages_allocated * disk_stats.page_size >> 10,
	(disk_stats.total_pages_allocated - disk_stats.n_pages_in_use) * disk_stats.page_size >> 10);

    storeAppendPrintf(sentry, "{\t\tPool for in-memory objects %d KB (Free %d KB)}\n",
	sm_stats.total_pages_allocated * sm_stats.page_size >> 10,
	(sm_stats.total_pages_allocated - sm_stats.n_pages_in_use) * sm_stats.page_size >> 10);

    storeAppendPrintf(sentry, "{\tTotal Accounted %d KB}\n",
	(int) (meta_data.store_entries * sizeof(StoreEntry) +
	    meta_data.store_in_mem_objects * sizeof(MemObject) +
	    meta_data.ipcache_count * sizeof(ipcache_entry) +
	    meta_data.hash_links * sizeof(hash_link) +
	    sm_stats.total_pages_allocated * sm_stats.page_size +
	    disk_stats.total_pages_allocated * disk_stats.page_size +
	    meta_data.url_strings) >> 10);

    storeAppendPrintf(sentry, "}\n");
}


void parameter_get(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;

{
    /* be careful if an object is bigger than 4096, 
     * need more malloc here */
    static char line[MAX_LINELEN];

    memset(line, '\0', MAX_LINELEN);

    storeAppendPrintf(sentry, "{\n");

    storeAppendPrintf(sentry, "{VM-Max %d \"# Maximum hot-vm cache (MB)\"}\n",
	getCacheMemMax() / (1 << 20));

    storeAppendPrintf(sentry, "{VM-High %d \"# High water mark hot-vm cache (%%)\"}\n",
	getCacheMemHighWaterMark());

    storeAppendPrintf(sentry, "{VM-Low %d \"# Low water-mark hot-vm cache (%%)\"}\n",
	getCacheMemLowWaterMark());

    storeAppendPrintf(sentry, "{Swap-Max %d \"# Maximum disk cache (MB)\"}\n",
	getCacheSwapMax() / (1 << 10));

    storeAppendPrintf(sentry, "{Swap-High %d \"# High Water mark disk cache (%%)\"}\n",
	getCacheSwapHighWaterMark());

    storeAppendPrintf(sentry, "{Swap-Low %d \"# Low water mark disk cache (%%)\"}\n",
	getCacheSwapLowWaterMark());

    storeAppendPrintf(sentry, "{HTTP-Max %d\"# Maximum size HTTP objects (KB)\"}\n",
	getHttpMax() / (1 << 10));

    storeAppendPrintf(sentry, "{HTTP-TTL %d \"# Http object default TTL (hrs)\"}\n", getHttpTTL() / 3600);

    storeAppendPrintf(sentry, "{Gopher-Max %d \"# Maximum size gopher objects (KB)\"}\n",
	getGopherMax() / (1 << 10));

    storeAppendPrintf(sentry, "{Gopher-TTL %d \"# TTL for gopher objects (hrs)\"}\n", getGopherTTL() / 3600);

    storeAppendPrintf(sentry, "{FTP-Max %d \"# Maximum size FTP objects (KB)\"}\n",
	getFtpMax() / (1 << 10));

    storeAppendPrintf(sentry, "{FTP-TTL %d \"# TTL for FTP objects (hrs)\"}\n", getFtpTTL() / 3600);

    storeAppendPrintf(sentry, "{Neg-TTL %d \"# TTL for negative cache (s)\"}\n",
	getNegativeTTL());

    storeAppendPrintf(sentry, "{ReadTimeout %d \"# Maximum idle connection (s)\"}\n", getReadTimeout());

    storeAppendPrintf(sentry, "{ClientLifetime %d \"# Lifetime for incoming ascii port requests or outgoing clients (s)\"}\n", getClientLifetime());

    storeAppendPrintf(sentry, "{CleanRate %d \"# Rate for periodic object expiring\"}\n",
	getCleanRate());

    /* Cachemgr.cgi expects an integer in the second field of the string */
    storeAppendPrintf(sentry, "{HttpAccelMode %d \"# Is operating as an HTTP accelerator\"}\n",
	httpd_accel_mode);

    /* end of stats */
    storeAppendPrintf(sentry, "}\n");
}


void log_append(obj, url, id, size, action, method, http_code, msec, ident)
     cacheinfo *obj;
     char *url;
     char *id;
     int size;
     char *action;
     char *method;
     int http_code;
     int msec;
     char *ident;
{
    static char tmp[6000];	/* MAX_URL is 4096 */
    char *buf = NULL;

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
	    sprintf(tmp, "%9d.%03d %6d %s %s/%03d %d %s %s %s\n",
		(int) current_time.tv_sec,
		(int) current_time.tv_usec / 1000,
		msec,
		id,
		action,
		http_code,
		size,
		method,
		url,
		ident);


	if (file_write(obj->logfile_fd, buf = xstrdup(tmp), strlen(tmp),
		obj->logfile_access, NULL, NULL) != DISK_OK) {
	    debug(18, 1, "log_append: File write failed.\n");
	    safe_free(buf);
	}
    }
}

void log_enable(obj, sentry)
     cacheinfo *obj;
     StoreEntry *sentry;
{
    static char tempbuf[MAX_LINELEN];

    if (obj->logfile_status == LOG_DISABLE) {
	obj->logfile_status = LOG_ENABLE;

	/* open the logfile */
	obj->logfile_fd = file_open(obj->logfilename, NULL, O_RDWR | O_CREAT);
	if (obj->logfile_fd == DISK_ERROR) {
	    debug(18, 0, "Cannot open logfile: %s\n", obj->logfilename);
	    obj->logfile_status = LOG_DISABLE;
	}
	obj->logfile_access = file_write_lock(obj->logfile_fd);

    }
    /* at the moment, store one char to make a storage manager happy */
    storeAppendPrintf(sentry, " ");
    storeAppend(sentry, tempbuf, strlen(tempbuf));
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
    static char tempbuf[MAX_LINELEN];


    /* what should be done here. Erase file ??? or move it to another name */
    /* At the moment, just erase it. */
    /* bug here need to be fixed. what if there are still data in memory. Need flush here */
    if (obj->logfile_status == LOG_ENABLE)
	file_close(obj->logfile_fd);

    unlink(obj->logfilename);

    /* reopen it anyway */
    obj->logfile_fd = file_open(obj->logfilename, NULL, O_RDWR | O_CREAT);
    if (obj->logfile_fd == DISK_ERROR) {
	debug(18, 0, "Cannot open logfile: %s\n", obj->logfilename);
	obj->logfile_status = LOG_DISABLE;
    }
    /* at the moment, store one char to make a storage manager happy */
    storeAppendPrintf(sentry, " ");
    storeAppend(sentry, tempbuf, strlen(tempbuf));
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

    obj = (cacheinfo *) xmalloc(sizeof(cacheinfo));
    memset(obj, '\0', sizeof(cacheinfo));

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

    memcpy(obj->logfilename, logfilename, (int) (strlen(logfilename) + 1) % 256);
    obj->logfile_fd = file_open(obj->logfilename, NULL, O_RDWR | O_CREAT);
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

    for (i = 0; i <= PROTO_MAX; i++) {
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
    static char state[256];

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
    case WAITING:
	strncat(state, "PING-WAIT", sizeof(state));
	break;
    case TIMEOUT:
	strncat(state, "PING-TIMEOUT", sizeof(state));
	break;
    case DONE:
	strncat(state, "PING-DONE", sizeof(state));
	break;
    case NOPING:
	strncat(state, "NO-PING", sizeof(state));
	break;
    default:
	strncat(state, "YEEHAH", sizeof(state));
	break;
    }
    return (state);
}

char *mem_describe(entry)
     StoreEntry *entry;
{
    static char where[100];

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
    static char TTL[60];
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
    static char FLAGS[32];
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
    static char from[MAXPATHLEN];
    static char to[MAXPATHLEN];
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
    CacheInfo->logfile_fd = file_open(fname, NULL, O_RDWR | O_CREAT | O_APPEND);
    if (CacheInfo->logfile_fd == DISK_ERROR) {
	debug(18, 0, "rotate_logs: Cannot open logfile: %s\n", fname);
	CacheInfo->logfile_status = LOG_DISABLE;
	fatal("Cannot open logfile.");
    }
    CacheInfo->logfile_access = file_write_lock(CacheInfo->logfile_fd);
}
