/* $Id: ipcache.cc,v 1.10 1996/03/29 21:19:22 wessels Exp $ */

/*
 * DEBUG: Section 14          ipcache: IP Cache
 */

#include "squid.h"


#define MAX_LINELEN (4096)
char ipcache_status_char _PARAMS((ipcache_entry *));
int ipcache_hash_entry_count();

#define IP_POS_TTL	86400	/* one day  */
#define IP_NEG_TTL	  120	/* 2 minutes */
#define MAX_IP		 1024	/* Maximum cached IP */
#define IP_LOW_WATER       70
#define IP_HIGH_WATER      90
#define MAX_HOST_NAME	  256
#define IP_INBUF	 4096

long ipcache_low = 180;
long ipcache_high = 200;

typedef struct _ip_pending {
    int fd;
    IPH handler;
    caddr_t data;
    struct _ip_pending *next;
} IpPending;


typedef struct _ipcache_list {
    ipcache_entry *entry;
    struct _ipcache_list *next;
} ipcache_list;


typedef struct _dnsserver_entry {
    int id;
    int alive;
    int inpipe;
    int outpipe;
    int pending_count;		/* counter of outstanding request */
    long lastcall;
    long answer;
    unsigned int offset;
    unsigned int size;
    char *ip_inbuf;
    /* global ipcache_entry list for pending entry */
    ipcache_list *global_pending;
    ipcache_list *global_pending_tail;
} dnsserver_entry;

typedef struct _line_entry {
    char *line;
    struct _line_entry *next;
} line_entry;

#define TEST_SITE 5
static char *test_site[TEST_SITE] =
{
    "internic.net",
    "usc.edu",
    "cs.colorado.edu",
    "mit.edu",
    "yale.edu"
};

static dnsserver_entry **dns_child_table = NULL;
static int last_dns_dispatched = 2;
static struct hostent *static_result = NULL;
static int dns_child_alive = 0;
static int ipcache_initialized = 0;

char *dns_error_message = NULL;	/* possible error message */
HashID ip_table = 0;

extern int do_dns_test;
extern int getMaxFD();
extern int getDnsChildren();
extern void fatal_dump _PARAMS((char *));
extern int file_update_open _PARAMS((int, char *));

void update_dns_child_alive()
{
    int i;

    dns_child_alive = 0;
    for (i = 0; i < getDnsChildren(); ++i) {
	if (dns_child_table[i]->alive) {
	    dns_child_alive = 1;
	    break;
	}
    }
}

int ipcache_testname()
{
    int success, i;

    for (success = i = 0; i < TEST_SITE; i++) {
	if (gethostbyname(test_site[i]) != NULL)
	    ++success;
    }
    return (success == 0) ? -1 : 0;
}




/*
 * open a UNIX domain socket for rendevouing with dnsservers
 */
int ipcache_create_dnsserver(command)
     char *command;
{
    int pid;
    struct sockaddr_un addr;
    static int n_dnsserver = 0;
    char socketname[256];
    int cfd;			/* socket for child (dnsserver) */
    int sfd;			/* socket for server (cached) */
    int fd;

    if ((cfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	debug(14, 0, "ipcache_create_dnsserver: socket: %s\n", xstrerror());
	return -1;
    }
    fdstat_open(cfd, Socket);
    fd_note(cfd, "socket to dnsserver");
    memset(&addr, '\0', sizeof(addr));
    addr.sun_family = AF_UNIX;
    sprintf(socketname, "dns/dns%d.%d", (int) getpid(), n_dnsserver++);
    strcpy(addr.sun_path, socketname);
    debug(14, 4, "ipcache_create_dnsserver: path is %s\n", addr.sun_path);

    if (bind(cfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
	close(cfd);
	debug(14, 0, "ipcache_create_dnsserver: bind: %s\n", xstrerror());
	return -1;
    }
    debug(14, 4, "ipcache_create_dnsserver: bind to local host.\n");
    listen(cfd, 1);

    if ((pid = fork()) < 0) {
	debug(14, 0, "ipcache_create_dnsserver: fork: %s\n", xstrerror());
	close(cfd);
	return -1;
    }
    if (pid > 0) {		/* parent */
	close(cfd);		/* close shared socket with child */

	/* open new socket for parent process */
	if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	    debug(14, 0, "ipcache_create_dnsserver: socket: %s\n", xstrerror());
	    return -1;
	}
	fcntl(sfd, F_SETFD, 1);	/* set close-on-exec */
	memset(&addr, '\0', sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, socketname);
	if (connect(sfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
	    close(sfd);
	    debug(14, 0, "ipcache_create_dnsserver: connect: %s\n", xstrerror());
	    return -1;
	}
	debug(14, 4, "ipcache_create_dnsserver: FD %d connected to %s #%d.\n",
	    sfd, command, n_dnsserver);
	return sfd;
    }
    /* child */

    dup2(cfd, 3);
    for (fd = getMaxFD(); fd > 3; fd--) {
	(void) close(fd);
    }

    execlp(command, "(dnsserver)", "-p", socketname, NULL);
    perror(command);
    _exit(1);
    return (0);			/* NOTREACHED */
}


/* removes the given ipcache entry */
int ipcache_release(e)
     ipcache_entry *e;
{
    ipcache_entry *result = 0;
    int i;

    debug(14, 5, "ipcache_release: ipcache_count before: %d \n", meta_data.ipcache_count);

    if (e != NULL && ip_table) {	/* sometimes called with NULL e */
	hash_link *table_entry = hash_lookup(ip_table, e->name);
	if (table_entry) {
	    result = (ipcache_entry *) table_entry;
	    debug(14, 5, "HASH table count before delete: %d\n", ipcache_hash_entry_count());
	    if (hash_remove_link(ip_table, table_entry)) {
		debug(14, 3, "ipcache_release: Cannot delete '%s' from hash table %d\n", e->name, ip_table);
	    }
	    debug(14, 5, "HASH table count after delete: %d\n", ipcache_hash_entry_count());
	    if (result) {
		if (result->status == PENDING) {
		    debug(14, 1, "ipcache_release: Try to release entry with PENDING status. ignored.\n");
		    debug(14, 5, "ipcache_release: ipcache_count: %d \n", meta_data.ipcache_count);
		    return -1;
		}
		if (result->status == CACHED) {
		    if (result->addr_count)
			for (i = 0; i < (int) result->addr_count; i++)
			    safe_free(result->entry.h_addr_list[i]);
		    if (result->entry.h_addr_list)
			safe_free(result->entry.h_addr_list);
		    if (result->alias_count)
			for (i = 0; i < (int) result->alias_count; i++)
			    safe_free(result->entry.h_aliases[i]);
		    if (result->entry.h_aliases)
			safe_free(result->entry.h_aliases);
		    safe_free(result->entry.h_name);
		    debug(14, 5, "ipcache_release: Released IP cached record for '%s'.\n", e->name);
		}
		/* XXX: we're having mem mgmt problems; zero, then free */
		safe_free(result->name);
		memset(result, '\0', sizeof(ipcache_entry));
		safe_free(result);
	    }
	    --meta_data.ipcache_count;
	    debug(14, 5, "ipcache_release: ipcache_count when return: %d \n", meta_data.ipcache_count);
	    return meta_data.ipcache_count;
	}
    }
    debug(14, 3, "ipcache_release: can't delete entry\n");
    return -1;			/* can't delete entry */
}

/* return match for given name */
ipcache_entry *ipcache_get(name)
     char *name;
{
    hash_link *e;
    static ipcache_entry *result;

    result = NULL;
    if (ip_table) {
	if ((e = hash_lookup(ip_table, name)) != NULL)
	    result = (ipcache_entry *) e;
    }
    if (result == NULL)
	return NULL;

    if (((result->timestamp + result->ttl) < cached_curtime) &&
	(result->status != PENDING)) {	/* expired? */
	ipcache_release(result);
	return NULL;
    }
    return result;
}


/* get the first ip entry in the storage */
ipcache_entry *ipcache_GetFirst()
{
    static hash_link *entryPtr;

    if ((!ip_table) || ((entryPtr = hash_first(ip_table)) == NULL))
	return NULL;
    return ((ipcache_entry *) entryPtr);
}


/* get the next ip entry in the storage for a given search pointer */
ipcache_entry *ipcache_GetNext()
{
    static hash_link *entryPtr;

    if ((!ip_table) || ((entryPtr = hash_next(ip_table)) == NULL))
	return NULL;
    return ((ipcache_entry *) entryPtr);
}

int ipcache_compareLastRef(e1, e2)
     ipcache_entry **e1, **e2;
{
    if (!e1 || !e2)
	fatal_dump(NULL);

    if ((*e1)->lastref > (*e2)->lastref)
	return (1);

    if ((*e1)->lastref < (*e2)->lastref)
	return (-1);

    return (0);
}



/* finds the LRU and deletes */
int ipcache_purgelru()
{
    ipcache_entry *e;
    int local_ip_count = 0;
    int local_ip_notpending_count = 0;
    int removed = 0;
    int i;
    ipcache_entry **LRU_list;
    int LRU_list_count = 0;
    int LRU_cur_size = meta_data.ipcache_count;

    LRU_list = (ipcache_entry **) xcalloc(LRU_cur_size, sizeof(ipcache_entry *));

    e = NULL;

    for (e = ipcache_GetFirst(); e; e = ipcache_GetNext()) {
	local_ip_count++;

	if (LRU_list_count >= LRU_cur_size) {
	    /* have to realloc  */
	    LRU_cur_size += 16;
	    debug(14, 3, "ipcache_purgelru: Have to grow LRU_list to %d. This shouldn't happen.\n",
		LRU_cur_size);
	    LRU_list = (ipcache_entry **) xrealloc((char *) LRU_list,
		LRU_cur_size * sizeof(ipcache_entry *));
	}
	if ((e->status != PENDING) && (e->pending_head == NULL)) {
	    local_ip_notpending_count++;
	    LRU_list[LRU_list_count++] = e;
	}
    }

    debug(14, 3, "ipcache_purgelru: ipcache_count: %5d\n", meta_data.ipcache_count);
    debug(14, 3, "                  actual count : %5d\n", local_ip_count);
    debug(14, 3, "                  high W mark  : %5d\n", ipcache_high);
    debug(14, 3, "                  low  W mark  : %5d\n", ipcache_low);
    debug(14, 3, "                  not pending  : %5d\n", local_ip_notpending_count);
    debug(14, 3, "              LRU candidated   : %5d\n", LRU_list_count);

    /* sort LRU candidate list */
    qsort((char *) LRU_list, LRU_list_count, sizeof(e), (int (*)(const void *, const void *)) ipcache_compareLastRef);

    for (i = 0; LRU_list[i] && (meta_data.ipcache_count > ipcache_low)
	&& i < LRU_list_count;
	++i) {
	ipcache_release(LRU_list[i]);
	removed++;
    }

    debug(14, 3, "                   removed      : %5d\n", removed);
    safe_free(LRU_list);
    return (removed > 0) ? 0 : -1;
}


/* create blank ipcache_entry */
ipcache_entry *ipcache_create()
{
    static ipcache_entry *ipe;
    static ipcache_entry *new;
    debug(14, 5, "ipcache_create: when enter. ipcache_count == %d\n", meta_data.ipcache_count);

    if (meta_data.ipcache_count > ipcache_high) {
	if (ipcache_purgelru() < 0) {
	    debug(14, 1, "ipcache_create: Cannot release needed IP entry via LRU: %d > %d, removing first entry...\n", meta_data.ipcache_count, MAX_IP);
	    ipe = ipcache_GetFirst();
	    if (!ipe) {
		debug(14, 1, "ipcache_create: First entry is a null pointer ???\n");
		/* have to let it grow beyond limit here */
	    } else if (ipe && ipe->status != PENDING) {
		ipcache_release(ipe);
	    } else {
		debug(14, 1, "ipcache_create: First entry is also PENDING entry.\n");
		/* have to let it grow beyond limit here */
	    }
	}
    }
    meta_data.ipcache_count++;
    debug(14, 5, "ipcache_create: before return. ipcache_count == %d\n", meta_data.ipcache_count);
    new = (ipcache_entry *) xcalloc(1, sizeof(ipcache_entry));
    /* set default to 4, in case parser fail to get token $h_length from
     * dnsserver. */
    new->entry.h_length = 4;
    return new;

}

void ipcache_add_to_hash(e)
     ipcache_entry *e;
{
    if (!ipcache_initialized)
	ipcache_init();
    if (hash_join(ip_table, (hash_link *) e)) {
	debug(14, 1, "ipcache_add_to_hash: Cannot add %s (%p) to hash table %d.\n",
	    e->name, e, ip_table);
    }
    debug(14, 5, "ipcache_add_to_hash: name <%s>\n", e->name);
    debug(14, 5, "                     ipcache_count: %d\n", meta_data.ipcache_count);
}


void ipcache_add(name, e, data, cached)
     char *name;
     ipcache_entry *e;
     struct hostent *data;
     int cached;
{
    int addr_count, alias_count, i;

    debug(14, 10, "ipcache_add: Adding name '%s' (%s).\n", name,
	cached ? "cached" : "not cached");

    e->name = xstrdup(name);
    if (cached) {

	/* count for IPs */
	addr_count = 0;
	while ((addr_count < 255) && data->h_addr_list[addr_count])
	    ++addr_count;

	e->addr_count = addr_count;

	/* count for Alias */
	alias_count = 0;
	if (data->h_aliases)
	    while ((alias_count < 255) && data->h_aliases[alias_count])
		++alias_count;

	e->alias_count = alias_count;

	/* copy ip addresses information */
	e->entry.h_addr_list = (char **) xcalloc(addr_count + 1, sizeof(char *));
	for (i = 0; i < addr_count; i++) {
	    e->entry.h_addr_list[i] = (char *) xcalloc(1, data->h_length);
	    memcpy(e->entry.h_addr_list[i], data->h_addr_list[i], data->h_length);
	}

	if (alias_count) {
	    /* copy aliases information */
	    e->entry.h_aliases = (char **) xcalloc(alias_count + 1, sizeof(char *));
	    for (i = 0; i < alias_count; i++) {
		e->entry.h_aliases[i] = (char *) xcalloc(1, strlen(data->h_aliases[i]) + 1);
		strcpy(e->entry.h_aliases[i], data->h_aliases[i]);
	    }
	}
	e->entry.h_length = data->h_length;
	e->entry.h_name = xstrdup(data->h_name);
	e->lastref = e->timestamp = cached_curtime;
	e->status = CACHED;
	e->ttl = IP_POS_TTL;
    } else {
	e->lastref = e->timestamp = cached_curtime;
	e->status = NEGATIVE_CACHED;
	e->ttl = IP_NEG_TTL;
    }

    ipcache_add_to_hash(e);
}


/* exactly the same to ipcache_add, 
 * except it does NOT
 * - create entry->name (assume it's there already.)
 * - add the entry to the hash (it's should be in hash table already.).
 * 
 * Intend to be used by ipcache_cleanup_pendinglist.
 */
void ipcache_update_content(name, e, data, cached)
     char *name;
     ipcache_entry *e;
     struct hostent *data;
     int cached;
{
    int addr_count, alias_count, i;

    debug(14, 10, "ipcache_update: Updating name '%s' (%s).\n", name,
	cached ? "cached" : "not cached");

    if (cached) {

	/* count for IPs */
	addr_count = 0;
	while ((addr_count < 255) && data->h_addr_list[addr_count])
	    ++addr_count;

	e->addr_count = addr_count;

	/* count for Alias */
	alias_count = 0;
	while ((alias_count < 255) && data->h_aliases[alias_count])
	    ++alias_count;

	e->alias_count = alias_count;

	/* copy ip addresses information */
	e->entry.h_addr_list = (char **) xcalloc(addr_count + 1, sizeof(char *));
	for (i = 0; i < addr_count; i++) {
	    e->entry.h_addr_list[i] = (char *) xcalloc(1, data->h_length);
	    memcpy(e->entry.h_addr_list[i], data->h_addr_list[i], data->h_length);
	}

	/* copy aliases information */
	e->entry.h_aliases = (char **) xcalloc(alias_count + 1, sizeof(char *));
	for (i = 0; i < alias_count; i++) {
	    e->entry.h_aliases[i] = (char *) xcalloc(1, strlen(data->h_aliases[i]) + 1);
	    strcpy(e->entry.h_aliases[i], data->h_aliases[i]);
	}

	e->entry.h_length = data->h_length;
	e->entry.h_name = xstrdup(data->h_name);
	e->lastref = e->timestamp = cached_curtime;
	e->status = CACHED;
	e->ttl = IP_POS_TTL;
    } else {
	e->lastref = e->timestamp = cached_curtime;
	e->status = NEGATIVE_CACHED;
	e->ttl = IP_NEG_TTL;
    }

}



/* walks down the pending list, calling handlers */
void ipcache_call_pending(entry)
     ipcache_entry *entry;
{
    IpPending *p;
    int nhandler = 0;

    entry->lastref = cached_curtime;

    while (entry->pending_head != NULL) {
	p = entry->pending_head;
	entry->pending_head = entry->pending_head->next;
	if (entry->pending_head == NULL)
	    entry->pending_tail = NULL;
	if (p->handler != NULL) {
	    nhandler++;
	    p->handler(p->fd, (entry->status == CACHED) ?
		&(entry->entry) : NULL, p->data);
	}
	memset(p, '\0', sizeof(IpPending));
	safe_free(p);
    }
    entry->pending_head = entry->pending_tail = NULL;	/* nuke list */
    debug(14, 10, "ipcache_call_pending: Called %d handlers.\n", nhandler);
}

void ipcache_call_pending_badname(fd, handler, data)
     int fd;
     IPH handler;
     caddr_t data;
{
    debug(14, 4, "ipcache_call_pending_badname: Bad Name: Calling handler with NULL result.\n");
    handler(fd, NULL, data);
}


/* call when dnsserver is broken, have to switch to blocking mode. 
 * All pending lookup will be looked up by blocking call.
 */
int ipcache_cleanup_pendinglist(data)
     dnsserver_entry *data;
{
    ipcache_list *p;
    struct hostent *s_result = NULL;

    while (data->global_pending != NULL) {
	s_result = gethostbyname(data->global_pending->entry->name);
	ipcache_update_content(data->global_pending->entry->name,
	    data->global_pending->entry, s_result, s_result ? 1 : 0);
	ipcache_call_pending(data->global_pending->entry);
	p = data->global_pending;
	data->global_pending = data->global_pending->next;
	/* XXX: we're having mem mgmt problems; zero, then free */
	memset(p, '\0', sizeof(ipcache_list));
	safe_free(p);
    }
    data->global_pending = data->global_pending_tail = NULL;	/* nuke */
    return 0;
}

/* free all lines in the list */
void free_lines(line)
     line_entry *line;
{
    line_entry *tmp;

    while (line) {
	tmp = line;
	line = line->next;
	safe_free(tmp->line);
	safe_free(tmp);
    }
}

/* return entry in global pending list that has entry which key match to name */
ipcache_list *globalpending_search(name, global_pending)
     char *name;
     ipcache_list *global_pending;
{
    static ipcache_list *p;

    if (name == NULL)
	return NULL;

    for (p = global_pending; p != NULL; p = p->next) {
	/* XXX: this is causing core dumps! p->entry is corrupt */
	if (p->entry && p->entry->name &&
	    strcmp(p->entry->name, name) == 0) {
	    return p;
	}
    }
    return NULL;

}

/* remove entry from global pending list */
void globalpending_remove(p, data)
     ipcache_list *p;
     dnsserver_entry *data;
{
    ipcache_list *q, *r;

    r = q = data->global_pending;
    while (q && (p != q)) {
	r = q;			/* r is the node before the one to kill */
	q = q->next;		/* q (and 'p') is the node to kill */
    }

    if (q == NULL) {		/* 'p' is not in the list? */
	debug(14, 1, "globalpending_remove: Failure while deleting entry from global pending list.\n");
	return;
    }
    /* nuke p from the list; do this carefully... */
    if (p == data->global_pending) {	/* p is head */
	if (p->next != NULL) {	/* nuke head */
	    data->global_pending = p->next;
	} else {		/* nuke whole list */
	    data->global_pending = NULL;
	    data->global_pending_tail = NULL;
	}
    } else if (p == data->global_pending_tail) {	/* p is tail */
	data->global_pending_tail = r;	/* tail is prev */
	data->global_pending_tail->next = NULL;		/* last node */
    } else {			/* p in middle */
	r->next = p->next;
    }

    /* we need to delete all references to p */
    /* XXX: we're having mem mgmt probs; zero then free DRH */
    memset(p, '\0', sizeof(ipcache_list));
    /* XXX: what about freeing p->entry? DRH */
    safe_free(p);

    if (data->pending_count > 0)
	data->pending_count--;

}

/* scan through buffer and do a conversion if possible 
 * return number of char used */
int ipcache_parsebuffer(buf, offset, data)
     char *buf;
     unsigned int offset;
     dnsserver_entry *data;
{
    char *pos = NULL;
    char *tpos = NULL;
    char *endpos = NULL;
    char *token = NULL;
    char *tmp_ptr = NULL;
    line_entry *line_head = NULL;
    line_entry *line_tail = NULL;
    line_entry *line_cur = NULL;
    ipcache_list *plist = NULL;

    *dns_error_message = '\0';

    pos = buf;
    while (pos < (buf + offset)) {

	/* no complete record here */
	if ((endpos = strstr(pos, "$end\n")) == NULL) {
	    debug(14, 2, "ipcache_parsebuffer: DNS response incomplete.\n");
	    break;
	}
	line_head = line_tail = NULL;

	while (pos < endpos) {
	    /* add the next line to the end of the list */
	    line_cur = (line_entry *) xcalloc(1, sizeof(line_entry));

	    if ((tpos = memchr(pos, '\n', 4096)) == NULL) {
		debug(14, 2, "ipcache_parsebuffer: DNS response incomplete.\n");
		return -1;
	    }
	    *tpos = '\0';
	    line_cur->line = xstrdup(pos);
	    debug(14, 7, "ipcache_parsebuffer: %s\n", line_cur->line);
	    *tpos = '\n';

	    if (line_tail)
		line_tail->next = line_cur;
	    if (line_head == NULL)
		line_head = line_cur;
	    line_tail = line_cur;
	    line_cur = NULL;

	    /* update pointer */
	    pos = tpos + 1;
	}
	pos = endpos + 5;	/* strlen("$end\n") */

	/* 
	 *  At this point, the line_head is a linked list with each
	 *  link node containing another line of the DNS response.
	 *  Start parsing...
	 */
	if (strstr(line_head->line, "$alive")) {
	    data->answer = cached_curtime;
	    free_lines(line_head);
	    debug(14, 10, "ipcache_parsebuffer: $alive succeeded.\n");
	} else if (strstr(line_head->line, "$fail")) {
	    /*
	     *  The $fail messages look like:
	     *      $fail host\n$message msg\n$end\n
	     */
	    token = strtok(line_head->line, w_space);	/* skip first token */
	    token = strtok(NULL, w_space);

	    line_cur = line_head->next;
	    if (line_cur && !strncmp(line_cur->line, "$message", 8)) {
		strcpy(dns_error_message, line_cur->line + 8);
	    }
	    if (token == NULL) {
		debug(14, 1, "ipcache_parsebuffer: Invalid $fail for DNS table?\n");
	    } else {
		plist = globalpending_search(token, data->global_pending);
		if (plist) {
		    plist->entry->lastref = plist->entry->timestamp = cached_curtime;
		    plist->entry->ttl = IP_NEG_TTL;
		    plist->entry->status = NEGATIVE_CACHED;
		    ipcache_call_pending(plist->entry);
		    globalpending_remove(plist, data);
		    debug(14, 10, "ipcache_parsebuffer: $fail succeeded: %s.\n",
			dns_error_message[0] ? dns_error_message : "why?");
		} else {
		    debug(14, 1, "ipcache_parsebuffer: No entry in DNS table?\n");
		}
	    }
	    free_lines(line_head);
	} else if (strstr(line_head->line, "$name")) {
	    tmp_ptr = line_head->line;
	    /* skip the first token */
	    token = strtok(tmp_ptr, w_space);
	    tmp_ptr = NULL;
	    token = strtok(tmp_ptr, w_space);
	    if (!token) {
		debug(14, 1, "ipcache_parsebuffer: Invalid OPCODE for DNS table?\n");
	    } else {
		plist = globalpending_search(token, data->global_pending);
		if (plist) {
		    int ipcount, aliascount;
		    ipcache_entry *e = plist->entry;

		    if (e->status != PENDING) {
			debug(14, 4, "ipcache_parsebuffer: DNS record already resolved.\n");
		    } else {
			e->lastref = e->timestamp = cached_curtime;
			e->ttl = IP_POS_TTL;
			e->status = CACHED;

			line_cur = line_head->next;

			/* get $h_name */
			if (line_cur == NULL ||
			    !strstr(line_cur->line, "$h_name")) {
			    debug(14, 1, "ipcache_parsebuffer: DNS record in invalid format? No $h_name.\n");
			    /* abandon this record */
			    break;
			}
			tmp_ptr = line_cur->line;
			/* skip the first token */
			token = strtok(tmp_ptr, w_space);
			tmp_ptr = NULL;
			token = strtok(tmp_ptr, w_space);
			e->entry.h_name = xstrdup(token);

			line_cur = line_cur->next;

			/* get $h_length */
			if (line_cur == NULL ||
			    !strstr(line_cur->line, "$h_len")) {
			    debug(14, 1, "ipcache_parsebuffer: DNS record in invalid format? No $h_len.\n");
			    /* abandon this record */
			    break;
			}
			tmp_ptr = line_cur->line;
			/* skip the first token */
			token = strtok(tmp_ptr, w_space);
			tmp_ptr = NULL;
			token = strtok(tmp_ptr, w_space);
			e->entry.h_length = atoi(token);

			line_cur = line_cur->next;

			/* get $ipcount */
			if (line_cur == NULL ||
			    !strstr(line_cur->line, "$ipcount")) {
			    debug(14, 1, "ipcache_parsebuffer: DNS record in invalid format? No $ipcount.\n");
			    /* abandon this record */
			    break;
			}
			tmp_ptr = line_cur->line;
			/* skip the first token */
			token = strtok(tmp_ptr, w_space);
			tmp_ptr = NULL;
			token = strtok(tmp_ptr, w_space);
			e->addr_count = ipcount = atoi(token);

			if (ipcount == 0) {
			    e->entry.h_addr_list = NULL;
			} else {
			    e->entry.h_addr_list = (char **) xcalloc(ipcount, sizeof(char *));
			}

			/* get ip addresses */
			{
			    int i = 0;
			    line_cur = line_cur->next;
			    while (i < ipcount) {
				if (line_cur == NULL) {
				    debug(14, 1, "ipcache_parsebuffer: DNS record in invalid format? No $ipcount data.\n");
				    break;
				}
				e->entry.h_addr_list[i] = (char *) xcalloc(1, e->entry.h_length);
				*((unsigned long *) e->entry.h_addr_list[i]) = inet_addr(line_cur->line);
				line_cur = line_cur->next;
				i++;
			    }
			}

			/* get $aliascount */
			if (line_cur == NULL ||
			    !strstr(line_cur->line, "$aliascount")) {
			    debug(14, 1, "ipcache_parsebuffer: DNS record in invalid format? No $aliascount.\n");
			    /* abandon this record */
			    break;
			}
			tmp_ptr = line_cur->line;
			/* skip the first token */
			token = strtok(tmp_ptr, w_space);
			tmp_ptr = NULL;
			token = strtok(tmp_ptr, w_space);
			e->alias_count = aliascount = atoi(token);

			if (aliascount == 0) {
			    e->entry.h_aliases = NULL;
			} else {
			    e->entry.h_aliases = (char **) xcalloc(aliascount, sizeof(char *));
			}

			/* get aliases */
			{
			    int i = 0;
			    line_cur = line_cur->next;
			    while (i < aliascount) {
				if (line_cur == NULL) {
				    debug(14, 1, "ipcache_parsebuffer: DNS record in invalid format? No $aliascount data.\n");
				    break;
				}
				e->entry.h_aliases[i] = xstrdup(line_cur->line);
				line_cur = line_cur->next;
				i++;
			    }
			}

			ipcache_call_pending(e);
			globalpending_remove(plist, data);
			debug(14, 10, "ipcache_parsebuffer: $name succeeded.\n");
		    }
		} else {
		    debug(14, 1, "ipcache_parsebuffer: No entries in DNS $name record?\n");
		}
	    }
	    free_lines(line_head);
	} else {
	    free_lines(line_head);
	    debug(14, 1, "ipcache_parsebuffer: Invalid OPCODE for DNS table?\n");
	    return -1;
	}
    }
    return (int) (pos - buf);
}


int ipcache_dnsHandleRead(fd, data)
     int fd;
     dnsserver_entry *data;
{
    int char_scanned;
    int len = read(fd, data->ip_inbuf + data->offset, data->size - data->offset);

    debug(14, 5, "ipcache_dnsHandleRead: Result from DNS ID %d.\n", data->id);

    if (len == 0) {
	debug(14, 1, "ipcache_dnsHandleRead: Connection from DNSSERVER is closed.\n");
	debug(14, 1, "                       Disabling this server ID %d.\n", data->id);
	data->alive = 0;
	update_dns_child_alive();
	ipcache_cleanup_pendinglist(data);
	return 0;
    }
    data->offset += len;
    data->ip_inbuf[data->offset] = '\0';

    if (strstr(data->ip_inbuf, "$end\n")) {
	/* end of record found */
	char_scanned = ipcache_parsebuffer(data->ip_inbuf, data->offset, data);
	if (char_scanned > 0) {
	    /* update buffer */
	    memcpy(data->ip_inbuf, data->ip_inbuf + char_scanned, data->offset - char_scanned);
	    data->offset -= char_scanned;
	    data->ip_inbuf[data->offset] = '\0';
	}
    }
    /* reschedule */
    comm_set_select_handler(data->inpipe, COMM_SELECT_READ,
	(PF) ipcache_dnsHandleRead, (caddr_t) data);
    return 0;
}

int ipcache_nbgethostbyname(name, fd, handler, data)
     char *name;
     int fd;
     IPH handler;
     caddr_t data;
{
    ipcache_entry *e;
    IpPending *pending;
    dnsserver_entry *dns;

    debug(14, 4, "ipcache_nbgethostbyname: FD %d: Name '%s'.\n", fd, name);

    if (name == NULL || name[0] == '\0') {
	debug(14, 4, "ipcache_nbgethostbyname: Invalid name!\n");
	ipcache_call_pending_badname(fd, handler, data);
	return 0;
    }
    if ((e = ipcache_get(name)) != NULL && (e->status != PENDING)) {
	/* hit here */
	debug(14, 4, "ipcache_nbgethostbyname: Hit for name '%s'.\n", name);
	pending = (IpPending *) xcalloc(1, sizeof(IpPending));
	pending->fd = fd;
	pending->handler = handler;
	pending->data = data;
	pending->next = NULL;
	if (e->pending_head == NULL) {	/* empty list */
	    e->pending_head = e->pending_tail = pending;
	} else {		/* add to tail of list */
	    e->pending_tail->next = pending;
	    e->pending_tail = e->pending_tail->next;
	}
	ipcache_call_pending(e);
	return 0;
    }
    debug(14, 4, "ipcache_nbgethostbyname: Name '%s': MISS or PENDING.\n", name);

    pending = (IpPending *) xcalloc(1, sizeof(IpPending));
    pending->fd = fd;
    pending->handler = handler;
    pending->data = data;
    pending->next = NULL;
    if (e == NULL) {
	/* No entry, create the new one */
	debug(14, 5, "ipcache_nbgethostbyname: Creating new entry for '%s'...\n",
	    name);
	e = ipcache_create();
	e->name = xstrdup(name);
	e->status = PENDING;
	e->pending_tail = e->pending_head = pending;
	ipcache_add_to_hash(e);
    } else {
	/* There is an entry. Add handler to list */
	debug(14, 5, "ipcache_nbgethostbyname: Adding handler to pending list for '%s'.\n", name);
	if (e->pending_head == NULL) {	/* empty list */
	    e->pending_head = e->pending_tail = pending;
	} else {		/* add to tail of list */
	    e->pending_tail->next = pending;
	    e->pending_tail = e->pending_tail->next;
	}
	return 0;
    }

    if (dns_child_alive) {
	int i, j, min_dns = 0, min_count = 255, alive = 0;

	j = last_dns_dispatched;
	/* select DNS server with the lowest number of pending */
	for (i = 0; i < getDnsChildren(); ++i) {
	    j += 1;
	    j %= getDnsChildren();
	    if ((dns_child_table[j]->alive) &&
		(dns_child_table[j]->pending_count < min_count)) {
		min_dns = j;
		min_count = dns_child_table[j]->pending_count;
	    }
	    alive = dns_child_table[j]->alive | alive;
	}

	if (alive == 0) {
	    dns_child_alive = 0;	/* all dead */
	    last_dns_dispatched = 0;	/* use entry 0 */
	} else {
	    last_dns_dispatched = min_dns;
	}
    } else {
	last_dns_dispatched = 0;
    }

    dns = dns_child_table[last_dns_dispatched];
    debug(14, 5, "ipcache_nbgethostbyname: Dispatched DNS %d.\n",
	last_dns_dispatched);

    /* add to global pending list */
    if (dns->global_pending == NULL) {	/* new list */
	dns->global_pending = (ipcache_list *) xcalloc(1, sizeof(ipcache_list));
	dns->global_pending->entry = e;
	dns->global_pending->next = NULL;
	dns->global_pending_tail = dns->global_pending;
    } else {			/* add to end of list */
	ipcache_list *p = (ipcache_list *) xcalloc(1, sizeof(ipcache_list));
	p->entry = e;
	p->next = NULL;
	dns->global_pending_tail->next = p;
	dns->global_pending_tail = dns->global_pending_tail->next;
    }

    if (dns_child_alive) {
	char *buf = (char *) xcalloc(1, 256);
	strncpy(buf, name, 254);
	strcat(buf, "\n");
	dns->pending_count++;
	file_write(dns->outpipe,
	    buf,
	    strlen(buf),
	    0,			/* Lock */
	    0,			/* Handler */
	    0);			/* Handler-data */

	debug(14, 5, "ipcache_nbgethostbyname: Request sent DNS server ID %d.\n", last_dns_dispatched);
    } else {
	/* do a blocking mode */
	debug(14, 4, "ipcache_nbgethostbyname: Fall back to blocking mode.  Server's dead...\n");
	ipcache_cleanup_pendinglist(dns);
    }
    return 0;
}


/* initialize the ipcache */
void ipcache_init()
{
    int i, dnssocket;
    char fd_note_buf[FD_ASCII_NOTE_SZ];

    debug(14, 3, "ipcache_init: Called.  ipcache_initialized=%d  getDnsChildren()=%d\n", ipcache_initialized, getDnsChildren());

    if (ipcache_initialized)
	return;

    if (mkdir("dns", 0755) < 0 && errno != EEXIST) {
	debug(14, 0, "ipcache_init: mkdir %s\n", xstrerror());
    }
    last_dns_dispatched = getDnsChildren() - 1;
    dns_error_message = xcalloc(1, 256);

    /* test naming lookup */
    if (!do_dns_test) {
	debug(14, 4, "ipcache_init: Skipping DNS name lookup tests, -D flag given.\n");
    } else if (ipcache_testname() < 0) {
	debug(14, 0, "ipcache_init: DNS name lookup appears to be broken on this machine.\n");
	fprintf(stderr, "ipcache_init: DNS name lookup appears to be broken on this machine.\n");
	exit(-1);
    } else {
	debug(14, 4, "ipcache_init: Successful DNS name lookup tests...\n");
    }

    ip_table = hash_create(urlcmp, 229);	/* small hash table */
    /* init static area */
    static_result = (struct hostent *) xcalloc(1, sizeof(struct hostent));
    static_result->h_length = 4;
    /* Need a terminating NULL address (h_addr_list[1]) */
    static_result->h_addr_list = (char **) xcalloc(2, sizeof(char *));
    static_result->h_addr_list[0] = (char *) xcalloc(1, 4);
    static_result->h_name = (char *) xcalloc(1, MAX_HOST_NAME + 1);
    /* start up companion process */
    dns_child_table = (dnsserver_entry **) xcalloc(getDnsChildren(), sizeof(dnsserver_entry));
    dns_child_alive = 0;
    debug(14, 1, "ipcache_init: Starting %d 'dns_server' processes\n",
	getDnsChildren());
    for (i = 0; i < getDnsChildren(); i++) {
	dns_child_table[i] = (dnsserver_entry *) xcalloc(1, sizeof(dnsserver_entry));
	if ((dnssocket = ipcache_create_dnsserver(getDnsProgram())) < 0) {
	    debug(14, 1, "ipcache_init: WARNING: Cannot run 'dnsserver' process.\n");
	    debug(14, 1, "              Fallling back to the blocking version.\n");
	    dns_child_table[i]->alive = 0;
	} else {
	    dns_child_alive = 1;
	    dns_child_table[i]->id = i;
	    dns_child_table[i]->inpipe = dnssocket;
	    dns_child_table[i]->outpipe = dnssocket;
	    dns_child_table[i]->lastcall = cached_curtime;
	    dns_child_table[i]->pending_count = 0;
	    dns_child_table[i]->size = IP_INBUF - 1;	/* spare one for \0 */
	    dns_child_table[i]->offset = 0;
	    dns_child_table[i]->alive = 1;
	    dns_child_table[i]->ip_inbuf = (char *) xcalloc(1, IP_INBUF);

	    /* update fd_stat */

	    sprintf(fd_note_buf, "%s #%d",
		getDnsProgram(),
		dns_child_table[i]->id);
	    file_update_open(dns_child_table[i]->inpipe, fd_note_buf);

	    debug(14, 5, "Calling fd_note() with FD %d and buf '%s'\n",
		dns_child_table[i]->inpipe, fd_note_buf);

	    fd_note(dns_child_table[i]->inpipe, fd_note_buf);
	    commSetNonBlocking(dns_child_table[i]->inpipe);

	    /* clear unused handlers */
	    comm_set_select_handler(dns_child_table[i]->inpipe,
		COMM_SELECT_WRITE,
		0,
		0);
	    comm_set_select_handler(dns_child_table[i]->outpipe,
		COMM_SELECT_READ,
		0,
		0);

	    /* set handler for incoming result */
	    comm_set_select_handler(dns_child_table[i]->inpipe,
		COMM_SELECT_READ,
		(PF) ipcache_dnsHandleRead,
		(caddr_t) dns_child_table[i]);
	    debug(14, 3, "ipcache_init: 'dns_server' %d started\n", i);
	}
    }
    ipcache_high = (long) (((float) MAX_IP *
	    (float) IP_HIGH_WATER) / (float) 100);
    ipcache_low = (long) (((float) MAX_IP *
	    (float) IP_LOW_WATER) / (float) 100);


    ipcache_initialized = 1;
}

/* clean up the pending entries in dnsserver */
/* return 1 if we found the host, 0 otherwise */
int ipcache_unregister(name, fd)
     char *name;
     int fd;
{
    ipcache_entry *e;
    IpPending *p, *q;

    e = ipcache_get(name);
    if (!e) {
	/* not found any where */
	return 0;
    }
    /* look for matched fd */
    for (q = p = e->pending_head; p; q = p, p = p->next) {
	if (p->fd == fd) {
	    break;
	}
    }

    if (p == NULL) {
	/* Can not find this ipcache_entry, weird */
	debug(14, 1, "ipcache_unregister: Failed to unregister FD %d from name: %s, can't find this FD.\n",
	    fd, name);
	return 0;
    }
    /* found */
    if (p == e->pending_head) {
	/* it's at the head of the queue */
	if (p->next) {
	    /* there is something along the line */
	    e->pending_head = p->next;
	    free(p->data);
	    free(p);
	} else {
	    /* it is the only entry */
	    e->pending_head = e->pending_tail = NULL;
	    free(p->data);
	    free(p);
	}
    } else if (p == e->pending_tail) {
	/* it's at the tail */
	e->pending_tail = q;
	q->next = NULL;
	free(p->data);
	free(p);
    } else {
	/* it's in the middle */
	/* skip it in the list */
	q->next = p->next;
	free(p->data);
	free(p);
    }
    return 1;
}


struct hostent *ipcache_gethostbyname(name)
     char *name;
{
    ipcache_entry *result;
    unsigned int a1, a2, a3, a4;
    struct hostent *s_result = NULL;

    if (!ipcache_initialized)
	ipcache_init();

    if (!name) {
	debug(14, 5, "ipcache_gethostbyname: Invalid argument?\n");
	return (NULL);
    }
    if (!(result = ipcache_get(name))) {
	/* cache miss */
	if (name) {
	    debug(14, 5, "ipcache_gethostbyname: IPcache miss for '%s'.\n", name);
	}
	/* check if it's already a IP address in text form. */
	if (sscanf(name, "%u.%u.%u.%u", &a1, &a2, &a3, &a4) == 4) {
	    *((unsigned long *) static_result->h_addr_list[0]) = inet_addr(name);
	    strncpy(static_result->h_name, name, MAX_HOST_NAME);
	    return static_result;
	} else {
	    s_result = gethostbyname(name);
	}

	if (s_result && s_result->h_name && (s_result->h_name[0] != '\0')) {
	    /* good address, cached */
	    debug(14, 10, "ipcache_gethostbyname: DNS success: cache for '%s'.\n", name);
	    ipcache_add(name, ipcache_create(), s_result, 1);
	    result = ipcache_get(name);
	    return &(result->entry);
	} else {
	    /* bad address, negative cached */
	    debug(14, 3, "ipcache_gethostbyname: DNS failure: negative cache for '%s'.\n", name);
	    ipcache_add(name, ipcache_create(), s_result, 0);
	    return NULL;
	}

    }
    /* cache hit */
    debug(14, 5, "ipcache_gethostbyname: Hit for '%s'.\n", name ? name : "NULL");
    result->lastref = cached_curtime;
    return (result->status == CACHED) ? &(result->entry) : NULL;
}



/* process objects list */
void stat_ipcache_get(sentry, obj)
     StoreEntry *sentry;
     cacheinfo *obj;
{
    char buffer[MAX_LINELEN];
    ipcache_entry *e = NULL;
    int i;
    int ttl;
    char status;

    sprintf(buffer, "{IP Cache Contents:\n\n");
    storeAppend(sentry, buffer, strlen(buffer));

    for (e = ipcache_GetFirst(); (e); e = ipcache_GetNext()) {
	if (e) {
	    ttl = (e->ttl - cached_curtime + e->lastref);
	    status = ipcache_status_char(e);
	    if (status == 'P')
		ttl = 0;

	    sprintf(buffer, " {%s %c %d %d",
		e->name, status, ttl, e->addr_count);
	    storeAppend(sentry, buffer, strlen(buffer));

	    for (i = 0; i < (int) e->addr_count; i++) {
		struct in_addr addr;
		memcpy((char *) &addr, e->entry.h_addr_list[i], e->entry.h_length);

		sprintf(buffer, "%s ", inet_ntoa(addr));
		storeAppend(sentry, buffer, strlen(buffer));
	    }
	    for (i = 0; i < (int) e->alias_count; i++) {
		sprintf(buffer, "%s ", e->entry.h_aliases[i]);
		storeAppend(sentry, buffer, strlen(buffer));
	    }
	    if (e->entry.h_name && strncmp(e->name, e->entry.h_name, MAX_LINELEN)) {
		sprintf(buffer, "%s ", e->entry.h_name);
		storeAppend(sentry, buffer, strlen(buffer));
	    }
	    sprintf(buffer, "}\n");
	    storeAppend(sentry, buffer, strlen(buffer));
	}
    }
    sprintf(buffer, "}\n");
    storeAppend(sentry, buffer, strlen(buffer));

}

char ipcache_status_char(e)
     ipcache_entry *e;
{
    switch (e->status) {
    case CACHED:
	return ('C');
    case PENDING:
	return ('P');
    case NEGATIVE_CACHED:
	return ('N');
    default:
	debug(14, 1, "ipcache_status_char: unexpected IP cache status.\n");
    }
    return ('X');
}

int ipcache_hash_entry_count()
{
    ipcache_entry *e;
    int local_ip_count = 0;

    e = NULL;

    for (e = ipcache_GetFirst(); e; e = ipcache_GetNext()) {
	local_ip_count++;
    }

    return local_ip_count;
}
