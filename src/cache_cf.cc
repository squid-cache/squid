
/*
 * $Id: cache_cf.cc,v 1.320 1999/01/22 19:07:02 glenn Exp $
 *
 * DEBUG: section 3     Configuration File Parsing
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

#if SQUID_SNMP
#include "snmp.h"
#endif

static const char *const T_SECOND_STR = "second";
static const char *const T_MINUTE_STR = "minute";
static const char *const T_HOUR_STR = "hour";
static const char *const T_DAY_STR = "day";
static const char *const T_WEEK_STR = "week";
static const char *const T_FORTNIGHT_STR = "fortnight";
static const char *const T_MONTH_STR = "month";
static const char *const T_YEAR_STR = "year";
static const char *const T_DECADE_STR = "decade";

static const char *const B_BYTES_STR = "bytes";
static const char *const B_KBYTES_STR = "KB";
static const char *const B_MBYTES_STR = "MB";
static const char *const B_GBYTES_STR = "GB";

static const char *const list_sep = ", \t\n\r";

static int http_header_first = 0;

static void self_destruct(void);

static void configDoConfigure(void);
static void parse_refreshpattern(refresh_t **);
static int parseTimeUnits(const char *unit);
static void parseTimeLine(time_t * tptr, const char *units);
static void parse_string(char **);
static void parse_wordlist(wordlist **);
static void default_all(void);
static void defaults_if_none(void);
static int parse_line(char *);
static void parseBytesLine(size_t * bptr, const char *units);
static size_t parseBytesUnits(const char *unit);
static void free_all(void);
static void requirePathnameExists(const char *name, const char *path);
static OBJH dump_config;
static void dump_http_header(StoreEntry * entry, const char *name, HttpHeaderMask header);
static void parse_http_header(HttpHeaderMask * header);
static void free_http_header(HttpHeaderMask *header);

static void
self_destruct(void)
{
    fatalf("Bungled %s line %d: %s",
	cfg_filename, config_lineno, config_input_line);
}

void
wordlistDestroy(wordlist ** list)
{
    wordlist *w = NULL;
    while ((w = *list) != NULL) {
	*list = w->next;
	safe_free(w->key);
	memFree(w, MEM_WORDLIST);
    }
    *list = NULL;
}

wordlist *
wordlistAdd(wordlist ** list, const char *key)
{
    while (*list)
	list = &(*list)->next;
    *list = memAllocate(MEM_WORDLIST);
    (*list)->key = xstrdup(key);
    (*list)->next = NULL;
    return *list;
}

void
wordlistCat(const wordlist * w, MemBuf * mb)
{
    while (NULL != w) {
	memBufPrintf(mb, "%s\n", w->key);
	w = w->next;
    }
}

void
intlistDestroy(intlist ** list)
{
    intlist *w = NULL;
    intlist *n = NULL;
    for (w = *list; w; w = n) {
	n = w->next;
	memFree(w, MEM_INTLIST);
    }
    *list = NULL;
}

int
intlistFind(intlist * list, int i)
{
    intlist *w = NULL;
    for (w = list; w; w = w->next)
	if (w->i == i)
	    return 1;
    return 0;
}


/*
 * Use this #define in all the parse*() functions.  Assumes char *token is
 * defined
 */

#define GetInteger(var) \
	token = strtok(NULL, w_space); \
	if( token == NULL) \
		self_destruct(); \
	if (sscanf(token, "%d", &var) != 1) \
		self_destruct();

int
parseConfigFile(const char *file_name)
{
    FILE *fp = NULL;
    char *token = NULL;
    char *tmp_line;
    int err_count = 0;
    free_all();
    default_all();
    if ((fp = fopen(file_name, "r")) == NULL)
	fatalf("Unable to open configuration file: %s: %s",
	    file_name, xstrerror());
    cfg_filename = file_name;
    if ((token = strrchr(cfg_filename, '/')))
	cfg_filename = token + 1;
    memset(config_input_line, '\0', BUFSIZ);
    config_lineno = 0;
    while (fgets(config_input_line, BUFSIZ, fp)) {
	config_lineno++;
	if ((token = strchr(config_input_line, '\n')))
	    *token = '\0';
	if (config_input_line[0] == '#')
	    continue;
	if (config_input_line[0] == '\0')
	    continue;
	debug(3, 5) ("Processing: '%s'\n", config_input_line);
	tmp_line = xstrdup(config_input_line);
	if (!parse_line(tmp_line)) {
	    debug(3, 0) ("parseConfigFile: line %d unrecognized: '%s'\n",
		config_lineno,
		config_input_line);
	    err_count++;
	}
	safe_free(tmp_line);
    }
    fclose(fp);
    defaults_if_none();
    configDoConfigure();
    cachemgrRegister("config",
	"Current Squid Configuration",
	dump_config,
	1, 1);
    return err_count;
}

static void
configDoConfigure(void)
{
    LOCAL_ARRAY(char, buf, BUFSIZ);
    memset(&Config2, '\0', sizeof(SquidConfig2));
    /* init memory as early as possible */
    memConfigure();
    /* Sanity checks */
    if (Config.cacheSwap.swapDirs == NULL)
	fatal("No cache_dir's specified in config file");
    /* calculate Config.Swap.maxSize */
    storeDirConfigure();
    if (Config.Swap.maxSize < (Config.memMaxSize >> 10))
	fatal("cache_swap is lower than cache_mem");
    if (Config.Announce.period > 0) {
	Config.onoff.announce = 1;
    } else if (Config.Announce.period < 1) {
	Config.Announce.period = 86400 * 365;	/* one year */
	Config.onoff.announce = 0;
    }
    if (Config.dnsChildren < 1)
	fatal("No dnsservers allocated");
    if (Config.dnsChildren > DefaultDnsChildrenMax) {
	debug(3, 0) ("WARNING: dns_children was set to a bad value: %d\n",
	    Config.dnsChildren);
	debug(3, 0) ("Setting it to the maximum (%d).\n",
	    DefaultDnsChildrenMax);
	Config.dnsChildren = DefaultDnsChildrenMax;
    }
    if (Config.Program.redirect) {
	if (Config.redirectChildren < 1) {
	    Config.redirectChildren = 0;
	    safe_free(Config.Program.redirect);
	} else if (Config.redirectChildren > DefaultRedirectChildrenMax) {
	    debug(3, 0) ("WARNING: redirect_children was set to a bad value: %d\n",
		Config.redirectChildren);
	    debug(3, 0) ("Setting it to the maximum (%d).\n", DefaultRedirectChildrenMax);
	    Config.redirectChildren = DefaultRedirectChildrenMax;
	}
    }
    if (Config.Program.authenticate) {
	if (Config.authenticateChildren < 1) {
	    Config.authenticateChildren = 0;
	    wordlistDestroy(&Config.Program.authenticate);
	} else if (Config.authenticateChildren > DefaultAuthenticateChildrenMax) {
	    debug(3, 0) ("WARNING: authenticate_children was set to a bad value: %d\n",
		Config.authenticateChildren);
	    debug(3, 0) ("Setting it to the maximum (%d).\n", DefaultAuthenticateChildrenMax);
	    Config.authenticateChildren = DefaultAuthenticateChildrenMax;
	}
    }
    if (Config.Accel.host) {
	snprintf(buf, BUFSIZ, "http://%s:%d", Config.Accel.host, Config.Accel.port);
	Config2.Accel.prefix = xstrdup(buf);
	Config2.Accel.on = 1;
    }
    if (Config.appendDomain)
	if (*Config.appendDomain != '.')
	    fatal("append_domain must begin with a '.'");
    if (Config.errHtmlText == NULL)
	Config.errHtmlText = xstrdup(null_string);
    storeConfigure();
    if (Config2.Accel.on && !strcmp(Config.Accel.host, "virtual"))
	vhost_mode = 1;
    if (Config.Port.http == NULL)
	fatal("No http_port specified!");
    snprintf(ThisCache, sizeof(ThisCache), "%s:%d (%s)",
	uniqueHostname(),
	(int) Config.Port.http->i,
	full_appname_string);
    /*
     * the extra space is for loop detection in client_side.c -- we search
     * for substrings in the Via header.
     */
    snprintf(ThisCache2, sizeof(ThisCache), " %s:%d (%s)",
	uniqueHostname(),
	(int) Config.Port.http->i,
	full_appname_string);
    if (!Config.udpMaxHitObjsz || Config.udpMaxHitObjsz > SQUID_UDP_SO_SNDBUF)
	Config.udpMaxHitObjsz = SQUID_UDP_SO_SNDBUF;
    if (Config.appendDomain)
	Config.appendDomainLen = strlen(Config.appendDomain);
    else
	Config.appendDomainLen = 0;
    safe_free(debug_options)
	debug_options = xstrdup(Config.debugOptions);
    if (Config.retry.timeout < 5)
	fatal("minimum_retry_timeout must be at least 5 seconds");
    if (Config.retry.maxtries > 10)
	fatal("maximum_single_addr_tries cannot be larger than 10");
    if (Config.retry.maxtries < 1) {
	debug(3, 0) ("WARNING: resetting 'maximum_single_addr_tries to 1\n");
	Config.retry.maxtries = 1;
    }
    if (Config.referenceAge < 300) {
	debug(3, 0) ("WARNING: resetting 'reference_age' to 1 week\n");
	Config.referenceAge = 86400 * 7;
    }
    requirePathnameExists("MIME Config Table", Config.mimeTablePathname);
    requirePathnameExists("cache_dns_program", Config.Program.dnsserver);
    requirePathnameExists("unlinkd_program", Config.Program.unlinkd);
    if (Config.Program.redirect)
	requirePathnameExists("redirect_program", Config.Program.redirect);
    if (Config.Program.authenticate)
	requirePathnameExists("authenticate_program", Config.Program.authenticate->key);
    requirePathnameExists("Icon Directory", Config.icons.directory);
    requirePathnameExists("Error Directory", Config.errorDirectory);
#if HTTP_VIOLATIONS
    {
	const refresh_t *R;
	for (R = Config.Refresh; R; R = R->next) {
	    if (!R->flags.override_expire)
		continue;
	    debug(22, 1) ("WARNING: use of 'override-expire' in 'refresh_pattern' violates HTTP\n");
	    break;
	}
	for (R = Config.Refresh; R; R = R->next) {
	    if (!R->flags.override_lastmod)
		continue;
	    debug(22, 1) ("WARNING: use of 'override-lastmod' in 'refresh_pattern' violates HTTP\n");
	    break;
	}
    }
#endif
    if (Config.Wais.relayHost) {
	if (Config.Wais.peer)
	    cbdataFree(Config.Wais.peer);
	Config.Wais.peer = memAllocate(MEM_PEER);
	cbdataAdd(Config.Wais.peer, peerDestroy, MEM_PEER);
	Config.Wais.peer->host = Config.Wais.relayHost;
	Config.Wais.peer->http_port = Config.Wais.relayPort;
    }
}

/* Parse a time specification from the config file.  Store the
 * result in 'tptr', after converting it to 'units' */
static void
parseTimeLine(time_t * tptr, const char *units)
{
    char *token;
    double d;
    time_t m;
    time_t u;
    if ((u = parseTimeUnits(units)) == 0)
	self_destruct();
    if ((token = strtok(NULL, w_space)) == NULL)
	self_destruct();
    d = atof(token);
    m = u;			/* default to 'units' if none specified */
    if (0 == d)
	(void) 0;
    else if ((token = strtok(NULL, w_space)) == NULL)
	debug(3, 0) ("WARNING: No units on '%s', assuming %f %s\n",
	    config_input_line, d, units);
    else if ((m = parseTimeUnits(token)) == 0)
	self_destruct();
    *tptr = m * d / u;
}

static int
parseTimeUnits(const char *unit)
{
    if (!strncasecmp(unit, T_SECOND_STR, strlen(T_SECOND_STR)))
	return 1;
    if (!strncasecmp(unit, T_MINUTE_STR, strlen(T_MINUTE_STR)))
	return 60;
    if (!strncasecmp(unit, T_HOUR_STR, strlen(T_HOUR_STR)))
	return 3600;
    if (!strncasecmp(unit, T_DAY_STR, strlen(T_DAY_STR)))
	return 86400;
    if (!strncasecmp(unit, T_WEEK_STR, strlen(T_WEEK_STR)))
	return 86400 * 7;
    if (!strncasecmp(unit, T_FORTNIGHT_STR, strlen(T_FORTNIGHT_STR)))
	return 86400 * 14;
    if (!strncasecmp(unit, T_MONTH_STR, strlen(T_MONTH_STR)))
	return 86400 * 30;
    if (!strncasecmp(unit, T_YEAR_STR, strlen(T_YEAR_STR)))
	return 86400 * 365.2522;
    if (!strncasecmp(unit, T_DECADE_STR, strlen(T_DECADE_STR)))
	return 86400 * 365.2522 * 10;
    debug(3, 1) ("parseTimeUnits: unknown time unit '%s'\n", unit);
    return 0;
}

static void
parseBytesLine(size_t * bptr, const char *units)
{
    char *token;
    double d;
    size_t m;
    size_t u;
    if ((u = parseBytesUnits(units)) == 0)
	self_destruct();
    if ((token = strtok(NULL, w_space)) == NULL)
	self_destruct();
    d = atof(token);
    m = u;			/* default to 'units' if none specified */
    if (0 == d)
	(void) 0;
    else if ((token = strtok(NULL, w_space)) == NULL)
	debug(3, 0) ("WARNING: No units on '%s', assuming %f %s\n",
	    config_input_line, d, units);
    else if ((m = parseBytesUnits(token)) == 0)
	self_destruct();
    *bptr = m * d / u;
}

static size_t
parseBytesUnits(const char *unit)
{
    if (!strncasecmp(unit, B_BYTES_STR, strlen(B_BYTES_STR)))
	return 1;
    if (!strncasecmp(unit, B_KBYTES_STR, strlen(B_KBYTES_STR)))
	return 1 << 10;
    if (!strncasecmp(unit, B_MBYTES_STR, strlen(B_MBYTES_STR)))
	return 1 << 20;
    if (!strncasecmp(unit, B_GBYTES_STR, strlen(B_GBYTES_STR)))
	return 1 << 30;
    debug(3, 1) ("parseBytesUnits: unknown bytes unit '%s'\n", unit);
    return 0;
}

/*****************************************************************************
 * Max
 *****************************************************************************/

static void
dump_acl(StoreEntry * entry, const char *name, acl * ae)
{
    wordlist *w;
    wordlist *v;
    while (ae != NULL) {
	debug(3, 3) ("dump_acl: %s %s\n", name, ae->name);
	v = w = aclDumpGeneric(ae);
	while (v != NULL) {
	    debug(3, 3) ("dump_acl: %s %s %s\n", name, ae->name, v->key);
	    storeAppendPrintf(entry, "%s %s %s %s\n",
		name,
		ae->name,
		aclTypeToStr(ae->type),
		v->key);
	    v = v->next;
	}
	wordlistDestroy(&w);
	ae = ae->next;
    }
}

static void
parse_acl(acl ** ae)
{
    aclParseAclLine(ae);
}

static void
free_acl(acl ** ae)
{
    aclDestroyAcls(ae);
}

static void
dump_acl_access(StoreEntry * entry, const char *name, acl_access * head)
{
    acl_list *l;
    while (head != NULL) {
	storeAppendPrintf(entry, "%s %s",
	    name,
	    head->allow ? "Allow" : "Deny");
	for (l = head->acl_list; l != NULL; l = l->next) {
	    storeAppendPrintf(entry, " %s%s",
		l->op ? null_string : "!",
		l->acl->name);
	}
	storeAppendPrintf(entry, "\n");
	head = head->next;
    }
}

static void
parse_acl_access(acl_access ** head)
{
    aclParseAccessLine(head);
}

static void
free_acl_access(acl_access ** head)
{
    aclDestroyAccessList(head);
}

static void
dump_address(StoreEntry * entry, const char *name, struct in_addr addr)
{
    storeAppendPrintf(entry, "%s %s\n", name, inet_ntoa(addr));
}

static void
parse_address(struct in_addr *addr)
{
    const struct hostent *hp;
    char *token = strtok(NULL, w_space);

    if (token == NULL)
	self_destruct();
    if (safe_inet_addr(token, addr) == 1)
	(void) 0;
    else if ((hp = gethostbyname(token)))	/* dont use ipcache */
	*addr = inaddrFromHostent(hp);
    else
	self_destruct();
}

static void
free_address(struct in_addr *addr)
{
    memset(addr, '\0', sizeof(struct in_addr));
}

static void
dump_http_header(StoreEntry * entry, const char *name, HttpHeaderMask header)
{    
    storeAppendPrintf(entry, "%s\n", name);
}
    
static void
parse_http_header(HttpHeaderMask * header)
{
    int allowed, id;
    char *t = NULL;

    if ((t = strtok(NULL, w_space)) == NULL) {
	debug(3, 0) ("%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(3, 0) ("parse_http_header: missing 'allow' or 'deny'.\n");
	return;
    }
    if (!strcmp(t, "allow"))
	allowed = 1;
    else if (!strcmp(t, "deny"))
	allowed = 0;
    else {
	debug(3, 0) ("%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(3, 0) ("parse_http_header: expecting 'allow' or 'deny', got '%s'.\n", t);
	return;
    }

    if(!http_header_first){
	http_header_first = 1;
	if (allowed)
	    httpHeaderMaskInit(header, 0xFF);
    }

    while ((t = strtok(NULL, w_space))) {
	if ((id = httpHeaderIdByNameDef(t, strlen(t))) == -1)
	    id = HDR_OTHER;
	if (allowed)
	    CBIT_CLR(*header, id);
	else
	    CBIT_SET(*header, id);
    }
}
     
static void
free_http_header(HttpHeaderMask *header)
{    
    httpHeaderMaskInit(header, 0);
}

static void
dump_cachedir(StoreEntry * entry, const char *name, cacheSwap swap)
{
    SwapDir *s;
    int i;
    for (i = 0; i < swap.n_configured; i++) {
	s = swap.swapDirs + i;
	storeAppendPrintf(entry, "%s %s %d %d %d\n",
	    name,
	    s->path,
	    s->max_size >> 10,
	    s->l1,
	    s->l2);
    }
}

static int
check_null_cachedir(cacheSwap swap)
{
    return swap.swapDirs == NULL;
}

static int
check_null_string(char *s)
{
    return s == NULL;
}

static void
parse_cachedir(cacheSwap * swap)
{
    char *token;
    char *path;
    int i;
    int size;
    int l1;
    int l2;
    int read_only = 0;
    SwapDir *tmp = NULL;
    if ((path = strtok(NULL, w_space)) == NULL)
	self_destruct();
    GetInteger(i);
    size = i << 10;		/* Mbytes to kbytes */
    if (size <= 0)
	fatal("parse_cachedir: invalid size value");
    GetInteger(i);
    l1 = i;
    if (l1 <= 0)
	fatal("parse_cachedir: invalid level 1 directories value");
    GetInteger(i);
    l2 = i;
    if (l2 <= 0)
	fatal("parse_cachedir: invalid level 2 directories value");
    if ((token = strtok(NULL, w_space)))
	if (!strcasecmp(token, "read-only"))
	    read_only = 1;
    for (i = 0; i < swap->n_configured; i++) {
	tmp = swap->swapDirs + i;
	if (!strcmp(path, tmp->path)) {
	    /* just reconfigure it */
	    if (size == tmp->max_size)
		debug(3, 1) ("Cache dir '%s' size remains unchanged at %d KB\n",
		    path, size);
	    else
		debug(3, 1) ("Cache dir '%s' size changed to %d KB\n",
		    path, size);
	    tmp->max_size = size;
	    if (tmp->read_only != read_only)
		debug(3, 1) ("Cache dir '%s' now %s\n",
		    path, read_only ? "Read-Only" : "Read-Write");
	    tmp->read_only = read_only;
	    return;
	}
    }
    if (swap->swapDirs == NULL) {
	swap->n_allocated = 4;
	swap->swapDirs = xcalloc(swap->n_allocated, sizeof(SwapDir));
    }
    if (swap->n_allocated == swap->n_configured) {
	swap->n_allocated <<= 1;
	tmp = xcalloc(swap->n_allocated, sizeof(SwapDir));
	xmemcpy(tmp, swap->swapDirs, swap->n_configured * sizeof(SwapDir));
	xfree(swap->swapDirs);
	swap->swapDirs = tmp;
    }
    tmp = swap->swapDirs + swap->n_configured;
    tmp->path = xstrdup(path);
    tmp->max_size = size;
    tmp->l1 = l1;
    tmp->l2 = l2;
    tmp->read_only = read_only;
    tmp->swaplog_fd = -1;
    swap->n_configured++;
}

static void
free_cachedir(cacheSwap * swap)
{
    SwapDir *s;
    int i;
    /* DON'T FREE THESE FOR RECONFIGURE */
    if (reconfiguring)
	return;
    for (i = 0; i < swap->n_configured; i++) {
	s = swap->swapDirs + i;
	if (s->swaplog_fd > -1) {
	    file_close(s->swaplog_fd);
	    s->swaplog_fd = -1;
	}
	xfree(s->path);
	filemapFreeMemory(s->map);
    }
    safe_free(swap->swapDirs);
    swap->swapDirs = NULL;
    swap->n_allocated = 0;
    swap->n_configured = 0;
}

const char *
peer_type_str(const peer_t type)
{
    switch (type) {
    case PEER_PARENT:
	return "parent";
	break;
    case PEER_SIBLING:
	return "sibling";
	break;
    case PEER_MULTICAST:
	return "multicast";
	break;
    default:
	return "unknown";
	break;
    }
}

static void
dump_peer(StoreEntry * entry, const char *name, peer * p)
{
    domain_ping *d;
    acl_access *a;
    domain_type *t;
    LOCAL_ARRAY(char, xname, 128);
    while (p != NULL) {
	storeAppendPrintf(entry, "%s %s %s %d %d",
	    name,
	    p->host,
	    neighborTypeStr(p),
	    p->http_port,
	    p->icp.port);
	dump_peer_options(entry, p);
	for (d = p->pinglist; d; d = d->next) {
	    storeAppendPrintf(entry, "cache_peer_domain %s %s%s\n",
		p->host,
		d->do_ping ? null_string : "!",
		d->domain);
	}
	if ((a = p->access)) {
	    snprintf(xname, 128, "cache_peer_access %s", p->host);
	    dump_acl_access(entry, xname, p->access);
	}
	for (t = p->typelist; t; t = t->next) {
	    storeAppendPrintf(entry, "neighbor_type_domain %s %s %s\n",
		p->host,
		peer_type_str(t->type),
		t->domain);
	}
	p = p->next;
    }
}

static void
parse_peer(peer ** head)
{
    char *token = NULL;
    peer *p;
    int i;
    ushortlist *u;
    const char *me = null_string;	/* XXX */
    p = memAllocate(MEM_PEER);
    p->http_port = CACHE_HTTP_PORT;
    p->icp.port = CACHE_ICP_PORT;
    p->weight = 1;
    p->stats.logged_state = PEER_ALIVE;
    if ((token = strtok(NULL, w_space)) == NULL)
	self_destruct();
    p->host = xstrdup(token);
    if ((token = strtok(NULL, w_space)) == NULL)
	self_destruct();
    p->type = parseNeighborType(token);
    GetInteger(i);
    p->http_port = (u_short) i;
    GetInteger(i);
    p->icp.port = (u_short) i;
    if (strcmp(p->host, me) == 0) {
	for (u = Config.Port.http; u; u = u->next) {
	    if (p->http_port != u->i)
		continue;
	    debug(15, 0) ("parse_peer: Peer looks like myself: %s %s/%d/%d\n",
		p->type, p->host, p->http_port, p->icp.port);
	    self_destruct();
	}
    }
    while ((token = strtok(NULL, w_space))) {
	if (!strcasecmp(token, "proxy-only")) {
	    p->options.proxy_only = 1;
	} else if (!strcasecmp(token, "no-query")) {
	    p->options.no_query = 1;
	} else if (!strcasecmp(token, "no-digest")) {
	    p->options.no_digest = 1;
	} else if (!strcasecmp(token, "multicast-responder")) {
	    p->options.mcast_responder = 1;
	} else if (!strncasecmp(token, "weight=", 7)) {
	    p->weight = atoi(token + 7);
	} else if (!strcasecmp(token, "closest-only")) {
	    p->options.closest_only = 1;
	} else if (!strncasecmp(token, "ttl=", 4)) {
	    p->mcast.ttl = atoi(token + 4);
	    if (p->mcast.ttl < 0)
		p->mcast.ttl = 0;
	    if (p->mcast.ttl > 128)
		p->mcast.ttl = 128;
	} else if (!strcasecmp(token, "default")) {
	    p->options.default_parent = 1;
	} else if (!strcasecmp(token, "round-robin")) {
	    p->options.roundrobin = 1;
#if USE_HTCP
	} else if (!strcasecmp(token, "htcp")) {
	    p->options.htcp = 1;
#endif
	} else if (!strcasecmp(token, "no-netdb-exchange")) {
	    p->options.no_netdb_exchange = 1;
#if USE_CARP
	} else if (!strncasecmp(token, "carp-load-factor=", 17)) {
	    if (p->type != PEER_PARENT)
		debug(3, 0) ("parse_peer: Ignoring carp-load-factor for non-parent %s/%d\n", p->host, p->http_port);
	    else
		p->carp.load_factor = atof(token + 17);
#endif
#if DELAY_POOLS
	} else if (!strcasecmp(token, "no-delay")) {
	    p->options.no_delay = 1;
#endif
	} else if (!strncasecmp(token, "login=", 6)) {
	    p->login = xstrdup(token + 6);
	} else {
	    debug(3, 0) ("parse_peer: token='%s'\n", token);
	    self_destruct();
	}
    }
    if (p->weight < 1)
	p->weight = 1;
    p->icp.version = ICP_VERSION_CURRENT;
    p->tcp_up = PEER_TCP_MAGIC_COUNT;
#if USE_CARP
    if (p->carp.load_factor) {
	/* calculate this peers hash for use in CARP */
	p->carp.hash = 0;
	for (token = p->host; *token != 0; token++)
	    p->carp.hash += (p->carp.hash << 19) + *token;
    }
#endif
    cbdataAdd(p, peerDestroy, MEM_PEER);	/* must preceed peerDigestCreate */
#if USE_CACHE_DIGESTS
    if (!p->options.no_digest) {
	p->digest = peerDigestCreate(p);
	cbdataLock(p->digest);	/* so we know when/if digest disappears */
    }
#endif
    while (*head != NULL)
	head = &(*head)->next;
    *head = p;
    Config.npeers++;
}

static void
free_peer(peer ** P)
{
    peer *p;
    while ((p = *P) != NULL) {
	*P = p->next;
#if USE_CACHE_DIGESTS
	if (p->digest)
	    cbdataUnlock(p->digest);
	p->digest = NULL;
#endif
	cbdataFree(p);
    }
    Config.npeers = 0;
}

static void
dump_cachemgrpasswd(StoreEntry * entry, const char *name, cachemgr_passwd * list)
{
    wordlist *w;
    while (list != NULL) {
	storeAppendPrintf(entry, "%s XXXXXXXXXX", name);
	for (w = list->actions; w != NULL; w = w->next) {
	    storeAppendPrintf(entry, " %s", w->key);
	}
	storeAppendPrintf(entry, "\n");
	list = list->next;
    }
}

static void
parse_cachemgrpasswd(cachemgr_passwd ** head)
{
    char *passwd = NULL;
    wordlist *actions = NULL;
    cachemgr_passwd *p;
    cachemgr_passwd **P;
    parse_string(&passwd);
    parse_wordlist(&actions);
    p = xcalloc(1, sizeof(cachemgr_passwd));
    p->passwd = passwd;
    p->actions = actions;
    for (P = head; *P; P = &(*P)->next);
    *P = p;
}

static void
free_cachemgrpasswd(cachemgr_passwd ** head)
{
    cachemgr_passwd *p;
    while ((p = *head) != NULL) {
	*head = p->next;
	xfree(p->passwd);
	wordlistDestroy(&p->actions);
	xfree(p);
    }
}

static void
dump_denyinfo(StoreEntry * entry, const char *name, acl_deny_info_list * var)
{
    acl_name_list *a;
    while (var != NULL) {
	storeAppendPrintf(entry, "%s %s", name, var->err_page_name);
	for (a = var->acl_list; a != NULL; a = a->next)
	    storeAppendPrintf(entry, " %s", a->name);
	storeAppendPrintf(entry, "\n");
	var = var->next;
    }
}

static void
parse_denyinfo(acl_deny_info_list ** var)
{
    aclParseDenyInfoLine(var);
}

void
free_denyinfo(acl_deny_info_list ** list)
{
    acl_deny_info_list *a = NULL;
    acl_deny_info_list *a_next = NULL;
    acl_name_list *l = NULL;
    acl_name_list *l_next = NULL;
    for (a = *list; a; a = a_next) {
	for (l = a->acl_list; l; l = l_next) {
	    l_next = l->next;
	    safe_free(l);
	}
	a_next = a->next;
	safe_free(a);
    }
    *list = NULL;
}

static void
parse_peer_access(void)
{
    char *host = NULL;
    peer *p;
    if (!(host = strtok(NULL, w_space)))
	self_destruct();
    if ((p = peerFindByName(host)) == NULL) {
	debug(15, 0) ("%s, line %d: No cache_peer '%s'\n",
	    cfg_filename, config_lineno, host);
	return;
    }
    aclParseAccessLine(&p->access);
}

static void
parse_hostdomain(void)
{
    char *host = NULL;
    char *domain = NULL;
    if (!(host = strtok(NULL, w_space)))
	self_destruct();
    while ((domain = strtok(NULL, list_sep))) {
	domain_ping *l = NULL;
	domain_ping **L = NULL;
	peer *p;
	if ((p = peerFindByName(host)) == NULL) {
	    debug(15, 0) ("%s, line %d: No cache_peer '%s'\n",
		cfg_filename, config_lineno, host);
	    continue;
	}
	l = xcalloc(1, sizeof(domain_ping));
	l->do_ping = 1;
	if (*domain == '!') {	/* check for !.edu */
	    l->do_ping = 0;
	    domain++;
	}
	l->domain = xstrdup(domain);
	for (L = &(p->pinglist); *L; L = &((*L)->next));
	*L = l;
    }
}

static void
parse_hostdomaintype(void)
{
    char *host = NULL;
    char *type = NULL;
    char *domain = NULL;
    if (!(host = strtok(NULL, w_space)))
	self_destruct();
    if (!(type = strtok(NULL, w_space)))
	self_destruct();
    while ((domain = strtok(NULL, list_sep))) {
	domain_type *l = NULL;
	domain_type **L = NULL;
	peer *p;
	if ((p = peerFindByName(host)) == NULL) {
	    debug(15, 0) ("%s, line %d: No cache_peer '%s'\n",
		cfg_filename, config_lineno, host);
	    return;
	}
	l = xcalloc(1, sizeof(domain_type));
	l->type = parseNeighborType(type);
	l->domain = xstrdup(domain);
	for (L = &(p->typelist); *L; L = &((*L)->next));
	*L = l;
    }
}

static void
dump_ushortlist(StoreEntry * entry, const char *name, ushortlist * u)
{
    while (u) {
	storeAppendPrintf(entry, "%s %d\n", name, (int) u->i);
	u = u->next;
    }
}

static int
check_null_ushortlist(ushortlist * u)
{
    return u == NULL;
}

static void
parse_ushortlist(ushortlist ** P)
{
    char *token;
    int i;
    ushortlist *u;
    ushortlist **U;
    while ((token = strtok(NULL, w_space))) {
	if (sscanf(token, "%d", &i) != 1)
	    self_destruct();
	if (i < 0)
	    i = 0;
	u = xcalloc(1, sizeof(ushortlist));
	u->i = (u_short) i;
	for (U = P; *U; U = &(*U)->next);
	*U = u;
    }
}

static void
free_ushortlist(ushortlist ** P)
{
    ushortlist *u;
    while ((u = *P) != NULL) {
	*P = u->next;
	xfree(u);
    }
}

static void
dump_int(StoreEntry * entry, const char *name, int var)
{
    storeAppendPrintf(entry, "%s %d\n", name, var);
}

static void
parse_int(int *var)
{
    char *token;
    int i;
    GetInteger(i);
    *var = i;
}

static void
free_int(int *var)
{
    *var = 0;
}

static void
dump_onoff(StoreEntry * entry, const char *name, int var)
{
    storeAppendPrintf(entry, "%s %s\n", name, var ? "on" : "off");
}

static void
parse_onoff(int *var)
{
    char *token = strtok(NULL, w_space);

    if (token == NULL)
	self_destruct();
    if (!strcasecmp(token, "on") || !strcasecmp(token, "enable"))
	*var = 1;
    else
	*var = 0;
}

#define free_onoff free_int
#define free_httpanonymizer free_int
#define dump_eol dump_string
#define free_eol free_string

static void
dump_refreshpattern(StoreEntry * entry, const char *name, refresh_t * head)
{
    while (head != NULL) {
	storeAppendPrintf(entry, "%s%s %s %d %d%% %d\n",
	    name,
	    head->flags.icase ? " -i" : null_string,
	    head->pattern,
	    (int) head->min / 60,
	    (int) (100.0 * head->pct + 0.5),
	    (int) head->max / 60);
#if HTTP_VIOLATIONS
	if (head->flags.override_expire)
	    storeAppendPrintf(entry, " override-expire");
	if (head->flags.override_lastmod)
	    storeAppendPrintf(entry, " override-lastmod");
	if (head->flags.reload_into_ims)
	    storeAppendPrintf(entry, " reload-into-ims");
	if (head->flags.ignore_reload)
	    storeAppendPrintf(entry, " ignore-reload");
#endif
	storeAppendPrintf(entry, "\n");
	head = head->next;
    }
}

static void
parse_refreshpattern(refresh_t ** head)
{
    char *token;
    char *pattern;
    time_t min = 0;
    double pct = 0.0;
    time_t max = 0;
#if HTTP_VIOLATIONS
    int override_expire = 0;
    int override_lastmod = 0;
    int reload_into_ims = 0;
    int ignore_reload = 0;
#endif
    int i;
    refresh_t *t;
    regex_t comp;
    int errcode;
    int flags = REG_EXTENDED | REG_NOSUB;
    if ((token = strtok(NULL, w_space)) == NULL)
	self_destruct();
    if (strcmp(token, "-i") == 0) {
	flags |= REG_ICASE;
	token = strtok(NULL, w_space);
    } else if (strcmp(token, "+i") == 0) {
	flags &= ~REG_ICASE;
	token = strtok(NULL, w_space);
    }
    if (token == NULL)
	self_destruct();
    pattern = xstrdup(token);
    GetInteger(i);		/* token: min */
    min = (time_t) (i * 60);	/* convert minutes to seconds */
    GetInteger(i);		/* token: pct */
    pct = (double) i / 100.0;
    GetInteger(i);		/* token: max */
    max = (time_t) (i * 60);	/* convert minutes to seconds */
    /* Options */
    while ((token = strtok(NULL, w_space)) != NULL) {
#if HTTP_VIOLATIONS
	if (!strcmp(token, "override-expire"))
	    override_expire = 1;
	else if (!strcmp(token, "override-lastmod"))
	    override_lastmod = 1;
	else if (!strcmp(token, "reload-into-ims")) {
	    reload_into_ims = 1;
	    refresh_nocache_hack = 1;
	    /* tell client_side.c that this is used */
	} else if (!strcmp(token, "ignore-reload")) {
	    ignore_reload = 1;
	    refresh_nocache_hack = 1;
	    /* tell client_side.c that this is used */
	} else
#endif
	    debug(22, 0) ("redreshAddToList: Unknown option '%s': %s\n",
		pattern, token);
    }
    if ((errcode = regcomp(&comp, pattern, flags)) != 0) {
	char errbuf[256];
	regerror(errcode, &comp, errbuf, sizeof errbuf);
	debug(22, 0) ("%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(22, 0) ("refreshAddToList: Invalid regular expression '%s': %s\n",
	    pattern, errbuf);
	return;
    }
    pct = pct < 0.0 ? 0.0 : pct;
    max = max < 0 ? 0 : max;
    t = xcalloc(1, sizeof(refresh_t));
    t->pattern = (char *) xstrdup(pattern);
    t->compiled_pattern = comp;
    t->min = min;
    t->pct = pct;
    t->max = max;
    if (flags & REG_ICASE)
	t->flags.icase = 1;
#if HTTP_VIOLATIONS
    if (override_expire)
	t->flags.override_expire = 1;
    if (override_lastmod)
	t->flags.override_lastmod = 1;
    if (reload_into_ims)
	t->flags.reload_into_ims = 1;
    if (ignore_reload)
	t->flags.ignore_reload = 1;
#endif
    t->next = NULL;
    while (*head)
	head = &(*head)->next;
    *head = t;
    safe_free(pattern);
}

static void
free_refreshpattern(refresh_t ** head)
{
    refresh_t *t;
    while ((t = *head) != NULL) {
	*head = t->next;
	safe_free(t->pattern);
	regfree(&t->compiled_pattern);
	safe_free(t);
    }
}

static void
dump_string(StoreEntry * entry, const char *name, char *var)
{
    if (var != NULL)
	storeAppendPrintf(entry, "%s %s\n", name, var);
}

static void
parse_string(char **var)
{
    char *token = strtok(NULL, w_space);
    safe_free(*var);
    if (token == NULL)
	self_destruct();
    *var = xstrdup(token);
}

static void
free_string(char **var)
{
    safe_free(*var);
}

static void
parse_eol(char *volatile *var)
{
    char *token = strtok(NULL, null_string);
    safe_free(*var);
    if (token == NULL)
	self_destruct();
    *var = xstrdup(token);
}

static void
dump_time_t(StoreEntry * entry, const char *name, time_t var)
{
    storeAppendPrintf(entry, "%s %d seconds\n", name, (int) var);
}

static void
parse_time_t(time_t * var)
{
    parseTimeLine(var, T_SECOND_STR);
}

static void
free_time_t(time_t * var)
{
    *var = 0;
}

static void
dump_size_t(StoreEntry * entry, const char *name, size_t var)
{
    storeAppendPrintf(entry, "%s %d\n", name, (int) var);
}

static void
dump_b_size_t(StoreEntry * entry, const char *name, size_t var)
{
    storeAppendPrintf(entry, "%s %d %s\n", name, (int) var, B_BYTES_STR);
}

static void
dump_kb_size_t(StoreEntry * entry, const char *name, size_t var)
{
    storeAppendPrintf(entry, "%s %d %s\n", name, (int) var, B_KBYTES_STR);
}

static void
parse_size_t(size_t * var)
{
    char *token;
    int i;
    GetInteger(i);
    *var = (size_t) i;
}

static void
parse_b_size_t(size_t * var)
{
    parseBytesLine(var, B_BYTES_STR);
}

static void
parse_kb_size_t(size_t * var)
{
    parseBytesLine(var, B_KBYTES_STR);
}

static void
free_size_t(size_t * var)
{
    *var = 0;
}

#define free_b_size_t free_size_t
#define free_kb_size_t free_size_t
#define free_mb_size_t free_size_t
#define free_gb_size_t free_size_t

static void
dump_ushort(StoreEntry * entry, const char *name, u_short var)
{
    storeAppendPrintf(entry, "%s %d\n", name, var);
}

static void
free_ushort(u_short * u)
{
    *u = 0;
}

static void
parse_ushort(u_short * var)
{
    char *token;
    int i;

    GetInteger(i);
    if (i < 0)
	i = 0;
    *var = (u_short) i;
}

static void
dump_wordlist(StoreEntry * entry, const char *name, wordlist * list)
{
    while (list != NULL) {
	storeAppendPrintf(entry, "%s %s\n", name, list->key);
	list = list->next;
    }
}

static void
parse_wordlist(wordlist ** list)
{
    char *token;
    while ((token = strtok(NULL, w_space)))
	wordlistAdd(list, token);
}

static int
check_null_wordlist(wordlist * w)
{
    return w == NULL;
}

#define free_wordlist wordlistDestroy

#define free_uri_whitespace free_int

static void
parse_uri_whitespace(int *var)
{
    char *token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    if (!strcasecmp(token, "deny"))
	*var = URI_WHITESPACE_DENY;
    else if (!strcasecmp(token, "allow"))
	*var = URI_WHITESPACE_ALLOW;
    else if (!strcasecmp(token, "encode"))
	*var = URI_WHITESPACE_ENCODE;
    else if (!strcasecmp(token, "chop"))
	*var = URI_WHITESPACE_CHOP;
    else
	self_destruct();
}


static void
dump_uri_whitespace(StoreEntry * entry, const char *name, int var)
{
    char *s;
    if (var == URI_WHITESPACE_ALLOW)
	s = "allow";
    else if (var == URI_WHITESPACE_ENCODE)
	s = "encode";
    else if (var == URI_WHITESPACE_CHOP)
	s = "chop";
    else
	s = "deny";
    storeAppendPrintf(entry, "%s %s\n", name, s);
}

#include "cf_parser.c"

peer_t
parseNeighborType(const char *s)
{
    if (!strcasecmp(s, "parent"))
	return PEER_PARENT;
    if (!strcasecmp(s, "neighbor"))
	return PEER_SIBLING;
    if (!strcasecmp(s, "neighbour"))
	return PEER_SIBLING;
    if (!strcasecmp(s, "sibling"))
	return PEER_SIBLING;
    if (!strcasecmp(s, "multicast"))
	return PEER_MULTICAST;
    debug(15, 0) ("WARNING: Unknown neighbor type: %s\n", s);
    return PEER_SIBLING;
}

void
configFreeMemory(void)
{
    free_all();
}

static void
requirePathnameExists(const char *name, const char *path)
{
    struct stat sb;
    assert(path != NULL);
    if (stat(path, &sb) < 0)
	fatalf("%s: %s", path, xstrerror());
}
