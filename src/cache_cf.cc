
/*
 * $Id: cache_cf.cc,v 1.363 2001/01/04 03:42:34 wessels Exp $
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
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
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
static int http_header_first;
static int http_header_allowed = 0;

static void update_maxobjsize(void);
static void configDoConfigure(void);
static void parse_refreshpattern(refresh_t **);
static int parseTimeUnits(const char *unit);
static void parseTimeLine(time_t * tptr, const char *units);
static void parse_ushort(u_short * var);
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
static void free_http_header(HttpHeaderMask * header);
static void parse_sockaddr_in_list(sockaddr_in_list **);
static void dump_sockaddr_in_list(StoreEntry *, const char *, const sockaddr_in_list *);
static void free_sockaddr_in_list(sockaddr_in_list **);
static int check_null_sockaddr_in_list(const sockaddr_in_list *);

void
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

const char *
wordlistAdd(wordlist ** list, const char *key)
{
    while (*list)
	list = &(*list)->next;
    *list = memAllocate(MEM_WORDLIST);
    (*list)->key = xstrdup(key);
    (*list)->next = NULL;
    return (*list)->key;
}

void
wordlistJoin(wordlist ** list, wordlist ** wl)
{
    while (*list)
	list = &(*list)->next;
    *list = *wl;
    *wl = NULL;
}

void
wordlistAddWl(wordlist ** list, wordlist * wl)
{
    while (*list)
	list = &(*list)->next;
    for (; wl; wl = wl->next, list = &(*list)->next) {
	*list = memAllocate(MEM_WORDLIST);
	(*list)->key = xstrdup(wl->key);
	(*list)->next = NULL;
    }
}

void
wordlistCat(const wordlist * w, MemBuf * mb)
{
    while (NULL != w) {
	memBufPrintf(mb, "%s\n", w->key);
	w = w->next;
    }
}

wordlist *
wordlistDup(const wordlist * w)
{
    wordlist *D = NULL;
    while (NULL != w) {
	wordlistAdd(&D, w->key);
	w = w->next;
    }
    return D;
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

int
GetInteger(void)
{
    char *token = strtok(NULL, w_space);
    int i;
    if (token == NULL)
	self_destruct();
    if (sscanf(token, "%d", &i) != 1)
	self_destruct();
    return i;
}

static void
update_maxobjsize(void)
{
    int i;
    ssize_t ms = -1;

    for (i = 0; i < Config.cacheSwap.n_configured; i++) {
	if (Config.cacheSwap.swapDirs[i].max_objsize > ms)
	    ms = Config.cacheSwap.swapDirs[i].max_objsize;
    }
    store_maxobjsize = ms;
}

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
#if defined(_SQUID_CYGWIN_)
    setmode(fileno(fp), O_TEXT);
#endif
    cfg_filename = file_name;
    if ((token = strrchr(cfg_filename, '/')))
	cfg_filename = token + 1;
    memset(config_input_line, '\0', BUFSIZ);
    config_lineno = 0;
    http_header_first = 0;
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
    if (0 == Config.Swap.maxSize)
	/* people might want a zero-sized cache on purpose */
	(void) 0;
    else if (Config.Swap.maxSize < (Config.memMaxSize >> 10))
	fatal("cache_swap is lower than cache_mem");
    if (Config.Announce.period > 0) {
	Config.onoff.announce = 1;
    } else if (Config.Announce.period < 1) {
	Config.Announce.period = 86400 * 365;	/* one year */
	Config.onoff.announce = 0;
    }
#if USE_DNSSERVERS
    if (Config.dnsChildren < 1)
	fatal("No dnsservers allocated");
    if (Config.dnsChildren > DefaultDnsChildrenMax) {
	debug(3, 0) ("WARNING: dns_children was set to a bad value: %d\n",
	    Config.dnsChildren);
	debug(3, 0) ("Setting it to the maximum (%d).\n",
	    DefaultDnsChildrenMax);
	Config.dnsChildren = DefaultDnsChildrenMax;
    }
#endif
    if (Config.Program.redirect) {
	if (Config.redirectChildren < 1) {
	    Config.redirectChildren = 0;
	    wordlistDestroy(&Config.Program.redirect);
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
    if (Config2.Accel.on && !strcmp(Config.Accel.host, "virtual")) {
	vhost_mode = 1;
	if (Config.Accel.port == 0)
	    vport_mode = 1;
    }
    if (Config.Sockaddr.http == NULL)
	fatal("No http_port specified!");
    snprintf(ThisCache, sizeof(ThisCache), "%s:%d (%s)",
	uniqueHostname(),
	(int) ntohs(Config.Sockaddr.http->s.sin_port),
	full_appname_string);
    /*
     * the extra space is for loop detection in client_side.c -- we search
     * for substrings in the Via header.
     */
    snprintf(ThisCache2, sizeof(ThisCache), " %s:%d (%s)",
	uniqueHostname(),
	(int) ntohs(Config.Sockaddr.http->s.sin_port),
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
    requirePathnameExists("MIME Config Table", Config.mimeTablePathname);
#if USE_DNSSERVERS
    requirePathnameExists("cache_dns_program", Config.Program.dnsserver);
#endif
#if USE_UNLINKD
    requirePathnameExists("unlinkd_program", Config.Program.unlinkd);
#endif
    if (Config.Program.redirect)
	requirePathnameExists("redirect_program", Config.Program.redirect->key);
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
	Config.Wais.peer->host = xstrdup(Config.Wais.relayHost);
	Config.Wais.peer->http_port = Config.Wais.relayPort;
    }
    if (aclPurgeMethodInUse(Config.accessList.http))
	Config2.onoff.enable_purge = 1;
    if (NULL != Config.effectiveUser) {
	struct passwd *pwd = getpwnam(Config.effectiveUser);
	if (NULL == pwd)
	    /*
	     * Andres Kroonmaa <andre@online.ee>:
	     * Some getpwnam() implementations (Solaris?) require
	     * an available FD < 256 for opening a FILE* to the
	     * passwd file.
	     * DW:
	     * This should be safe at startup, but might still fail
	     * during reconfigure.
	     */
	    fatalf("getpwnam failed to find userid for effective user '%s'",
		Config.effectiveUser,
		xstrerror());
	Config2.effectiveUserID = pwd->pw_uid;
    }
    if (NULL != Config.effectiveGroup) {
	struct group *grp = getgrnam(Config.effectiveGroup);
	if (NULL == grp)
	    fatalf("getgrnam failed to find groupid for effective group '%s'",
		Config.effectiveGroup,
		xstrerror());
	Config2.effectiveGroupID = grp->gr_gid;
    }
    urlExtMethodConfigure();
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
    if (0.0 == d)
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

#if DELAY_POOLS

/* do nothing - free_delay_pool_count is the magic free function.
 * this is why delay_pool_count isn't just marked TYPE: ushort
 */
#define free_delay_pool_class(X)
#define free_delay_pool_access(X)
#define free_delay_pool_rates(X)
#define dump_delay_pool_class(X, Y, Z)
#define dump_delay_pool_access(X, Y, Z)
#define dump_delay_pool_rates(X, Y, Z)

static void
free_delay_pool_count(delayConfig * cfg)
{
    int i;

    if (!cfg->pools)
	return;
    for (i = 0; i < cfg->pools; i++) {
	if (cfg->class[i]) {
	    delayFreeDelayPool(i);
	    safe_free(cfg->rates[i]);
	}
	aclDestroyAccessList(&cfg->access[i]);
    }
    delayFreeDelayData();
    xfree(cfg->class);
    xfree(cfg->rates);
    xfree(cfg->access);
    memset(cfg, 0, sizeof(*cfg));
}

static void
dump_delay_pool_count(StoreEntry * entry, const char *name, delayConfig cfg)
{
    int i;
    LOCAL_ARRAY(char, nom, 32);

    if (!cfg.pools) {
	storeAppendPrintf(entry, "%s 0\n", name);
	return;
    }
    storeAppendPrintf(entry, "%s %d\n", name, cfg.pools);
    for (i = 0; i < cfg.pools; i++) {
	storeAppendPrintf(entry, "delay_class %d %d\n", i + 1, cfg.class[i]);
	snprintf(nom, 32, "delay_access %d", i + 1);
	dump_acl_access(entry, nom, cfg.access[i]);
	if (cfg.class[i] >= 1)
	    storeAppendPrintf(entry, "delay_parameters %d %d/%d", i + 1,
		cfg.rates[i]->aggregate.restore_bps,
		cfg.rates[i]->aggregate.max_bytes);
	if (cfg.class[i] >= 3)
	    storeAppendPrintf(entry, " %d/%d",
		cfg.rates[i]->network.restore_bps,
		cfg.rates[i]->network.max_bytes);
	if (cfg.class[i] >= 2)
	    storeAppendPrintf(entry, " %d/%d",
		cfg.rates[i]->individual.restore_bps,
		cfg.rates[i]->individual.max_bytes);
	if (cfg.class[i] >= 1)
	    storeAppendPrintf(entry, "\n");
    }
}

static void
parse_delay_pool_count(delayConfig * cfg)
{
    if (cfg->pools) {
	debug(3, 0) ("parse_delay_pool_count: multiple delay_pools lines, aborting all previous delay_pools config\n");
	free_delay_pool_count(cfg);
    }
    parse_ushort(&cfg->pools);
    delayInitDelayData(cfg->pools);
    cfg->class = xcalloc(cfg->pools, sizeof(u_char));
    cfg->rates = xcalloc(cfg->pools, sizeof(delaySpecSet *));
    cfg->access = xcalloc(cfg->pools, sizeof(acl_access *));
}

static void
parse_delay_pool_class(delayConfig * cfg)
{
    ushort pool, class;

    parse_ushort(&pool);
    if (pool < 1 || pool > cfg->pools) {
	debug(3, 0) ("parse_delay_pool_class: Ignoring pool %d not in 1 .. %d\n", pool, cfg->pools);
	return;
    }
    parse_ushort(&class);
    if (class < 1 || class > 3) {
	debug(3, 0) ("parse_delay_pool_class: Ignoring pool %d class %d not in 1 .. 3\n", pool, class);
	return;
    }
    pool--;
    if (cfg->class[pool]) {
	delayFreeDelayPool(pool);
	safe_free(cfg->rates[pool]);
    }
    cfg->rates[pool] = xmalloc(class * sizeof(delaySpec));
    cfg->class[pool] = class;
    cfg->rates[pool]->aggregate.restore_bps = cfg->rates[pool]->aggregate.max_bytes = -1;
    if (cfg->class[pool] >= 3)
	cfg->rates[pool]->network.restore_bps = cfg->rates[pool]->network.max_bytes = -1;
    if (cfg->class[pool] >= 2)
	cfg->rates[pool]->individual.restore_bps = cfg->rates[pool]->individual.max_bytes = -1;
    delayCreateDelayPool(pool, class);
}

static void
parse_delay_pool_rates(delayConfig * cfg)
{
    ushort pool, class;
    int i;
    delaySpec *ptr;
    char *token;

    parse_ushort(&pool);
    if (pool < 1 || pool > cfg->pools) {
	debug(3, 0) ("parse_delay_pool_rates: Ignoring pool %d not in 1 .. %d\n", pool, cfg->pools);
	return;
    }
    pool--;
    class = cfg->class[pool];
    if (class == 0) {
	debug(3, 0) ("parse_delay_pool_rates: Ignoring pool %d attempt to set rates with class not set\n", pool + 1);
	return;
    }
    ptr = (delaySpec *) cfg->rates[pool];
    /* read in "class" sets of restore,max pairs */
    while (class--) {
	token = strtok(NULL, "/");
	if (token == NULL)
	    self_destruct();
	if (sscanf(token, "%d", &i) != 1)
	    self_destruct();
	ptr->restore_bps = i;
	i = GetInteger();
	ptr->max_bytes = i;
	ptr++;
    }
    class = cfg->class[pool];
    /* if class is 3, swap around network and individual */
    if (class == 3) {
	delaySpec tmp;

	tmp = cfg->rates[pool]->individual;
	cfg->rates[pool]->individual = cfg->rates[pool]->network;
	cfg->rates[pool]->network = tmp;
    }
    /* initialize the delay pools */
    delayInitDelayPool(pool, class, cfg->rates[pool]);
}

static void
parse_delay_pool_access(delayConfig * cfg)
{
    ushort pool;

    parse_ushort(&pool);
    if (pool < 1 || pool > cfg->pools) {
	debug(3, 0) ("parse_delay_pool_rates: Ignoring pool %d not in 1 .. %d\n", pool, cfg->pools);
	return;
    }
    aclParseAccessLine(&cfg->access[pool - 1]);
}
#endif

static void
dump_http_header(StoreEntry * entry, const char *name, HttpHeaderMask header)
{
    int i;
    for (i = 0; i < HDR_OTHER; i++) {
	if (http_header_allowed && !CBIT_TEST(header, i))
	    storeAppendPrintf(entry, "%s allow %s\n", name, httpHeaderNameById(i));
	else if (!http_header_allowed && CBIT_TEST(header, i))
	    storeAppendPrintf(entry, "%s deny %s\n", name, httpHeaderNameById(i));
    }
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
    if (!http_header_first) {
	http_header_first = 1;
	if (allowed) {
	    http_header_allowed = 1;
	    httpHeaderMaskInit(header, 0xFF);
	} else {
	    http_header_allowed = 0;
	    httpHeaderMaskInit(header, 0);
	}
    }
    while ((t = strtok(NULL, w_space))) {
	if ((id = httpHeaderIdByNameDef(t, strlen(t))) == -1)
	    debug(3, 0) ("parse_http_header: Ignoring unknown header '%s'\n", t);
	else if (allowed)
	    CBIT_CLR(*header, id);
	else
	    CBIT_SET(*header, id);
    }
}

static void
free_http_header(HttpHeaderMask * header)
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
	s->dump(entry, name, s);
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

void
allocate_new_swapdir(cacheSwap * swap)
{
    if (swap->swapDirs == NULL) {
	swap->n_allocated = 4;
	swap->swapDirs = xcalloc(swap->n_allocated, sizeof(SwapDir));
    }
    if (swap->n_allocated == swap->n_configured) {
	SwapDir *tmp;
	swap->n_allocated <<= 1;
	tmp = xcalloc(swap->n_allocated, sizeof(SwapDir));
	xmemcpy(tmp, swap->swapDirs, swap->n_configured * sizeof(SwapDir));
	xfree(swap->swapDirs);
	swap->swapDirs = tmp;
    }
}

static int
find_fstype(char *type)
{
    int i;
    for (i = 0; storefs_list[i].typestr != NULL; i++) {
	if (strcasecmp(type, storefs_list[i].typestr) == 0) {
	    return i;
	}
    }
    return (-1);
}

static void
parse_cachedir(cacheSwap * swap)
{
    char *type_str;
    char *path_str;
    SwapDir *sd;
    int i;
    int fs;
    ssize_t maxobjsize;

    if ((type_str = strtok(NULL, w_space)) == NULL)
	self_destruct();

    maxobjsize = (ssize_t) GetInteger();

    if ((path_str = strtok(NULL, w_space)) == NULL)
	self_destruct();

    /*
     * This bit of code is a little strange.
     * See, if we find a path and type match for a given line, then
     * as long as we're reconfiguring, we can just call its reconfigure
     * function. No harm there.
     *
     * Trouble is, if we find a path match, but not a type match, we have
     * a dilemma - we could gracefully shut down the fs, kill it, and
     * create a new one of a new type in its place, BUT at this stage the
     * fs is meant to be the *NEW* one, and so things go very strange. :-)
     *
     * So, we'll assume the person isn't going to change the fs type for now,
     * and XXX later on we will make sure that its picked up.
     *
     * (moving around cache_dir lines will be looked at later in a little
     * more sane detail..)
     */

    for (i = 0; i < swap->n_configured; i++) {
	if (0 == strcasecmp(path_str, swap->swapDirs[i].path)) {
	    /* This is a little weird, you'll appreciate it later */
	    fs = find_fstype(type_str);
	    if (fs < 0) {
		fatalf("Unknown cache_dir type '%s'\n", type_str);
	    }
	    sd = swap->swapDirs + i;
	    storefs_list[fs].reconfigurefunc(sd, i, path_str);
	    sd->max_objsize = maxobjsize;
	    update_maxobjsize();
	    return;
	}
    }

    fs = find_fstype(type_str);
    if (fs < 0) {
	/* If we get here, we didn't find a matching cache_dir type */
	fatalf("Unknown cache_dir type '%s'\n", type_str);
    }
    allocate_new_swapdir(swap);
    sd = swap->swapDirs + swap->n_configured;
    storefs_list[fs].parsefunc(sd, swap->n_configured, path_str);
    /* XXX should we dupe the string here, in case it gets trodden on? */
    sd->type = storefs_list[fs].typestr;
    sd->max_objsize = maxobjsize;
    /* defaults in case fs implementation fails to set these */
    sd->fs.blksize = 1024;
    sd->fs.kperblk = 1;
    swap->n_configured++;
    /* Update the max object size */
    update_maxobjsize();
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
	s->freefs(s);
	xfree(s->path);
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
	for (d = p->peer_domain; d; d = d->next) {
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
    i = GetInteger();
    p->http_port = (u_short) i;
    i = GetInteger();
    p->icp.port = (u_short) i;
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
	} else if (!strncasecmp(token, "connect-timeout=", 16)) {
	    p->connect_timeout = atoi(token + 16);
#if USE_CACHE_DIGESTS
	} else if (!strncasecmp(token, "digest-url=", 11)) {
	    p->digest_url = xstrdup(token + 11);
#endif
	} else if (!strcasecmp(token, "allow-miss")) {
	    p->options.allow_miss = 1;
	} else if (!strcasecmp(token, "max-conn=")) {
	    p->max_conn = atoi(token + 9);
	} else {
	    debug(3, 0) ("parse_peer: token='%s'\n", token);
	    self_destruct();
	}
    }
    if (p->weight < 1)
	p->weight = 1;
    p->icp.version = ICP_VERSION_CURRENT;
    p->tcp_up = PEER_TCP_MAGIC_COUNT;
    p->test_fd = -1;
#if USE_CARP
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
    if (p->carp.load_factor) {
	/* calculate this peers hash for use in CARP */
	p->carp.hash = 0;
	for (token = p->host; *token != 0; token++)
	    p->carp.hash += ROTATE_LEFT(p->carp.hash, 19) + (unsigned int) *token;
	p->carp.hash += p->carp.hash * 0x62531965;
	p->carp.hash = ROTATE_LEFT(p->carp.hash, 21);
    }
#endif
    /* This must preceed peerDigestCreate */
    cbdataAdd(p, peerDestroy, MEM_PEER);
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
    peerClearRR(p);
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
	if (strcmp(list->passwd, "none") && strcmp(list->passwd, "disable"))
	    storeAppendPrintf(entry, "%s XXXXXXXXXX", name);
	else
	    storeAppendPrintf(entry, "%s %s", name, list->passwd);
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
	    memFree(l, MEM_ACL_NAME_LIST);
	    l = NULL;
	}
	a_next = a->next;
	memFree(a, MEM_ACL_DENY_INFO_LIST);
	a = NULL;
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
	for (L = &(p->peer_domain); *L; L = &((*L)->next));
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

#if UNUSED_CODE
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
#endif

static void
dump_int(StoreEntry * entry, const char *name, int var)
{
    storeAppendPrintf(entry, "%s %d\n", name, var);
}

static void
parse_int(int *var)
{
    int i;
    i = GetInteger();
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
    i = GetInteger();		/* token: min */
    min = (time_t) (i * 60);	/* convert minutes to seconds */
    i = GetInteger();		/* token: pct */
    pct = (double) i / 100.0;
    i = GetInteger();		/* token: max */
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

static int
check_null_refreshpattern(refresh_t * data)
{
    return data != NULL;
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
    int i;
    i = GetInteger();
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
    int i;

    i = GetInteger();
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

static int
check_null_acl_access(acl_access * a)
{
    return a == NULL;
}

#define free_wordlist wordlistDestroy

#define free_uri_whitespace free_int

static void
parse_uri_whitespace(int *var)
{
    char *token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    if (!strcasecmp(token, "strip"))
	*var = URI_WHITESPACE_STRIP;
    else if (!strcasecmp(token, "deny"))
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
    else if (var == URI_WHITESPACE_DENY)
	s = "deny";
    else
	s = "strip";
    storeAppendPrintf(entry, "%s %s\n", name, s);
}

static void
free_removalpolicy(RemovalPolicySettings ** settings)
{
    if (!*settings)
	return;
    free_string(&(*settings)->type);
    free_wordlist(&(*settings)->args);
    xfree(*settings);
    *settings = NULL;
}

static void
parse_removalpolicy(RemovalPolicySettings ** settings)
{
    if (*settings)
	free_removalpolicy(settings);
    *settings = xcalloc(1, sizeof(**settings));
    parse_string(&(*settings)->type);
    parse_wordlist(&(*settings)->args);
}

static void
dump_removalpolicy(StoreEntry * entry, const char *name, RemovalPolicySettings * settings)
{
    wordlist *args;
    storeAppendPrintf(entry, "%s %s", name, settings->type);
    args = settings->args;
    while (args) {
	storeAppendPrintf(entry, " %s", args->key);
	args = args->next;
    }
    storeAppendPrintf(entry, "\n");
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

static void
parse_sockaddr_in_list(sockaddr_in_list ** head)
{
    char *token;
    char *t;
    char *host;
    const struct hostent *hp;
    unsigned short port;
    sockaddr_in_list *s;
    while ((token = strtok(NULL, w_space))) {
	host = NULL;
	port = 0;
	if ((t = strchr(token, ':'))) {
	    /* host:port */
	    host = token;
	    *t = '\0';
	    port = (unsigned short) atoi(t + 1);
	    if (0 == port)
		self_destruct();
	} else if ((port = atoi(token)) > 0) {
	    /* port */
	} else {
	    self_destruct();
	}
	s = xcalloc(1, sizeof(*s));
	s->s.sin_port = htons(port);
	if (NULL == host)
	    s->s.sin_addr = any_addr;
	else if (1 == safe_inet_addr(host, &s->s.sin_addr))
	    (void) 0;
	else if ((hp = gethostbyname(host)))	/* dont use ipcache */
	    s->s.sin_addr = inaddrFromHostent(hp);
	else
	    self_destruct();
	while (*head)
	    head = &(*head)->next;
	*head = s;
    }
}

static void
dump_sockaddr_in_list(StoreEntry * e, const char *n, const sockaddr_in_list * s)
{
    while (s) {
	storeAppendPrintf(e, "%s %s:%d\n",
	    n,
	    inet_ntoa(s->s.sin_addr),
	    ntohs(s->s.sin_port));
	s = s->next;
    }
}

static void
free_sockaddr_in_list(sockaddr_in_list ** head)
{
    sockaddr_in_list *s;
    while ((s = *head) != NULL) {
	*head = s->next;
	xfree(s);
    }
}

static int
check_null_sockaddr_in_list(const sockaddr_in_list * s)
{
    return NULL == s;
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
