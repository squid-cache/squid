/*
 * $Id: cache_cf.cc,v 1.226 1997/10/25 17:22:34 wessels Exp $
 *
 * DEBUG: section 3     Configuration File Parsing
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

static char fatal_str[BUFSIZ];
static void self_destruct(void);
static void wordlistAdd(wordlist **, const char *);

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

/* These come from cf_gen.c */
static void default_all(void);
static void free_all(void);

static void
self_destruct(void)
{
    snprintf(fatal_str, BUFSIZ, "Bungled %s line %d: %s",
	cfg_filename, config_lineno, config_input_line);
    fatal(fatal_str);
}

void
wordlistDestroy(wordlist ** list)
{
    wordlist *w = NULL;
    while ((w = *list)) {
	*list = w->next;
	safe_free(w->key);
	safe_free(w);
    }
    *list = NULL;
}

static void
wordlistAdd(wordlist ** list, const char *key)
{
    wordlist *p = NULL;
    wordlist *q = NULL;

    if (!(*list)) {
	/* empty list */
	*list = xcalloc(1, sizeof(wordlist));
	(*list)->key = xstrdup(key);
	(*list)->next = NULL;
    } else {
	p = *list;
	while (p->next)
	    p = p->next;
	q = xcalloc(1, sizeof(wordlist));
	q->key = xstrdup(key);
	q->next = NULL;
	p->next = q;
    }
}

void
intlistDestroy(intlist ** list)
{
    intlist *w = NULL;
    intlist *n = NULL;

    for (w = *list; w; w = n) {
	n = w->next;
	safe_free(w);
    }
    *list = NULL;
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
    free_all();
    default_all();
    if ((fp = fopen(file_name, "r")) == NULL) {
	snprintf(fatal_str, BUFSIZ, "Unable to open configuration file: %s: %s",
	    file_name, xstrerror());
	fatal(fatal_str);
    }
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
	}
	safe_free(tmp_line);
    }

    /* Sanity checks */
    if (Config.cacheSwap.swapDirs == NULL)
	fatal("No cache_dir's specified in config file");
    if (Config.Swap.maxSize < (Config.Mem.maxSize >> 10)) {
	printf("WARNING: cache_swap (%d kbytes) is less than cache_mem (%d bytes).\n", Config.Swap.maxSize, Config.Mem.maxSize);
	printf("         This will cause serious problems with your cache!!!\n");
	printf("         Change your configuration file.\n");
	fflush(stdout);		/* print message */
    }
    if (Config.Announce.period < 1) {
	Config.Announce.period = 86400 * 365;	/* one year */
	Config.onoff.announce = 0;
    }
    if (Config.dnsChildren < 0)
	Config.dnsChildren = 0;
    if (Config.dnsChildren < 1) {
	printf("WARNING: dnsservers are disabled!\n");
	printf("WARNING: Cache performance may be very poor\n");
    } else if (Config.dnsChildren > DefaultDnsChildrenMax) {
	printf("WARNING: dns_children was set to a bad value: %d\n",
	    Config.dnsChildren);
	printf("Setting it to the maximum (%d).\n", DefaultDnsChildrenMax);
	Config.dnsChildren = DefaultDnsChildrenMax;
    }
    if (Config.Program.redirect) {
	if (Config.redirectChildren < 1) {
	    Config.redirectChildren = 0;
	    safe_free(Config.Program.redirect);
	} else if (Config.redirectChildren > DefaultRedirectChildrenMax) {
	    printf("WARNING: redirect_children was set to a bad value: %d\n",
		Config.redirectChildren);
	    printf("Setting it to the maximum (%d).\n", DefaultRedirectChildrenMax);
	    Config.redirectChildren = DefaultRedirectChildrenMax;
	}
    }
    fclose(fp);
    defaults_if_none();
    configDoConfigure();
    return 0;
}

static void
configDoConfigure(void)
{
    LOCAL_ARRAY(char, buf, BUFSIZ);
    memset(&Config2, '\0', sizeof(SquidConfig2));
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
    snprintf(ThisCache, SQUIDHOSTNAMELEN << 1, "%s:%d (Squid/%s)",
	getMyHostname(),
	(int) Config.Port.http->i,
	SQUID_VERSION);
    if (!Config.udpMaxHitObjsz || Config.udpMaxHitObjsz > SQUID_UDP_SO_SNDBUF)
	Config.udpMaxHitObjsz = SQUID_UDP_SO_SNDBUF;
    if (Config.appendDomain)
	Config.appendDomainLen = strlen(Config.appendDomain);
    else
	Config.appendDomainLen = 0;
    safe_free(debug_options)
	debug_options = xstrdup(Config.debugOptions);
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
    if ((token = strtok(NULL, w_space)) == NULL)
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
    if ((token = strtok(NULL, w_space)) == NULL)
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
dump_acl(StoreEntry * entry, const char *name, acl * acl)
{
    storeAppendPrintf(entry, "%s -- UNIMPLEMENTED\n", name);
}

static void
parse_acl(acl ** acl)
{
    aclParseAclLine(acl);
}

static void
free_acl(acl ** acl)
{
    aclDestroyAcls(acl);
}

static void
dump_acl_access(StoreEntry * entry, const char *name, struct _acl_access *head)
{
    storeAppendPrintf(entry, "%s -- UNIMPLEMENTED\n", name);
}

static void
parse_acl_access(struct _acl_access **head)
{
    aclParseAccessLine(head);
}

static void
free_acl_access(struct _acl_access **head)
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
dump_cachedir(StoreEntry * entry, const char *name, struct _cacheSwap swap)
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
check_null_cachedir(struct _cacheSwap swap)
{
    return swap.swapDirs == NULL;
}

static void
parse_cachedir(struct _cacheSwap *swap)
{
    char *token;
    char *path;
    int i;
    int size;
    int l1;
    int l2;
    int readonly = 0;
    SwapDir *tmp = NULL;
    if ((path = strtok(NULL, w_space)) == NULL)
	self_destruct();
    if (strlen(path) > (SQUID_MAXPATHLEN - 32))
	fatal_dump("cache_dir pathname is too long");
    GetInteger(i);
    size = i << 10;		/* Mbytes to kbytes */
    GetInteger(i);
    l1 = i;
    GetInteger(i);
    l2 = i;
    if ((token = strtok(NULL, w_space)))
	if (!strcasecmp(token, "read-only"))
	    readonly = 1;
    for (i = 0; i < swap->n_configured; i++) {
	tmp = swap->swapDirs + i;
	if (!strcmp(path, tmp->path)) {
	    /* just reconfigure it */
	    tmp->max_size = size;
	    tmp->read_only = readonly;
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
    debug(20, 1) ("Creating Swap Dir #%d in %s\n", swap->n_configured + 1, path);
    tmp = swap->swapDirs + swap->n_configured;
    tmp->path = xstrdup(path);
    tmp->max_size = size;
    tmp->l1 = l1;
    tmp->l2 = l2;
    tmp->read_only = readonly;
    tmp->map = file_map_create(MAX_FILES_PER_DIR);
    tmp->swaplog_fd = -1;
    swap->n_configured++;
    Config.Swap.maxSize += size;
}

static void
free_cachedir(struct _cacheSwap *swap)
{
    SwapDir *s;
    int i;
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

static void
dump_peer(StoreEntry * entry, const char *name, peer * p)
{
    storeAppendPrintf(entry, "%s -- UNIMPLEMENTED\n", name);
}

static void
parse_peer(peer ** head)
{
    char *token = NULL;
    peer *p;
    int i;
    ushortlist *u;
    const char *me = null_string;	/* XXX */
    p = xcalloc(1, sizeof(peer));
    p->http_port = CACHE_HTTP_PORT;
    p->icp_port = CACHE_ICP_PORT;
    p->weight = 1;
    if ((token = strtok(NULL, w_space)) == NULL)
	self_destruct();
    p->host = xstrdup(token);
    if ((token = strtok(NULL, w_space)) == NULL)
	self_destruct();
    p->type = parseNeighborType(token);
    GetInteger(i);
    p->http_port = (u_short) i;
    GetInteger(i);
    p->icp_port = (u_short) i;
    if (strcmp(p->host, me) == 0) {
	for (u = Config.Port.http; u; u = u->next) {
	    if (p->http_port != u->i)
		continue;
	    debug(15, 0) ("parse_peer: Peer looks like myself: %s %s/%d/%d\n",
		p->type, p->host, p->http_port, p->icp_port);
	    self_destruct();
	}
    }
    while ((token = strtok(NULL, w_space))) {
	if (!strcasecmp(token, "proxy-only")) {
	    p->options |= NEIGHBOR_PROXY_ONLY;
	} else if (!strcasecmp(token, "no-query")) {
	    p->options |= NEIGHBOR_NO_QUERY;
	} else if (!strcasecmp(token, "multicast-responder")) {
	    p->options |= NEIGHBOR_MCAST_RESPONDER;
	} else if (!strncasecmp(token, "weight=", 7)) {
	    p->weight = atoi(token + 7);
	} else if (!strncasecmp(token, "closest-only", 12)) {
	    p->options |= NEIGHBOR_CLOSEST_ONLY;
	} else if (!strncasecmp(token, "ttl=", 4)) {
	    p->mcast.ttl = atoi(token + 4);
	    if (p->mcast.ttl < 0)
		p->mcast.ttl = 0;
	    if (p->mcast.ttl > 128)
		p->mcast.ttl = 128;
	} else if (!strncasecmp(token, "default", 7)) {
	    p->options |= NEIGHBOR_DEFAULT_PARENT;
	} else if (!strncasecmp(token, "round-robin", 11)) {
	    p->options |= NEIGHBOR_ROUNDROBIN;
	} else {
	    debug(3, 0) ("parse_peer: token='%s'\n", token);
	    self_destruct();
	}
    }
    if (p->weight < 1)
	p->weight = 1;
    p->icp_version = ICP_VERSION_CURRENT;
    p->tcp_up = 1;
    cbdataAdd(p);
    while (*head != NULL)
	head = &(*head)->next;
    *head = p;
    Config.npeers++;
}

static void
free_peer(peer ** P)
{
    peer *p;
    while ((p = *P)) {
	*P = p->next;
	peerDestroy(p);
    }
}

static void
dump_cachemgrpasswd(StoreEntry * entry, const char *name, cachemgr_passwd * list)
{
    storeAppendPrintf(entry, "%s -- UNIMPLEMENTED\n", name);
}

static void
parse_cachemgrpasswd(cachemgr_passwd ** head)
{
    char *passwd = NULL;
    wordlist *actions = NULL;
    parse_string(&passwd);
    parse_wordlist(&actions);
    objcachePasswdAdd(head, passwd, actions);
    wordlistDestroy(&actions);
}

static void
free_cachemgrpasswd(cachemgr_passwd ** head)
{
    cachemgr_passwd *p;
    while ((p = *head)) {
	*head = p->next;
	xfree(p->passwd);
	xfree(p);
    }
}


static void
dump_denyinfo(StoreEntry * entry, const char *name, struct _acl_deny_info_list *var)
{
    storeAppendPrintf(entry, "%s -- UNIMPLEMENTED\n", name);
}

static void
parse_denyinfo(struct _acl_deny_info_list **var)
{
    aclParseDenyInfoLine(var);
}

void
free_denyinfo(acl_deny_info_list ** list)
{
    struct _acl_deny_info_list *a = NULL;
    struct _acl_deny_info_list *a_next = NULL;
    struct _acl_name_list *l = NULL;
    struct _acl_name_list *l_next = NULL;
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
parse_peeracl(void)
{
    char *host = NULL;
    char *aclname = NULL;
    if (!(host = strtok(NULL, w_space)))
	self_destruct();
    while ((aclname = strtok(NULL, list_sep))) {
	peer *p;
	acl_list *L = NULL;
	acl_list **Tail = NULL;
	acl *a = NULL;
	if ((p = peerFindByName(host)) == NULL) {
	    debug(15, 0) ("%s, line %d: No cache_peer '%s'\n",
		cfg_filename, config_lineno, host);
	    return;
	}
	L = xcalloc(1, sizeof(struct _acl_list));
	L->op = 1;
	if (*aclname == '!') {
	    L->op = 0;
	    aclname++;
	}
	debug(15, 3) ("neighborAddAcl: looking for ACL name '%s'\n", aclname);
	a = aclFindByName(aclname);
	if (a == NULL) {
	    debug(15, 0) ("%s line %d: %s\n",
		cfg_filename, config_lineno, config_input_line);
	    debug(15, 0) ("neighborAddAcl: ACL name '%s' not found.\n", aclname);
	    xfree(L);
	    return;
	}
	L->acl = a;
	for (Tail = &p->acls; *Tail; Tail = &(*Tail)->next);
	*Tail = L;
    }
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
	l = xcalloc(1, sizeof(struct _domain_ping));
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
	l = xcalloc(1, sizeof(struct _domain_type));
	l->type = parseNeighborType(type);
	l->domain = xstrdup(domain);
	for (L = &(p->typelist); *L; L = &((*L)->next));
	*L = l;
    }
}

static void
dump_httpanonymizer(StoreEntry * entry, const char *name, int var)
{
    switch (var) {
    case ANONYMIZER_NONE:
	printf("off");
	break;
    case ANONYMIZER_STANDARD:
	printf("paranoid");
	break;
    case ANONYMIZER_PARANOID:
	printf("standard");
	break;
    }
}

static void
parse_httpanonymizer(int *var)
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    if (!strcasecmp(token, "off"))
	*var = ANONYMIZER_NONE;
    else if (!strcasecmp(token, "paranoid"))
	*var = ANONYMIZER_PARANOID;
    else
	*var = ANONYMIZER_STANDARD;
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
    while ((u = *P)) {
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
#define dump_pathname_stat dump_string
#define free_pathname_stat free_string
#define dump_eol dump_string
#define free_eol free_string

static void
parse_pathname_stat(char **path)
{
    struct stat sb;
    parse_string(path);
    if (stat(*path, &sb) < 0) {
	debug(50, 1) ("parse_pathname_stat: %s: %s\n", *path, xstrerror());
	self_destruct();
    }
}

static void
dump_refreshpattern(StoreEntry * entry, const char *name, refresh_t * head)
{
    storeAppendPrintf(entry, "%s -- UNIMPLEMENTED\n", name);
}

static void
parse_refreshpattern(refresh_t ** head)
{
    char *token;
    char *pattern;
    time_t min = 0;
    int pct = 0;
    time_t max = 0;
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
    pct = i;
    GetInteger(i);		/* token: max */
    max = (time_t) (i * 60);	/* convert minutes to seconds */
    if ((errcode = regcomp(&comp, pattern, flags)) != 0) {
	char errbuf[256];
	regerror(errcode, &comp, errbuf, sizeof errbuf);
	debug(22, 0) ("%s line %d: %s\n",
	    cfg_filename, config_lineno, config_input_line);
	debug(22, 0) ("refreshAddToList: Invalid regular expression '%s': %s\n",
	    pattern, errbuf);
	return;
    }
    pct = pct < 0 ? 0 : pct;
    max = max < 0 ? 0 : max;
    t = xcalloc(1, sizeof(refresh_t));
    t->pattern = (char *) xstrdup(pattern);
    t->compiled_pattern = comp;
    t->min = min;
    t->pct = pct;
    t->max = max;
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
    while ((t = *head)) {
	*head = t->next;
	safe_free(t->pattern);
	regfree(&t->compiled_pattern);
	safe_free(t);
    }
}

static void
dump_regexlist(StoreEntry * entry, const char *name, relist * var)
{
    storeAppendPrintf(entry, "%s -- UNIMPLEMENTED\n", name);
}

static void
parse_regexlist(relist ** var)
{
    aclParseRegexList(var);
}

static void
free_regexlist(relist ** var)
{
    aclDestroyRegexList(*var);
    *var = NULL;
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
    xfree(*var);
    *var = NULL;
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

#define free_wordlist wordlistDestroy

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
