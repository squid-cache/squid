/*
 * $Id: cache_cf.cc,v 1.199 1997/07/06 05:14:09 wessels Exp $
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

struct SquidConfig Config;

static const char *const T_SECOND_STR = "second";
static const char *const T_MINUTE_STR = "minute";
static const char *const T_HOUR_STR = "hour";
static const char *const T_DAY_STR = "day";
static const char *const T_WEEK_STR = "week";
static const char *const T_FORTNIGHT_STR = "fortnight";
static const char *const T_MONTH_STR = "month";
static const char *const T_YEAR_STR = "year";
static const char *const T_DECADE_STR = "decade";

int httpd_accel_mode = 0;	/* for fast access */
const char *DefaultSwapDir = DEFAULT_SWAP_DIR;
const char *DefaultConfigFile = DEFAULT_CONFIG_FILE;
char *ConfigFile = NULL;	/* the whole thing */
const char *cfg_filename = NULL;	/* just the last part */

static const char *const list_sep = ", \t\n\r";
char config_input_line[BUFSIZ];
int config_lineno = 0;

static char fatal_str[BUFSIZ];
static void self_destruct _PARAMS((void));
static void wordlistAdd _PARAMS((wordlist **, const char *));

static void configDoConfigure _PARAMS((void));
static void parseRefreshPattern _PARAMS((int icase));
static int parseTimeUnits _PARAMS((const char *unit));
static void parseTimeLine _PARAMS((int *iptr, const char *units));

static void parse_string _PARAMS((char **));
static void parse_wordlist _PARAMS((wordlist **));
static void dump_all _PARAMS((void));
static void default_all _PARAMS((void));
static int parse_line _PARAMS((char *));

/* These come from cf_gen.c */
static void default_all _PARAMS((void));
static void dump_all _PARAMS((void));
static void free_all _PARAMS((void));

static void
self_destruct(void)
{
    sprintf(fatal_str, "Bungled %s line %d: %s",
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

static void
parseRefreshPattern(int icase)
{
    char *token;
    char *pattern;
    time_t min = 0;
    int pct = 0;
    time_t max = 0;
    int i;
    token = strtok(NULL, w_space);	/* token: regex pattern */
    if (token == NULL)
	self_destruct();
    pattern = xstrdup(token);
    GetInteger(i);		/* token: min */
    min = (time_t) (i * 60);	/* convert minutes to seconds */
    GetInteger(i);		/* token: pct */
    pct = i;
    GetInteger(i);		/* token: max */
    max = (time_t) (i * 60);	/* convert minutes to seconds */
    refreshAddToList(pattern, icase, min, pct, max);
    safe_free(pattern);
}

int
parseConfigFile(const char *file_name)
{
    FILE *fp = NULL;
    char *token = NULL;
    LOCAL_ARRAY(char, tmp_line, BUFSIZ);

    free_all();
    default_all();
    aclDestroyAcls();
    aclDestroyDenyInfoList(&Config.denyInfoList);
    aclDestroyAccessList(&Config.accessList.HTTP);
    aclDestroyAccessList(&Config.accessList.ICP);
    aclDestroyAccessList(&Config.accessList.MISS);
    aclDestroyAccessList(&Config.accessList.NeverDirect);
    aclDestroyAccessList(&Config.accessList.AlwaysDirect);
    aclDestroyRegexList(Config.cache_stop_relist);
    Config.cache_stop_relist = NULL;

    if ((fp = fopen(file_name, "r")) == NULL) {
	sprintf(fatal_str, "Unable to open configuration file: %s: %s",
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
	strcpy(tmp_line, config_input_line);
	if (!parse_line(tmp_line)) {
	    debug(3, 0) ("parseConfigFile: line %d unrecognized: '%s'\n",
		config_lineno,
		config_input_line);
	}
    }

    /* Scale values */
    Config.maxRequestSize <<= 10;	/* 1k */
    Config.Store.maxObjectSize <<= 10;	/* 1k */
    Config.Mem.maxSize <<= 10;	/* 1m */

    /* Sanity checks */
    if (Config.Swap.maxSize < (Config.Mem.maxSize >> 10)) {
	printf("WARNING: cache_swap (%d kbytes) is less than cache_mem (%d bytes).\n", Config.Swap.maxSize, Config.Mem.maxSize);
	printf("         This will cause serious problems with your cache!!!\n");
	printf("         Change your configuration file.\n");
	fflush(stdout);		/* print message */
    }
    if (Config.cleanRate < 1)
	Config.cleanRate = 86400 * 365;		/* one year */
    if (Config.Announce.rate < 1) {
	Config.Announce.rate = 86400 * 365;	/* one year */
	Config.Announce.on = 0;
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
    configDoConfigure();
    dump_all();
    return 0;
}

static void
configDoConfigure(void)
{
    httpd_accel_mode = Config.Accel.prefix ? 1 : 0;
    if (Config.errHtmlText == NULL)
	Config.errHtmlText = xstrdup(null_string);
    storeConfigure();
    if (httpd_accel_mode && !strcmp(Config.Accel.host, "virtual"))
	vhost_mode = 1;
    if (Config.Port.http == NULL)
	fatal("No http_port specified!");
    sprintf(ThisCache, "%s:%d (Squid/%s)",
	getMyHostname(),
	(int) Config.Port.http->i,
	SQUID_VERSION);
    if (!Config.udpMaxHitObjsz || Config.udpMaxHitObjsz > SQUID_UDP_SO_SNDBUF)
	Config.udpMaxHitObjsz = SQUID_UDP_SO_SNDBUF;
    if (Config.appendDomain)
	Config.appendDomainLen = strlen(Config.appendDomain);
    else
	Config.appendDomainLen = 0;
}

/* Parse a time specification from the config file.  Store the
 * result in 'iptr', after converting it to 'units' */
static void
parseTimeLine(int *iptr, const char *units)
{
    char *token;
    double d;
    int m;
    int u;
    if ((u = parseTimeUnits(units)) == 0)
	self_destruct();
    if ((token = strtok(NULL, w_space)) == NULL)
	self_destruct();
    d = atof(token);
    m = u;			/* default to 'units' if none specified */
    if ((token = strtok(NULL, w_space)) != NULL) {
	if ((m = parseTimeUnits(token)) == 0)
	    self_destruct();
    }
    *iptr = m * d / u;
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

/*****************************************************************************
 * Max
 *****************************************************************************/

static void
dump_acl(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_acl(void)
{
    aclParseAclLine();
}

static void
dump_acl_access(struct _acl_access *head)
{
    debug(0,0)("XXX need to fix\n");
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
dump_address(struct in_addr addr)
{
    printf("%s", inet_ntoa(addr));
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
dump_announceto(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_announceto(void)
{
    char *token;
    int i;

    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Announce.host);
    Config.Announce.host = xstrdup(token);
    if ((token = strchr(Config.Announce.host, ':'))) {
	*token++ = '\0';
	if (sscanf(token, "%d", &i) != 1)
	    Config.Announce.port = i;
    }
    token = strtok(NULL, w_space);
    if (token == NULL)
	return;
    safe_free(Config.Announce.file);
    Config.Announce.file = xstrdup(token);
}

static void
dump_appenddomain(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_appenddomain(void)
{
    char *token = strtok(NULL, w_space);

    if (token == NULL)
	self_destruct();
    if (*token != '.')
	self_destruct();
    safe_free(Config.appendDomain);
    Config.appendDomain = xstrdup(token);
}

static void
dump_cacheannounce(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_cacheannounce(void)
{
    char *token;
    int i;
    GetInteger(i);
    Config.Announce.rate = i * 3600;	/* hours to seconds */
    if (Config.Announce.rate > 0)
	Config.Announce.on = 1;
}

static void
dump_cachedir(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_cachedir(void)
{
    char *token;
    char *dir;
    int i;
    int size;
    int l1;
    int l2;
    int readonly = 0;

    if ((token = strtok(NULL, w_space)) == NULL)
	self_destruct();
    dir = token;
    GetInteger(i);
    size = i << 10;		/* Mbytes to kbytes */
    Config.Swap.maxSize += size;
    GetInteger(i);
    l1 = i;
    GetInteger(i);
    l2 = i;
    if ((token = strtok(NULL, w_space)))
	if (!strcasecmp(token, "read-only"))
	    readonly = 1;
    if (configured_once)
	storeReconfigureSwapDisk(dir, size, l1, l2, readonly);
    else
	storeAddSwapDisk(dir, size, l1, l2, readonly);
}

static void
dump_cache_peer(struct cache_peer *p)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_cache_peer(struct cache_peer **head)
{
    char *token = NULL;
    struct cache_peer peer;
    struct cache_peer *p;
    int i;
    memset(&peer, '\0', sizeof(struct cache_peer));
    peer.http = CACHE_HTTP_PORT;
    peer.icp = CACHE_ICP_PORT;
    peer.weight = 1;
    if (!(peer.host = strtok(NULL, w_space))) 
	self_destruct();
    if (!(peer.type = strtok(NULL, w_space)))
	self_destruct();
    GetInteger(i);
    peer.http = (u_short) i;
    GetInteger(i);
    peer.icp = (u_short) i;
    while ((token = strtok(NULL, w_space))) {
	if (!strcasecmp(token, "proxy-only")) {
	    peer.options |= NEIGHBOR_PROXY_ONLY;
	} else if (!strcasecmp(token, "no-query")) {
	    peer.options |= NEIGHBOR_NO_QUERY;
	} else if (!strcasecmp(token, "multicast-responder")) {
	    peer.options |= NEIGHBOR_MCAST_RESPONDER;
	} else if (!strncasecmp(token, "weight=", 7)) {
	    peer.weight = atoi(token + 7);
	} else if (!strncasecmp(token, "ttl=", 4)) {
	    peer.mcast_ttl = atoi(token + 4);
	    if (peer.mcast_ttl < 0)
		peer.mcast_ttl = 0;
	    if (peer.mcast_ttl > 128)
		peer.mcast_ttl = 128;
	} else if (!strncasecmp(token, "default", 7)) {
	    peer.options |= NEIGHBOR_DEFAULT_PARENT;
	} else if (!strncasecmp(token, "round-robin", 11)) {
	    peer.options |= NEIGHBOR_ROUNDROBIN;
	} else {
	    debug(3, 0) ("parse_cache_peer: token='%s'\n", token);
	    self_destruct();
	}
    }
    if (peer.weight < 1)
	peer.weight = 1;
    p = xcalloc(1, sizeof(struct cache_peer));
    *p = peer;
    p->host = xstrdup(peer.host);
    p->type = xstrdup(peer.type);
    while (*head != NULL)
	head = &(*head)->next;
    *head = p;
}

static void
free_cache_peer(struct cache_peer **P)
{
	struct cache_peer *p;
	while ((p = *P)) {
		*P = p->next;
		xfree(p->host);
		xfree(p->type);
		xfree(p);
	}
}

static void
dump_cachemgrpasswd(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_cachemgrpasswd(void)
{
    char *passwd = NULL;
    wordlist *actions = NULL;
    parse_string(&passwd);
    parse_wordlist(&actions);
    objcachePasswdAdd(&Config.passwd_list, passwd, actions);
    wordlistDestroy(&actions);
}

static void
dump_denyinfo(struct _acl_deny_info_list *var)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_denyinfo(struct _acl_deny_info_list **var)
{
    aclParseDenyInfoLine(var);
}

static void
dump_errhtml(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_errhtml(void)
{
    char *token;
    if ((token = strtok(NULL, null_string)))
	Config.errHtmlText = xstrdup(token);
}

static void
dump_hostacl(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_hostacl(void)
{
    char *host = NULL;
    char *aclname = NULL;
    if (!(host = strtok(NULL, w_space)))
	self_destruct();
    while ((aclname = strtok(NULL, list_sep)))
	neighborAddAcl(host, aclname);
}

static void
dump_hostdomain(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_hostdomain(void)
{
    char *host = NULL;
    char *domain = NULL;
    if (!(host = strtok(NULL, w_space)))
	self_destruct();
    while ((domain = strtok(NULL, list_sep)))
	neighborAddDomainPing(host, domain);
}

static void
dump_hostdomaintype(void)
{
    debug(0,0)("XXX need to fix\n");
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
    while ((domain = strtok(NULL, list_sep)))
	neighborAddDomainType(host, domain, type);
}

static void
dump_httpanonymizer(int var)
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
dump_httpdaccel(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_httpdaccel(void)
{
    char *token;
    LOCAL_ARRAY(char, buf, BUFSIZ);
    int i;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Accel.host);
    Config.Accel.host = xstrdup(token);
    GetInteger(i);
    Config.Accel.port = i;
    safe_free(Config.Accel.prefix);
    sprintf(buf, "http://%s:%d", Config.Accel.host, Config.Accel.port);
    Config.Accel.prefix = xstrdup(buf);
    httpd_accel_mode = 1;
}

static void
dump_ushortlist(ushortlist *u)
{
    while (u) {
	printf("%d ", (int) u->i);
	u = u->next;
    }
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
free_ushortlist(ushortlist **P)
{
	ushortlist *u;
	while ((u = *P)) {
		*P = u->next;
		xfree(u);
	}
}

static void
dump_int(int var)
{
    printf("%d", var);
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
dump_onoff(int var)
{
    printf(var ? "on" : "off");
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
#define dump_pathname_stat dump_string
#define free_pathname_stat free_string

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
dump_refreshpattern(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_refreshpattern(void)
{
    parseRefreshPattern(0);
}

static void
dump_refreshpattern_icase(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_refreshpattern_icase(void)
{
    parseRefreshPattern(1);
}

static void
dump_regexlist(relist * var)
{
    debug(0,0)("XXX need to fix\n");
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
dump_string(char *var)
{
    printf("%s", var);
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
dump_string_optional(const char *var)
{
    printf("%s", var);
}

static void
parse_volatile_string(char *volatile *var)
{
    char *token = strtok(NULL, null_string);
    safe_free(*var);
    if (token == NULL) {
	*var = NULL;
	return;
    }
    *var = xstrdup(token);
}

static void
dump_time_min(int var)
{
    printf("%d", var / 60);
}

static void
parse_time_min(int *var)
{
    parseTimeLine(var, T_MINUTE_STR);
}

static void
dump_time_sec(int var)
{
    printf("%d", var);
}

static void
parse_time_sec(int *var)
{
    parseTimeLine(var, T_SECOND_STR);
}

static void
dump_ushort(u_short var)
{
    printf("%d", var);
}

static void
free_ushort(u_short *u)
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
dump_vizhack(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_vizhack(void)
{
    char *token;
    int i;
    const struct hostent *hp;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    if (safe_inet_addr(token, &Config.vizHack.addr) == 1)
	(void) 0;
    else if ((hp = gethostbyname(token)))	/* dont use ipcache */
	Config.vizHack.addr = inaddrFromHostent(hp);
    else
	self_destruct();
    if ((token = strtok(NULL, w_space)) == NULL)
	self_destruct();
    if (sscanf(token, "%d", &i) == 1)
	Config.vizHack.port = i;
    Config.vizHack.mcast_ttl = 64;
    if ((token = strtok(NULL, w_space)) == NULL)
	return;
    if (sscanf(token, "%d", &i) == 1)
	Config.vizHack.mcast_ttl = i;
}

static void
dump_wordlist(wordlist * list)
{
    printf("{");
    while (list != NULL) {
	printf("%s ", list->key);
	list = list->next;
    }
    printf("}");
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
