/*
 * $Id: cache_cf.cc,v 1.56 1996/07/09 03:41:19 wessels Exp $
 *
 * DEBUG: section 3     Configuration File Parsing
 * AUTHOR: Harvest Derived
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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

static struct {
    struct {
	int maxSize;
	int highWatherMark;
	int lowWaterMark;
    } Mem , Swap;
    struct {
	int maxObjSize;
	int defaultTtl;
    } Gopher, Http, Ftp;
    struct {
	int maxObjSize;
	int defaultTtl;
	char *relayHost;
	u_short relayPort;
    } Wais;
    int negativeTtl;
    int negativeDnsTtl;
    int positiveDnsTtl;
    int readTimeout;
    int lifetimeDefault;
    int lifetimeShutdown;
    int connectTimeout;
    int ageMaxDefault;
    int cleanRate;
    int dnsChildren;
    int maxRequestSize;
    double hotVmFactor;
    struct {
	u_short http;
	u_short icp;
    } Port;
    struct {
	char *log;
	char *access;
	char *hierarchy;
	char *store;
	int rotateNumber;
    } Log;
    char *adminEmail;
    char *effectiveUser;
    char *effectiveGroup;
    struct {
	char *ftpget;
	char *ftpget_opts;
	char *dnsserver;
    } Program;
    int sourcePing;
    int quickAbort;
    int commonLogFormat;
    int neighborTimeout;
    int stallDelay;
    int singleParentBypass;
    struct {
	char *host;
	char *prefix;
	u_short port;
	int withProxy;
    } Accel;
    char *appendDomain;
    char *debugOptions;
    char *pidFilename;
    char *visibleHostname;
    char *ftpUser;
    struct {
	char *host;
	u_short port;
	char *file;
	int rate;
    } Announce;
    struct {
	struct in_addr tcp_incoming;
	struct in_addr tcp_outgoing;
	struct in_addr udp_incoming;
	struct in_addr udp_outgoing;
    } Addrs;
    wordlist *cache_dirs;
    wordlist *http_stoplist;
    wordlist *gopher_stoplist;
    wordlist *ftp_stoplist;
    wordlist *hierarchy_stoplist;
    wordlist *local_domain_list;
    wordlist *inside_firewall_list;
    wordlist *dns_testname_list;
} Config;

#define DefaultMemMaxSize 	(16 << 20)	/* 16 MB */
#define DefaultMemHighWatherMark 90	/* 90% */
#define DefaultMemLowWatherMark  75	/* 75% */
#define DefaultSwapMaxSize	(100 << 10)	/* 100 MB (100*1024 kbytes) */
#define DefaultSwapHighWaterMark 90	/* 90% */
#define DefaultSwapLowWaterMark  75	/* 75% */

#define DefaultFtpDefaultTtl	(3 * 24 * 60 * 60)	/* 3 days */
#define DefaultFtpMaxObjSize	(4 << 20)	/* 4 MB */
#define DefaultGopherDefaultTtl	(3 * 24 * 60 * 60)	/* 3 days */
#define DefaultGopherMaxObjSize	(4 << 20)	/* 4 MB */
#define DefaultHttpDefaultTtl	(3 * 24 * 60 * 60)	/* 3 days */
#define DefaultHttpMaxObjSize	(4 << 20)	/* 4 MB */
#define DefaultWaisDefaultTtl	(3 * 24 * 60 * 60)	/* 3 days */
#define DefaultWaisMaxObjSize	(4 << 20)	/* 4 MB */
#define DefaultWaisRelayHost	(char *)NULL
#define DefaultWaisRelayPort	0

#define DefaultNegativeTtl	(5 * 60)	/* 5 min */
#define DefaultNegativeDnsTtl	(2 * 60)	/* 2 min */
#define DefaultPositiveDnsTtl	(360 * 60)	/* 6 hours */
#define DefaultReadTimeout	(15 * 60)	/* 15 min */
#define DefaultLifetimeDefault	(200 * 60)	/* 3+ hours */
#define DefaultLifetimeShutdown	30	/* 30 seconds */
#define DefaultConnectTimeout	(2 * 60)	/* 2 min */
#define DefaultDefaultAgeMax	(3600 * 24 * 30)	/* 30 days */
#define DefaultCleanRate	-1	/* disabled */
#define DefaultDnsChildren	5	/* 3 processes */
#define DefaultMaxRequestSize	(100 << 10)	/* 100Kb */
#define DefaultHotVmFactor	0.0	/* disabled */

#define DefaultHttpPortNum	CACHE_HTTP_PORT
#define DefaultIcpPortNum	CACHE_ICP_PORT

#define DefaultCacheLogFile	DEFAULT_CACHE_LOG
#define DefaultAccessLogFile	DEFAULT_ACCESS_LOG
#define DefaultHierarchyLogFile DEFAULT_HIERARCHY_LOG
#define DefaultStoreLogFile	DEFAULT_STORE_LOG
#define DefaultLogRotateNumber  10
#define DefaultAdminEmail	"webmaster"
#define DefaultFtpgetProgram	DEFAULT_FTPGET
#define DefaultFtpgetOptions	""
#define DefaultDnsserverProgram DEFAULT_DNSSERVER
#define DefaultEffectiveUser	(char *)NULL	/* default NONE */
#define DefaultEffectiveGroup	(char *)NULL	/* default NONE */
#define DefaultAppendDomain	(char *)NULL	/* default NONE */

#define DefaultDebugOptions	"ALL,1"		/* All sections at level 1 */
#define DefaultAccelHost	(char *)NULL	/* default NONE */
#define DefaultAccelPrefix	(char *)NULL	/* default NONE */
#define DefaultAccelPort	0	/* default off */
#define DefaultAccelWithProxy	0	/* default off */
#define DefaultSourcePing	0	/* default off */
#define DefaultCommonLogFormat	1	/* default on */
#define DefaultQuickAbort	0	/* default off */
#define DefaultNeighborTimeout  2	/* 2 seconds */
#define DefaultStallDelay	1	/* 1 seconds */
#define DefaultSingleParentBypass 0	/* default off */
#define DefaultPidFilename      (char *)NULL	/* default NONE */
#define DefaultVisibleHostname  (char *)NULL	/* default NONE */
#define DefaultFtpUser		"squid@"	/* Default without domain */
#define DefaultAnnounceHost	"sd.cache.nlanr.net"
#define DefaultAnnouncePort	3131
#define DefaultAnnounceFile	(char *)NULL	/* default NONE */
#define DefaultAnnounceRate	0	/* Default off */
#define DefaultTcpIncomingAddr	INADDR_ANY
#define DefaultTcpOutgoingAddr	INADDR_NONE
#define DefaultUdpIncomingAddr	INADDR_ANY
#define DefaultUdpOutgoingAddr	INADDR_NONE

ip_acl *local_ip_list = NULL;
ip_acl *firewall_ip_list = NULL;

int zap_disk_store = 0;		/* off, try to rebuild from disk */
int httpd_accel_mode = 0;	/* for fast access */
int emulate_httpd_log = DefaultCommonLogFormat;		/* for fast access */
time_t neighbor_timeout = DefaultNeighborTimeout;	/* for fast access */
int single_parent_bypass = 0;
int DnsPositiveTtl = DefaultPositiveDnsTtl;
char *DefaultSwapDir = DEFAULT_SWAP_DIR;
char *DefaultConfigFile = DEFAULT_CONFIG_FILE;
char *ConfigFile = NULL;	/* the whole thing */
char *cfg_filename = NULL;	/* just the last part */
char ForwardedBy[256];

char w_space[] = " \t\n";
char config_input_line[BUFSIZ];
int config_lineno = 0;

static void configSetFactoryDefaults _PARAMS((void));
static void configFreeMemory _PARAMS((void));
static void configDoConfigure _PARAMS((void));
static char *safe_xstrdup _PARAMS((char *p));
static char fatal_str[BUFSIZ];

void self_destruct()
{
    sprintf(fatal_str, "Bungled %s line %d: %s",
	cfg_filename, config_lineno, config_input_line);
    fatal(fatal_str);
}

int ip_acl_match(c, a)
     struct in_addr c;
     ip_acl *a;
{
    static struct in_addr h;

    h.s_addr = c.s_addr & a->mask.s_addr;
    if (h.s_addr == a->addr.s_addr)
	return 1;
    else
	return 0;
}


ip_access_type ip_access_check(address, list)
     struct in_addr address;
     ip_acl *list;
{
    static int init = 0;
    static struct in_addr localhost;
    ip_acl *p = NULL;
    struct in_addr naddr;	/* network byte-order IP addr */

    if (!list)
	return IP_ALLOW;

    if (!init) {
	memset((char *) &localhost, '\0', sizeof(struct in_addr));
	localhost.s_addr = inet_addr("127.0.0.1");
	init = 1;
    }
    naddr.s_addr = address.s_addr;
    if (naddr.s_addr == localhost.s_addr)
	return IP_ALLOW;

    debug(3, 5, "ip_access_check: using %s\n", inet_ntoa(naddr));

    for (p = list; p; p = p->next) {
	debug(3, 5, "ip_access_check: %s vs %s/%s\n",
	    inet_ntoa(naddr),
	    inet_ntoa(p->addr),
	    inet_ntoa(p->mask));
	if (ip_acl_match(naddr, p))
	    return p->access;
    }
    return IP_ALLOW;
}


void addToIPACL(list, ip_str, access)
     ip_acl **list;
     char *ip_str;
     ip_access_type access;
{
    ip_acl *p, *q;
    int a1, a2, a3, a4;
    int m1, m2, m3, m4;
    struct in_addr lmask;
    int c;

    if (!ip_str) {
	return;
    }
    if (!(*list)) {
	/* empty list */
	*list = xcalloc(1, sizeof(ip_acl));
	(*list)->next = NULL;
	q = *list;
    } else {
	/* find end of list */
	p = *list;
	while (p->next)
	    p = p->next;
	q = xcalloc(1, sizeof(ip_acl));
	q->next = NULL;
	p->next = q;
    }


    /* decode ip address */
    if (!strcasecmp(ip_str, "all")) {
	a1 = a2 = a3 = a4 = 0;
	lmask.s_addr = 0;
    } else {
	a1 = a2 = a3 = a4 = 0;
	c = sscanf(ip_str, "%d.%d.%d.%d/%d.%d.%d.%d", &a1, &a2, &a3, &a4,
	    &m1, &m2, &m3, &m4);

	switch (c) {
	case 4:
	    if (a1 == 0 && a2 == 0 && a3 == 0 && a4 == 0)	/* world   */
		lmask.s_addr = 0x00000000;
	    else if (a2 == 0 && a3 == 0 && a4 == 0)	/* class A */
		lmask.s_addr = htonl(0xff000000);
	    else if (a3 == 0 && a4 == 0)	/* class B */
		lmask.s_addr = htonl(0xffff0000);
	    else if (a4 == 0)	/* class C */
		lmask.s_addr = htonl(0xffffff00);
	    else
		lmask.s_addr = 0xffffffff;
	    break;

	case 5:
	    if (m1 < 0 || m1 > 32) {
		debug(3, 0, "addToIPACL: Ignoring invalid IP acl line '%s'\n",
		    ip_str);
		return;
	    }
	    lmask.s_addr = htonl(0xffffffff << (32 - m1));
	    break;

	case 8:
	    lmask.s_addr = htonl(m1 * 0x1000000 + m2 * 0x10000 + m3 * 0x100 + m4);
	    break;

	default:
	    debug(3, 0, "addToIPACL: Ignoring invalid IP acl line '%s'\n",
		ip_str);
	    return;
	}
    }

    q->access = access;
    q->addr.s_addr = htonl(a1 * 0x1000000 + a2 * 0x10000 + a3 * 0x100 + a4);
    q->mask.s_addr = lmask.s_addr;
}

void wordlistDestroy(list)
     wordlist **list;
{
    wordlist *w = NULL;
    wordlist *n = NULL;

    for (w = *list; w; w = n) {
	n = w->next;
	safe_free(w->key);
	safe_free(w);
    }
    *list = NULL;
}

void wordlistAdd(list, key)
     wordlist **list;
     char *key;
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

void intlistDestroy(list)
     intlist **list;
{
    intlist *w = NULL;
    intlist *n = NULL;

    for (w = *list; w; w = n) {
	n = w->next;
	safe_free(w);
    }
    *list = NULL;
}


/* Use this #define in all the parse*() functions.  Assumes 
 * ** char *token is defined
 */

#define GetInteger(var) \
	token = strtok(NULL, w_space); \
	if( token == NULL) \
		self_destruct(); \
	if (sscanf(token, "%d", &var) != 1) \
		self_destruct();


static void parseCacheHostLine()
{
    char *type = NULL;
    char *hostname = NULL;
    char *token = NULL;
    u_short http_port = CACHE_HTTP_PORT;
    u_short icp_port = CACHE_ICP_PORT;
    int options = 0;
    int weight = 1;
    int i;

    /* Parse a cache_host line */
    if (!(hostname = strtok(NULL, w_space)))
	self_destruct();
    if (!(type = strtok(NULL, w_space)))
	self_destruct();

    GetInteger(i);
    http_port = (u_short) i;
    GetInteger(i);
    icp_port = (u_short) i;
    while ((token = strtok(NULL, w_space))) {
	if (!strcasecmp(token, "proxy-only")) {
	    options |= NEIGHBOR_PROXY_ONLY;
	} else if (!strcasecmp(token, "no-query")) {
	    options |= NEIGHBOR_NO_QUERY;
	} else if (!strncasecmp(token, "weight=", 7)) {
	    weight = atoi(token + 7);
	} else {
	    debug(3, 0, "parseCacheHostLine: token='%s'\n", token);
	    self_destruct();
	}
    }
    if (weight < 1)
	weight = 1;
    neighbors_cf_add(hostname, type, http_port, icp_port, options, weight);
}

static void parseHostDomainLine()
{
    char *host = NULL;
    char *domain = NULL;
    if (!(host = strtok(NULL, w_space)))
	self_destruct();
    while ((domain = strtok(NULL, ", \t\n")))
	neighbors_cf_domain(host, domain);
}

static void parseHostAclLine()
{
    char *host = NULL;
    char *aclname = NULL;
    if (!(host = strtok(NULL, w_space)))
	self_destruct();
    while ((aclname = strtok(NULL, ", \t\n")))
	neighbors_cf_acl(host, aclname);
}


static void parseSourcePingLine()
{
    char *srcping;

    srcping = strtok(NULL, w_space);
    if (srcping == NULL)
	self_destruct();

    /* set source_ping, default is off. */
    if (!strcasecmp(srcping, "on"))
	Config.sourcePing = 1;
    else if (!strcasecmp(srcping, "off"))
	Config.sourcePing = 0;
    else
	Config.sourcePing = 0;
}


static void parseQuickAbortLine()
{
    char *abort;

    abort = strtok(NULL, w_space);
    if (abort == NULL)
	self_destruct();

    if (!strcasecmp(abort, "on") || !strcasecmp(abort, "quick"))
	Config.quickAbort = 1;
    else if (!strcmp(abort, "off") || !strcasecmp(abort, "normal"))
	Config.quickAbort = 0;
    else
	Config.quickAbort = 0;

}

static void parseMemLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Mem.maxSize = i << 20;
}

static void parseMemHighLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Mem.highWatherMark = i;
}

static void parseMemLowLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Mem.lowWaterMark = i;
}

static void parseHotVmFactorLine()
{
    char *token = NULL;
    double d;

    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    if (sscanf(token, "%lf", &d) != 1)
	self_destruct();
    if (d < 0)
	self_destruct();
    Config.hotVmFactor = d;
}

static void parseSwapLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Swap.maxSize = i << 10;
}

static void parseSwapHighLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Swap.highWatherMark = i;
}

static void parseSwapLowLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Swap.lowWaterMark = i;
}

static void parseHttpLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Http.maxObjSize = i << 20;
    GetInteger(i);
    Config.Http.defaultTtl = i * 60;
}

static void parseGopherLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Gopher.maxObjSize = i << 20;
    GetInteger(i);
    Config.Gopher.defaultTtl = i * 60;
}

static void parseFtpLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Ftp.maxObjSize = i << 20;
    GetInteger(i);
    Config.Ftp.defaultTtl = i * 60;
}

static void parseTTLPattern()
{
    char *token;
    char *pattern;
    time_t abs_ttl = 0;
    int pct_age = 0;
    time_t age_max = Config.ageMaxDefault;
    int i;

    token = strtok(NULL, w_space);	/* token: regex pattern */
    if (token == NULL)
	self_destruct();
    pattern = xstrdup(token);

    GetInteger(i);		/* token: abs_ttl */
    abs_ttl = (time_t) (i * 60);	/* convert minutes to seconds */

    token = strtok(NULL, w_space);	/* token: pct_age */
    if (token != (char *) NULL) {	/* pct_age is optional */
	if (sscanf(token, "%d", &pct_age) != 1)
	    self_destruct();
    }
    token = strtok(NULL, w_space);	/* token: age_max */
    if (token != (char *) NULL) {	/* age_max is optional */
	if (sscanf(token, "%d", &i) != 1)
	    self_destruct();
	age_max = (time_t) (i * 60);	/* convert minutes to seconds */
    }
    ttlAddToList(pattern, abs_ttl, pct_age, age_max);

    safe_free(pattern);
}

static void parseNegativeLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.negativeTtl = i * 60;
}

static void parseNegativeDnsLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.negativeDnsTtl = i * 60;
}

static void parsePositiveDnsLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.positiveDnsTtl = i * 60;
}

static void parseReadTimeoutLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.readTimeout = i * 60;
}

static void parseLifetimeLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.lifetimeDefault = i * 60;
}

static void parseShutdownLifetimeLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.lifetimeShutdown = i;
}

static void parseConnectTimeout()
{
    char *token;
    int i;
    GetInteger(i);
    Config.connectTimeout = i;
}

static void parseCleanRateLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.cleanRate = i * 60;
}

static void parseDnsChildrenLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.dnsChildren = i;
}

static void parseRequestSizeLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.maxRequestSize = i * 1024;
}

static void parseMgrLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.adminEmail);
    Config.adminEmail = xstrdup(token);
}

static void parseDirLine()
{
    char *token;

    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    wordlistAdd(&Config.cache_dirs, token);
}

static void parseHttpdAccelLine()
{
    char *token;
    static char buf[BUFSIZ];
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

static void parseHttpdAccelWithProxyLine()
{
    char *proxy;

    proxy = strtok(NULL, w_space);
    if (proxy == NULL)
	self_destruct();

    /* set httpd_accel_with_proxy, default is off. */
    if (!strcasecmp(proxy, "on"))
	Config.Accel.withProxy = 1;
    else if (!strcasecmp(proxy, "off"))
	Config.Accel.withProxy = 0;
    else
	Config.Accel.withProxy = 0;
}

static void parseEffectiveUserLine()
{
    char *token;

    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.effectiveUser);
    safe_free(Config.effectiveGroup);
    Config.effectiveUser = xstrdup(token);

    token = strtok(NULL, w_space);
    if (token == NULL)
	return;			/* group is optional */
    Config.effectiveGroup = xstrdup(token);
}

static void parseLogLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Log.log);
    Config.Log.log = xstrdup(token);
}

static void parseAccessLogLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Log.access);
    Config.Log.access = xstrdup(token);
}

static void parseHierachyLogLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Log.hierarchy);
    Config.Log.hierarchy = xstrdup(token);
}

static void parseStoreLogLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Log.store);
    Config.Log.store = xstrdup(token);
}

static void parseLogfileRotateLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Log.rotateNumber = i;
}

static void parseFtpProgramLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Program.ftpget);
    Config.Program.ftpget = xstrdup(token);
}

static void parseFtpOptionsLine()
{
    char *token;
    token = strtok(NULL, "");	/* Note "", don't separate these */
    if (token == NULL)
	self_destruct();
    safe_free(Config.Program.ftpget_opts);
    Config.Program.ftpget_opts = xstrdup(token);
}

static void parseDnsProgramLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Program.dnsserver);
    Config.Program.dnsserver = xstrdup(token);
}

static void parseEmulateLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    if (!strcasecmp(token, "on") || !strcasecmp(token, "enable"))
	Config.commonLogFormat = 1;
    else
	Config.commonLogFormat = 0;
}

static void parseWAISRelayLine()
{
    char *token;
    int i;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Wais.relayHost);
    Config.Wais.relayHost = xstrdup(token);
    GetInteger(i);
    Config.Wais.relayPort = (u_short) i;
    GetInteger(i);
    Config.Wais.maxObjSize = i << 20;
}

static void parseIPLine(list)
     ip_acl **list;
{
    char *token;
    while ((token = strtok(NULL, w_space))) {
	addToIPACL(list, token, IP_DENY);
    }
}

static void parseHttpStopLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	return;
    wordlistAdd(&Config.http_stoplist, token);
}

static void parseGopherStopLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	return;
    wordlistAdd(&Config.gopher_stoplist, token);
}
static void parseFtpStopLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	return;
    wordlistAdd(&Config.ftp_stoplist, token);
}
static void parseHierarchyStoplistLine()
{
    char *token;
    while ((token = strtok(NULL, w_space)))
	wordlistAdd(&Config.hierarchy_stoplist, token);
}

static void parseAppendDomainLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    if (*token != '.')
	self_destruct();
    safe_free(Config.appendDomain);
    Config.appendDomain = xstrdup(token);
}

static void parseAddressLine(addr)
     struct in_addr *addr;
{
    char *token;
    struct hostent *hp = NULL;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    if (inet_addr(token) != INADDR_NONE)
	(*addr).s_addr = inet_addr(token);
    else if ((hp = gethostbyname(token)))
	xmemcpy(addr, hp->h_addr, hp->h_length);
    else
	self_destruct();
}

static void parseLocalDomainFile(fname)
     char *fname;
{
    static char tmp_line[BUFSIZ];
    FILE *fp = NULL;
    char *t = NULL;

    if ((fp = fopen(fname, "r")) == NULL) {
	debug(3, 1, "parseLocalDomainFile: %s: %s\n", fname, xstrerror());
	return;
    }
    memset(tmp_line, '\0', BUFSIZ);
    while (fgets(tmp_line, BUFSIZ, fp)) {
	if (tmp_line[0] == '#')
	    continue;
	if (tmp_line[0] == '\0')
	    continue;
	if (tmp_line[0] == '\n')
	    continue;
	for (t = strtok(tmp_line, w_space); t; t = strtok(NULL, w_space)) {
	    debug(3, 1, "parseLocalDomainFileLine: adding %s\n", t);
	    wordlistAdd(&Config.local_domain_list, t);
	}
    }
    fclose(fp);
}

static void parseLocalDomainLine()
{
    char *token = NULL;
    struct stat sb;
    while ((token = strtok(NULL, w_space))) {
	if (stat(token, &sb) < 0) {
	    wordlistAdd(&Config.local_domain_list, token);
	} else {
	    parseLocalDomainFile(token);
	}
    }
}


static void parseInsideFirewallLine()
{
    char *token;
    while ((token = strtok(NULL, w_space))) {
	wordlistAdd(&Config.inside_firewall_list, token);
    }
}

static void parseDnsTestnameLine()
{
    char *token;
    while ((token = strtok(NULL, w_space))) {
	wordlistAdd(&Config.dns_testname_list, token);
    }
}

static void parseHttpPortLine()
{
    char *token;
    int i;
    GetInteger(i);
    if (i < 0)
	i = 0;
    Config.Port.http = (u_short) i;
}

static void parseIcpPortLine()
{
    char *token;
    int i;
    GetInteger(i);
    if (i < 0)
	i = 0;
    Config.Port.icp = (u_short) i;
}

static void parseNeighborTimeout()
{
    char *token;
    int i;
    GetInteger(i);
    Config.neighborTimeout = i;
}

static void parseSingleParentBypassLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    if (!strcasecmp(token, "on"))
	Config.singleParentBypass = 1;
}

static void parseDebugOptionsLine()
{
    char *token;
    token = strtok(NULL, "");	/* Note "", don't separate these */
    safe_free(Config.debugOptions);
    if (token == NULL) {
	Config.debugOptions = NULL;
	return;
    }
    Config.debugOptions = xstrdup(token);
}

static void parsePidFilenameLine()
{
    char *token;
    token = strtok(NULL, w_space);
    safe_free(Config.pidFilename);
    if (token == NULL)
	self_destruct();
    Config.pidFilename = xstrdup(token);
}

static void parseVisibleHostnameLine()
{
    char *token;
    token = strtok(NULL, w_space);
    safe_free(Config.visibleHostname);
    if (token == NULL)
	self_destruct();
    Config.visibleHostname = xstrdup(token);
}

static void parseFtpUserLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.ftpUser);
    Config.ftpUser = xstrdup(token);
}

static void parseCacheAnnounceLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Announce.rate = i * 3600;	/* hours to seconds */
}

static void parseAnnounceToLine()
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


int parseConfigFile(file_name)
     char *file_name;
{
    FILE *fp = NULL;
    char *token = NULL;
    static char tmp_line[BUFSIZ];

    configFreeMemory();
    configSetFactoryDefaults();
    aclDestroyAcls();
    aclDestroyAccessList(&HTTPAccessList);
    aclDestroyAccessList(&ICPAccessList);

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
	debug(3, 5, "Processing: '%s'\n", config_input_line);
	strcpy(tmp_line, config_input_line);
	if ((token = strtok(tmp_line, w_space)) == NULL)
	    continue;

	/* Parse a cache_host line */
	if (!strcmp(token, "cache_host"))
	    parseCacheHostLine();

	/* Parse a cache_host_domain line */
	else if (!strcmp(token, "cache_host_domain"))
	    parseHostDomainLine();
	else if (!strcmp(token, "cache_host_acl"))
	    parseHostAclLine();

	/* Parse a neighbor_timeout line */
	else if (!strcmp(token, "neighbor_timeout"))
	    parseNeighborTimeout();
	else if (!strcmp(token, "neighbour_timeout"))	/* alternate spelling */
	    parseNeighborTimeout();

	/* Parse a cache_dir line */
	else if (!strcmp(token, "cache_dir"))
	    parseDirLine();

	/* Parse a cache_log line */
	else if (!strcmp(token, "cache_log"))
	    parseLogLine();

	/* Parse a cache_access_log line */
	else if (!strcmp(token, "cache_access_log"))
	    parseAccessLogLine();

	/* Parse a cache_hierarchy_log line */
	else if (!strcmp(token, "cache_hierarchy_log"))
	    parseHierachyLogLine();

	/* Parse a cache_store_log line */
	else if (!strcmp(token, "cache_store_log"))
	    parseStoreLogLine();

	/* Parse a logfile_rotate line */
	else if (!strcmp(token, "logfile_rotate"))
	    parseLogfileRotateLine();

	/* Parse a httpd_accel_with_proxy line */
	else if (!strcmp(token, "httpd_accel_with_proxy"))
	    parseHttpdAccelWithProxyLine();

	/* Parse a httpd_accel line */
	else if (!strcmp(token, "httpd_accel"))
	    parseHttpdAccelLine();

	/* Parse a cache_effective_user line */
	else if (!strcmp(token, "cache_effective_user"))
	    parseEffectiveUserLine();

	/* Parse a cache_mem_high line */
	else if (!strcmp(token, "cache_swap_high"))
	    parseSwapHighLine();

	/* Parse a cache_mem_low line */
	else if (!strcmp(token, "cache_swap_low"))
	    parseSwapLowLine();

	/* Parse a cache_mem_high line */
	else if (!strcmp(token, "cache_mem_high"))
	    parseMemHighLine();

	/* Parse a cache_mem_low line */
	else if (!strcmp(token, "cache_mem_low"))
	    parseMemLowLine();

	/* Parse a cache_hot_vm_factor line */
	else if (!strcmp(token, "cache_hot_vm_factor"))
	    parseHotVmFactorLine();

	/* Parse a cache_mem line */
	/* XXX: this must be AFTER cache_mem_low, etc. */
	else if (!strcmp(token, "cache_mem"))
	    parseMemLine();

	/* Parse a cache_swap line */
	else if (!strcmp(token, "cache_swap"))
	    parseSwapLine();

	/* Parse a cache_mgr line */
	else if (!strcmp(token, "cache_mgr"))
	    parseMgrLine();

	else if (!strcmp(token, "acl"))
	    aclParseAclLine();

	else if (!strcmp(token, "http_access"))
	    aclParseAccessLine(&HTTPAccessList);

	else if (!strcmp(token, "icp_access"))
	    aclParseAccessLine(&ICPAccessList);

	/* Parse a http_stop line */
	else if (!strcmp(token, "http_stop"))
	    parseHttpStopLine();

	/* Parse a gopher_stop line */
	else if (!strcmp(token, "gopher_stop"))
	    parseGopherStopLine();

	/* Parse a ftp_stop line */
	else if (!strcmp(token, "ftp_stop"))
	    parseFtpStopLine();

	/* Parse a hierarchy_stoplist line */
	else if (!strcmp(token, "hierarchy_stoplist"))
	    parseHierarchyStoplistLine();

	/* Parse a gopher protocol line */
	else if (!strcmp(token, "gopher"))
	    parseGopherLine();

	/* Parse a http protocol line */
	else if (!strcmp(token, "http"))
	    parseHttpLine();

	/* Parse a ftp protocol line */
	else if (!strcmp(token, "ftp"))
	    parseFtpLine();

	else if (!strcmp(token, "ttl_pattern"))
	    parseTTLPattern();

	/* Parse a negative_ttl line */
	else if (!strcmp(token, "negative_ttl"))
	    parseNegativeLine();

	/* Parse a negative_dns_ttl line */
	else if (!strcmp(token, "negative_dns_ttl"))
	    parseNegativeDnsLine();

	/* Parse a positive_dns_ttl line */
	else if (!strcmp(token, "positive_dns_ttl"))
	    parsePositiveDnsLine();

	/* Parse a read_timeout line */
	else if (!strcmp(token, "read_timeout"))
	    parseReadTimeoutLine();

	/* Parse a clean_rate line */
	else if (!strcmp(token, "clean_rate"))
	    parseCleanRateLine();

	/* Parse a client_lifetime line */
	else if (!strcmp(token, "client_lifetime"))
	    parseLifetimeLine();

	/* Parse a client_lifetime line */
	else if (!strcmp(token, "shutdown_lifetime"))
	    parseShutdownLifetimeLine();

	/* Parse a request_size line */
	else if (!strcmp(token, "request_size"))
	    parseRequestSizeLine();

	/* Parse a connect_timeout line */
	else if (!strcmp(token, "connect_timeout"))
	    parseConnectTimeout();

	/* Parse a cache_ftp_program line */
	else if (!strcmp(token, "cache_ftp_program"))
	    parseFtpProgramLine();

	/* Parse a cache_ftp_options line */
	else if (!strcmp(token, "cache_ftp_options"))
	    parseFtpOptionsLine();

	/* Parse a cache_dns_program line */
	else if (!strcmp(token, "cache_dns_program"))
	    parseDnsProgramLine();

	/* Parse a cache_dns_program line */
	else if (!strcmp(token, "dns_children"))
	    parseDnsChildrenLine();

	/* Parse source_ping line */
	else if (!strcmp(token, "source_ping"))
	    parseSourcePingLine();

	/* Parse quick_abort line */
	else if (!strcmp(token, "quick_abort"))
	    parseQuickAbortLine();

	/* Parse emulate_httpd_log line */
	else if (!strcmp(token, "emulate_httpd_log"))
	    parseEmulateLine();

	else if (!strcmp(token, "append_domain"))
	    parseAppendDomainLine();

	else if (!strcmp(token, "wais_relay"))
	    parseWAISRelayLine();

	else if (!strcmp(token, "local_ip"))
	    parseIPLine(&local_ip_list);

	else if (!strcmp(token, "firewall_ip"))
	    parseIPLine(&firewall_ip_list);

	/* Parse a local_domain line */
	else if (!strcmp(token, "local_domain"))
	    parseLocalDomainLine();

	else if (!strcmp(token, "tcp_incoming_address"))
	    parseAddressLine(&Config.Addrs.tcp_incoming);

	else if (!strcmp(token, "tcp_outgoing_address"))
	    parseAddressLine(&Config.Addrs.tcp_outgoing);

	else if (!strcmp(token, "udp_incoming_address"))
	    parseAddressLine(&Config.Addrs.udp_incoming);

	else if (!strcmp(token, "udp_outgoing_address"))
	    parseAddressLine(&Config.Addrs.udp_outgoing);

	else if (!strcmp(token, "bind_address"))
	    parseAddressLine(&Config.Addrs.tcp_incoming);

	else if (!strcmp(token, "outbound_address"))
	    parseAddressLine(&Config.Addrs.tcp_outgoing);

	/* Parse a http_port line */
	else if (!strcmp(token, "http_port") || !strcmp(token, "ascii_port"))
	    parseHttpPortLine();

	/* Parse a icp_port line */
	else if (!strcmp(token, "icp_port") || !strcmp(token, "udp_port"))
	    parseIcpPortLine();

	else if (!strcmp(token, "inside_firewall"))
	    parseInsideFirewallLine();

	else if (!strcmp(token, "dns_testnames"))
	    parseDnsTestnameLine();

	else if (!strcmp(token, "single_parent_bypass"))
	    parseSingleParentBypassLine();

	else if (!strcmp(token, "debug_options"))
	    parseDebugOptionsLine();

	else if (!strcmp(token, "pid_filename"))
	    parsePidFilenameLine();

	else if (!strcmp(token, "visible_hostname"))
	    parseVisibleHostnameLine();

	else if (!strcmp(token, "ftp_user"))
	    parseFtpUserLine();

	else if (!strcmp(token, "cache_announce"))
	    parseCacheAnnounceLine();

	else if (!strcmp(token, "announce_to"))
	    parseAnnounceToLine();

	/* If unknown, treat as a comment line */
	else {
	    debug(3, 0, "parseConfigFile: line %d unrecognized: '%s'\n",
		config_lineno,
		config_input_line);
	}
    }

    /* Sanity checks */
    if (getClientLifetime() < getReadTimeout()) {
	printf("WARNING: client_lifetime (%d seconds) is less than read_timeout (%d seconds).\n",
	    getClientLifetime(), getReadTimeout());
	printf("         This may cause serious problems with your cache!!!\n");
	printf("         Change your configuration file.\n");
	fflush(stdout);		/* print message */
    }
    if (getCacheSwapMax() < (getCacheMemMax() >> 10)) {
	printf("WARNING: cache_swap (%d kbytes) is less than cache_mem (%d bytes).\n", getCacheSwapMax(), getCacheMemMax());
	printf("         This will cause serious problems with your cache!!!\n");
	printf("         Change your configuration file.\n");
	Config.Swap.maxSize = getCacheMemMax() >> 10;
	printf("         For this run, however, %s will use %d kbytes for cache_swap.\n", appname, getCacheSwapMax());
	fflush(stdout);		/* print message */
    }
    if (getCleanRate() > -1 && getCleanRate() < 60) {
	Config.cleanRate = (30 * 60);
	printf("WARNING: clean_rate is less than one minute.\n");
	printf("         This will cause serious problems with your cache!!!\n");
	printf("         Change your configuration file.\n");
	printf("         For this run, however, %s will use %d minutes for clean_rate.\n", appname, (int) (getCleanRate() / 60));
	fflush(stdout);		/* print message */
    }
    if (getDnsChildren() < 1) {
	printf("WARNING: dns_children was set to a bad value: %d\n",
	    getDnsChildren());
	printf("Setting it to the default (3).\n");
	Config.dnsChildren = 3;
    } else if (getDnsChildren() > DefaultDnsChildrenMax) {
	printf("WARNING: dns_children was set to a bad value: %d\n",
	    getDnsChildren());
	printf("Setting it to the maximum (%d).\n", DefaultDnsChildrenMax);
	Config.dnsChildren = DefaultDnsChildrenMax;
    }
    fclose(fp);

    configDoConfigure();
    return 0;
}



int getHttpMax()
{
    return Config.Http.maxObjSize;
}
int getHttpTTL()
{
    return Config.Http.defaultTtl;
}
int getGopherMax()
{
    return Config.Gopher.maxObjSize;
}
int getGopherTTL()
{
    return Config.Gopher.defaultTtl;
}
int getWAISMax()
{
    return Config.Wais.maxObjSize;
}
char *getWaisRelayHost()
{
    return Config.Wais.relayHost;
}
u_short getWaisRelayPort()
{
    return Config.Wais.relayPort;
}
int getFtpMax()
{
    return Config.Ftp.maxObjSize;
}
int getFtpTTL()
{
    return Config.Ftp.defaultTtl;
}
int getNegativeTTL()
{
    return Config.negativeTtl;
}
int getNegativeDNSTTL()
{
    return Config.negativeDnsTtl;
}
int getCacheMemMax()
{
    return Config.Mem.maxSize;
}
int getCacheMemHighWaterMark()
{
    return Config.Mem.highWatherMark;
}
int getCacheMemLowWaterMark()
{
    return Config.Mem.lowWaterMark;
}
double getCacheHotVmFactor()
{
    return Config.hotVmFactor;
}
int getCacheSwapHighWaterMark()
{
    return Config.Swap.highWatherMark;
}
int getCacheSwapLowWaterMark()
{
    return Config.Swap.lowWaterMark;
}
int getCacheSwapMax()
{
    return Config.Swap.maxSize;
}
int setCacheSwapMax(size)
     int size;
{
    Config.Swap.maxSize = size;
    return Config.Swap.maxSize;
}
int getReadTimeout()
{
    return Config.readTimeout;
}
int getClientLifetime()
{
    return Config.lifetimeDefault;
}
int getShutdownLifetime()
{
    return Config.lifetimeShutdown;
}
int getMaxRequestSize()
{
    return Config.maxRequestSize;
}
int getConnectTimeout()
{
    return Config.connectTimeout;
}
int getCleanRate()
{
    return Config.cleanRate;
}
int getSourcePing()
{
    return Config.sourcePing;
}
int getDnsChildren()
{
    return Config.dnsChildren;
}
int getQuickAbort()
{
    return Config.quickAbort;
}
char *getAccelPrefix()
{
    return Config.Accel.prefix;
}
u_short getAccelPort()
{
    return Config.Accel.port;
}
int getAccelWithProxy()
{
    return Config.Accel.withProxy;
}
char *getAccessLogFile()
{
    return Config.Log.access;
}
char *getHierarchyLogFile()
{
    return Config.Log.hierarchy;
}
char *getStoreLogFile()
{
    return Config.Log.store;
}
int getLogfileRotateNumber()
{
    return Config.Log.rotateNumber;
}
char *getCacheLogFile()
{
    return Config.Log.log;
}
u_short getHttpPortNum()
{
    return Config.Port.http;
}
u_short getIcpPortNum()
{
    return Config.Port.icp;
}
char *getDnsProgram()
{
    return Config.Program.dnsserver;
}
char *getFtpProgram()
{
    return Config.Program.ftpget;
}
char *getFtpOptions()
{
    return Config.Program.ftpget_opts;
}
char *getAdminEmail()
{
    return Config.adminEmail;
}
char *getDebugOptions()
{
    return Config.debugOptions;
}
int getStallDelay()
{
    return Config.stallDelay;
}
char *getAppendDomain()
{
    return Config.appendDomain;
}
char *getEffectiveUser()
{
    return Config.effectiveUser;
}
char *getEffectiveGroup()
{
    return Config.effectiveGroup;
}
char *getPidFilename()
{
    return Config.pidFilename;
}
char *getVisibleHostname()
{
    return Config.visibleHostname;
}
char *getFtpUser()
{
    return Config.ftpUser;
}
char *getAnnounceHost()
{
    return Config.Announce.host;
}
u_short getAnnouncePort()
{
    return Config.Announce.port;
}
char *getAnnounceFile()
{
    return Config.Announce.file;
}
int getAnnounceRate()
{
    return Config.Announce.rate;
}
wordlist *getHttpStoplist()
{
    return Config.http_stoplist;
}
wordlist *getFtpStoplist()
{
    return Config.ftp_stoplist;
}
wordlist *getHierarchyStoplist()
{
    return Config.hierarchy_stoplist;
}
wordlist *getGopherStoplist()
{
    return Config.gopher_stoplist;
}
wordlist *getLocalDomainList()
{
    return Config.local_domain_list;
}
wordlist *getCacheDirs()
{
    return Config.cache_dirs;
}
wordlist *getInsideFirewallList()
{
    return Config.inside_firewall_list;
}
wordlist *getDnsTestnameList()
{
    return Config.dns_testname_list;
}
struct in_addr getTcpIncomingAddr()
{
    return Config.Addrs.tcp_incoming;
}
struct in_addr getTcpOutgoingAddr()
{
    return Config.Addrs.tcp_outgoing;
}
struct in_addr getUdpIncomingAddr()
{
    return Config.Addrs.udp_incoming;
}
struct in_addr getUdpOutgoingAddr()
{
    return Config.Addrs.udp_outgoing;
}

u_short setHttpPortNum(port)
     u_short port;
{
    return (Config.Port.http = port);
}
u_short setIcpPortNum(port)
     u_short port;
{
    return (Config.Port.icp = port);
}


static char *safe_xstrdup(p)
     char *p;
{
    return p ? xstrdup(p) : p;
}

static void configFreeMemory()
{
    safe_free(Config.Wais.relayHost);
    safe_free(Config.Log.log);
    safe_free(Config.Log.access);
    safe_free(Config.Log.hierarchy);
    safe_free(Config.Log.store);
    safe_free(Config.adminEmail);
    safe_free(Config.effectiveUser);
    safe_free(Config.effectiveGroup);
    safe_free(Config.Program.ftpget);
    safe_free(Config.Program.ftpget_opts);
    safe_free(Config.Program.dnsserver);
    safe_free(Config.Accel.host);
    safe_free(Config.Accel.prefix);
    safe_free(Config.appendDomain);
    safe_free(Config.debugOptions);
    safe_free(Config.pidFilename);
    safe_free(Config.visibleHostname);
    safe_free(Config.ftpUser);
    safe_free(Config.Announce.host);
    safe_free(Config.Announce.file);
    wordlistDestroy(&Config.cache_dirs);
    wordlistDestroy(&Config.http_stoplist);
    wordlistDestroy(&Config.gopher_stoplist);
    wordlistDestroy(&Config.ftp_stoplist);
    wordlistDestroy(&Config.hierarchy_stoplist);
    wordlistDestroy(&Config.local_domain_list);
    wordlistDestroy(&Config.inside_firewall_list);
    wordlistDestroy(&Config.dns_testname_list);
}


static void configSetFactoryDefaults()
{
    Config.Mem.maxSize = DefaultMemMaxSize;
    Config.Mem.highWatherMark = DefaultMemHighWatherMark;
    Config.Mem.lowWaterMark = DefaultMemLowWatherMark;
    Config.Swap.maxSize = DefaultSwapMaxSize;
    Config.Swap.highWatherMark = DefaultSwapHighWaterMark;
    Config.Swap.lowWaterMark = DefaultSwapLowWaterMark;

    Config.Ftp.defaultTtl = DefaultFtpDefaultTtl;
    Config.Ftp.maxObjSize = DefaultFtpMaxObjSize;
    Config.Gopher.defaultTtl = DefaultGopherDefaultTtl;
    Config.Gopher.maxObjSize = DefaultGopherMaxObjSize;
    Config.Http.defaultTtl = DefaultHttpDefaultTtl;
    Config.Http.maxObjSize = DefaultHttpMaxObjSize;
    Config.Wais.defaultTtl = DefaultWaisDefaultTtl;
    Config.Wais.maxObjSize = DefaultWaisMaxObjSize;
    Config.Wais.relayHost = safe_xstrdup(DefaultWaisRelayHost);
    Config.Wais.relayPort = DefaultWaisRelayPort;

    Config.negativeTtl = DefaultNegativeTtl;
    Config.negativeDnsTtl = DefaultNegativeDnsTtl;
    Config.positiveDnsTtl = DefaultPositiveDnsTtl;
    Config.readTimeout = DefaultReadTimeout;
    Config.lifetimeDefault = DefaultLifetimeDefault;
    Config.lifetimeShutdown = DefaultLifetimeShutdown;
    Config.maxRequestSize = DefaultMaxRequestSize;
    Config.connectTimeout = DefaultConnectTimeout;
    Config.ageMaxDefault = DefaultDefaultAgeMax;
    Config.cleanRate = DefaultCleanRate;
    Config.dnsChildren = DefaultDnsChildren;
    Config.hotVmFactor = DefaultHotVmFactor;
    Config.sourcePing = DefaultSourcePing;
    Config.quickAbort = DefaultQuickAbort;
    Config.commonLogFormat = DefaultCommonLogFormat;
    Config.debugOptions = safe_xstrdup(DefaultDebugOptions);
    Config.neighborTimeout = DefaultNeighborTimeout;
    Config.stallDelay = DefaultStallDelay;
    Config.singleParentBypass = DefaultSingleParentBypass;
    Config.adminEmail = safe_xstrdup(DefaultAdminEmail);
    Config.effectiveUser = safe_xstrdup(DefaultEffectiveUser);
    Config.effectiveGroup = safe_xstrdup(DefaultEffectiveGroup);
    Config.appendDomain = safe_xstrdup(DefaultAppendDomain);

    Config.Port.http = DefaultHttpPortNum;
    Config.Port.icp = DefaultIcpPortNum;
    Config.Log.log = safe_xstrdup(DefaultCacheLogFile);
    Config.Log.access = safe_xstrdup(DefaultAccessLogFile);
    Config.Log.hierarchy = safe_xstrdup(DefaultHierarchyLogFile);
    Config.Log.store = safe_xstrdup(DefaultStoreLogFile);
    Config.Log.rotateNumber = DefaultLogRotateNumber;
    Config.Program.ftpget = safe_xstrdup(DefaultFtpgetProgram);
    Config.Program.ftpget_opts = safe_xstrdup(DefaultFtpgetOptions);
    Config.Program.dnsserver = safe_xstrdup(DefaultDnsserverProgram);
    Config.Accel.host = safe_xstrdup(DefaultAccelHost);
    Config.Accel.prefix = safe_xstrdup(DefaultAccelPrefix);
    Config.Accel.port = DefaultAccelPort;
    Config.Accel.withProxy = DefaultAccelWithProxy;
    Config.pidFilename = safe_xstrdup(DefaultPidFilename);
    Config.visibleHostname = safe_xstrdup(DefaultVisibleHostname);
    Config.ftpUser = safe_xstrdup(DefaultFtpUser);
    Config.Announce.host = safe_xstrdup(DefaultAnnounceHost);
    Config.Announce.port = DefaultAnnouncePort;
    Config.Announce.file = safe_xstrdup(DefaultAnnounceFile);
    Config.Announce.rate = DefaultAnnounceRate;
    Config.Addrs.tcp_outgoing.s_addr = DefaultTcpOutgoingAddr;
    Config.Addrs.tcp_incoming.s_addr = DefaultTcpIncomingAddr;
    Config.Addrs.udp_outgoing.s_addr = DefaultUdpOutgoingAddr;
    Config.Addrs.udp_incoming.s_addr = DefaultUdpIncomingAddr;
}

static void configDoConfigure()
{
    httpd_accel_mode = Config.Accel.prefix ? 1 : 0;
    emulate_httpd_log = Config.commonLogFormat;
    neighbor_timeout = (time_t) Config.neighborTimeout;
    single_parent_bypass = Config.singleParentBypass;
    DnsPositiveTtl = Config.positiveDnsTtl;
    sprintf(ForwardedBy, "Forwarded: by http://%s:%d/",
	getMyHostname(), getHttpPortNum());


#if !ALLOW_HOT_CACHE
    if (!httpd_accel_mode || Config.Accel.withProxy) {
	/* Not running strict httpd_accel--force hot_vm_factor to be 0 */
	if (Config.hotVmFactor != 0.0) {
	    printf("WARNING: Non-zero hot_vm_factor not allowed unless running only\n");
	    printf("         in httpd_accel mode.  Setting hot_vm_factor to 0.\n");
	    Config.hotVmFactor = 0.0;
	}
    }
#endif /* !ALLOW_HOT_CACHE */
}
