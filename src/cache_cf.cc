/*
 * $Id: cache_cf.cc,v 1.87 1996/09/14 08:45:37 wessels Exp $
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

struct SquidConfig Config;

#define DefaultMemMaxSize 	(16 << 20)	/* 16 MB */
#define DefaultMemHighWaterMark 90	/* 90% */
#define DefaultMemLowWaterMark  75	/* 75% */
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

#define DefaultExpireAge	(86400 * 7)	/* 1 week */
#define DefaultNegativeTtl	(5 * 60)	/* 5 min */
#define DefaultNegativeDnsTtl	(2 * 60)	/* 2 min */
#define DefaultPositiveDnsTtl	(360 * 60)	/* 6 hours */
#define DefaultReadTimeout	(15 * 60)	/* 15 min */
#define DefaultLifetimeDefault	(200 * 60)	/* 3+ hours */
#define DefaultLifetimeShutdown	30	/* 30 seconds */
#define DefaultConnectTimeout	(2 * 60)	/* 2 min */
#define DefaultDefaultAgeMax	(3600 * 24 * 30)	/* 30 days */
#define DefaultCleanRate	-1	/* disabled */
#define DefaultDnsChildren	5	/* 5 processes */
#define DefaultRedirectChildren	5	/* 5 processes */
#define DefaultMaxRequestSize	(100 << 10)	/* 100Kb */
#define DefaultHotVmFactor	0.0	/* disabled */

#define DefaultHttpPortNum	CACHE_HTTP_PORT
#define DefaultIcpPortNum	CACHE_ICP_PORT

#define DefaultCacheLogFile	DEFAULT_CACHE_LOG
#define DefaultAccessLogFile	DEFAULT_ACCESS_LOG
#define DefaultStoreLogFile	DEFAULT_STORE_LOG
#if USE_PROXY_AUTH
#define DefaultProxyAuthFile    (char *)NULL	/* default NONE */
#define DefaultProxyAuthIgnoreDomain (char *)NULL	/* default NONE */
#endif /* USE_PROXY_AUTH */
#define DefaultLogRotateNumber  10
#define DefaultAdminEmail	"webmaster"
#define DefaultFtpgetProgram	DEFAULT_FTPGET
#define DefaultFtpgetOptions	""
#define DefaultDnsserverProgram DEFAULT_DNSSERVER
#define DefaultRedirectProgram  (char *)NULL	/* default NONE */
#define DefaultEffectiveUser	(char *)NULL	/* default NONE */
#define DefaultEffectiveGroup	(char *)NULL	/* default NONE */
#define DefaultAppendDomain	(char *)NULL	/* default NONE */
#define DefaultErrHtmlText	(char *)NULL	/* default NONE */

#define DefaultDebugOptions	"ALL,1"		/* All sections at level 1 */
#define DefaultAccelHost	(char *)NULL	/* default NONE */
#define DefaultAccelPrefix	(char *)NULL	/* default NONE */
#define DefaultAccelPort	0	/* default off */
#define DefaultAccelWithProxy	0	/* default off */
#define DefaultSourcePing	0	/* default off */
#define DefaultCommonLogFormat	0	/* default off */
#if LOG_FULL_HEADERS
#define DefaultLogMimeHdrs	0	/* default off */
#endif /* LOG_FULL_HEADERS */
#define DefaultIdentLookup	0	/* default off */
#define DefaultQuickAbortMin	-1	/* default off */
#define DefaultQuickAbortPct	0	/* default off */
#define DefaultQuickAbortMax	0	/* default off */
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
#define DefaultTcpRcvBufsz	0	/* use system default */
#define DefaultTcpIncomingAddr	INADDR_ANY
#define DefaultTcpOutgoingAddr	INADDR_NONE
#define DefaultUdpIncomingAddr	INADDR_ANY
#define DefaultUdpOutgoingAddr	INADDR_NONE
#define DefaultClientNetmask	0xFFFFFFFF
#define DefaultSslProxyPort	0
#define DefaultSslProxyHost	(char *)NULL
#define DefaultIpcacheSize	1024
#define DefaultIpcacheLow	90
#define DefaultIpcacheHigh	95

int httpd_accel_mode = 0;	/* for fast access */
char *DefaultSwapDir = DEFAULT_SWAP_DIR;
char *DefaultConfigFile = DEFAULT_CONFIG_FILE;
char *ConfigFile = NULL;	/* the whole thing */
char *cfg_filename = NULL;	/* just the last part */
char ForwardedBy[256];

char w_space[] = " \t\n";
char config_input_line[BUFSIZ];
int config_lineno = 0;

static char *safe_xstrdup(char *p);
static void parseOnOff(int *);
static void parseIntegerValue(int *);
static char fatal_str[BUFSIZ];
static void configDoConfigure(void);
static void configFreeMemory(void);
static void configSetFactoryDefaults(void);
static void parseAccessLogLine(void);
static void parseAddressLine(struct in_addr *);
static void parseAnnounceToLine(void);
static void parseAppendDomainLine(void);
static void parseCacheAnnounceLine(void);
static void parseCacheHostLine(void);
static void parseDebugOptionsLine(void);
static void parseDirLine(void);
static void parseDnsProgramLine(void);
static void parseDnsTestnameLine(void);
static void parseEffectiveUserLine(void);
static void parseErrHtmlLine(void);
static void parseFtpLine(void);
static void parseFtpOptionsLine(void);
static void parseFtpProgramLine(void);
static void parseFtpUserLine(void);
static void parseGopherLine(void);
static void parseHierarchyStoplistLine(void);
static void parseHostAclLine(void);
static void parseHostDomainLine(void);
static void parseHotVmFactorLine(void);
static void parseHttpLine(void);
static void parseHttpPortLine(void);
static void parseHttpdAccelLine(void);
static void parseIPLine(ip_acl ** list);
static void parseIcpPortLine(void);
static void parseInsideFirewallLine(void);
static void parseLocalDomainFile(char *fname);
static void parseLocalDomainLine(void);
static void parseLogLine(void);
static void parseMemLine(void);
static void parseMgrLine(void);
static void parsePidFilenameLine(void);
static void parseRequestSizeLine(void);
static void parseStoreLogLine(void);
static void parseSwapLine(void);
static void parseTTLPattern(int icase, int force);
static void parseVisibleHostnameLine(void);
static void parseWAISRelayLine(void);
static void parseMinutesLine(int *);

void
self_destruct()
{
    sprintf(fatal_str, "Bungled %s line %d: %s",
	cfg_filename, config_lineno, config_input_line);
    fatal(fatal_str);
}

int
ip_acl_match(struct in_addr c, ip_acl * a)
{
    static struct in_addr h;

    h.s_addr = c.s_addr & a->mask.s_addr;
    if (h.s_addr == a->addr.s_addr)
	return 1;
    else
	return 0;
}


ip_access_type
ip_access_check(struct in_addr address, ip_acl * list)
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


void
addToIPACL(ip_acl ** list, char *ip_str, ip_access_type access)
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

void
wordlistDestroy(wordlist ** list)
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

void
wordlistAdd(wordlist ** list, char *key)
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


/* Use this #define in all the parse*() functions.  Assumes 
 * ** char *token is defined
 */

#define GetInteger(var) \
	token = strtok(NULL, w_space); \
	if( token == NULL) \
		self_destruct(); \
	if (sscanf(token, "%d", &var) != 1) \
		self_destruct();


static void
parseCacheHostLine()
{
    char *type = NULL;
    char *hostname = NULL;
    char *token = NULL;
    u_short http_port = CACHE_HTTP_PORT;
    u_short icp_port = CACHE_ICP_PORT;
    int options = 0;
    int weight = 1;
    int i;

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

static void
parseHostDomainLine()
{
    char *host = NULL;
    char *domain = NULL;
    if (!(host = strtok(NULL, w_space)))
	self_destruct();
    while ((domain = strtok(NULL, ", \t\n")))
	neighbors_cf_domain(host, domain);
}

static void
parseHostAclLine()
{
    char *host = NULL;
    char *aclname = NULL;
    if (!(host = strtok(NULL, w_space)))
	self_destruct();
    while ((aclname = strtok(NULL, ", \t\n")))
	neighbors_cf_acl(host, aclname);
}


static void
parseMemLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Mem.maxSize = i << 20;
}

static void
parseHotVmFactorLine()
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

static void
parseSwapLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Swap.maxSize = i << 10;
}

static void
parseHttpLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Http.maxObjSize = i << 20;
    GetInteger(i);
    Config.Http.defaultTtl = i * 60;
}

static void
parseGopherLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Gopher.maxObjSize = i << 20;
    GetInteger(i);
    Config.Gopher.defaultTtl = i * 60;
}

static void
parseFtpLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Ftp.maxObjSize = i << 20;
    GetInteger(i);
    Config.Ftp.defaultTtl = i * 60;
}

static void
parseTTLPattern(int icase, int force)
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

	token = strtok(NULL, w_space);	/* token: age_max */
	if (token != (char *) NULL) {	/* age_max is optional */
	    if (sscanf(token, "%d", &i) != 1)
		self_destruct();
	    age_max = (time_t) (i * 60);	/* convert minutes to seconds */
	}
    }
    ttlAddToList(pattern, icase, force, abs_ttl, pct_age, age_max);
    safe_free(pattern);
}

static void
parseQuickAbort()
{
    char *token;
    int i;
    token = strtok(NULL, w_space);
    if (!strcasecmp(token, "on")) {
	Config.quickAbort.min = 10 << 10;	/* 10k */
	Config.quickAbort.pct = 64;	/* 50% */
	Config.quickAbort.max = 100 << 10;	/* 100k */
    } else if (!strcasecmp(token, "off")) {
	Config.quickAbort.min = -1;
	Config.quickAbort.pct = 0;
	Config.quickAbort.max = 0;
    } else {
	if (sscanf(token, "%d", &i) != 1)
	    self_destruct();
	Config.quickAbort.min = i * 1024;
	GetInteger(i);
	Config.quickAbort.pct = i * 128 / 100;	/* 128 is full scale */
	GetInteger(i);
	Config.quickAbort.max = i * 1024;
    }
}

static void
parseMinutesLine(int *iptr)
{
    char *token;
    int i;
    GetInteger(i);
    *iptr = i * 60;
}

static void
parseRequestSizeLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.maxRequestSize = i * 1024;
}

static void
parseMgrLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.adminEmail);
    Config.adminEmail = xstrdup(token);
}

static void
parseDirLine()
{
    char *token;

    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    wordlistAdd(&Config.cache_dirs, token);
}

#if USE_PROXY_AUTH
static void
parseProxyAuthLine()
{
    char *token;

    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.proxyAuthFile);
    safe_free(Config.proxyAuthIgnoreDomain);
    Config.proxyAuthFile = xstrdup(token);
    if ((token = strtok(NULL, w_space)))
	Config.proxyAuthIgnoreDomain = xstrdup(token);
}
#endif /* USE_PROXY_AUTH */

static void
parseHttpdAccelLine()
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
parseEffectiveUserLine()
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

static void
parseLogLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Log.log);
    Config.Log.log = xstrdup(token);
}

static void
parseAccessLogLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Log.access);
    Config.Log.access = xstrdup(token);
}

static void
parseStoreLogLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Log.store);
    Config.Log.store = xstrdup(token);
}

static void
parseFtpProgramLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Program.ftpget);
    Config.Program.ftpget = xstrdup(token);
}

static void
parseFtpOptionsLine()
{
    char *token;
    token = strtok(NULL, "");	/* Note "", don't separate these */
    if (token == NULL)
	self_destruct();
    safe_free(Config.Program.ftpget_opts);
    Config.Program.ftpget_opts = xstrdup(token);
}

static void
parseDnsProgramLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Program.dnsserver);
    Config.Program.dnsserver = xstrdup(token);
}

static void
parseRedirectProgramLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Program.redirect);
    Config.Program.redirect = xstrdup(token);
}

static void
parseOnOff(int *var)
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    if (!strcasecmp(token, "on") || !strcasecmp(token, "enable"))
	*var = 1;
    else
	*var = 0;
}

static void
parseWAISRelayLine()
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

static void
parseIPLine(ip_acl ** list)
{
    char *token;
    while ((token = strtok(NULL, w_space))) {
	addToIPACL(list, token, IP_DENY);
    }
}

static void
parseHierarchyStoplistLine()
{
    char *token;
    while ((token = strtok(NULL, w_space)))
	wordlistAdd(&Config.hierarchy_stoplist, token);
}

static void
parseAppendDomainLine()
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

static void
parseAddressLine(struct in_addr *addr)
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

static void
parseLocalDomainFile(char *fname)
{
    LOCAL_ARRAY(char, tmp_line, BUFSIZ);
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

static void
parseLocalDomainLine()
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

static void
parseInsideFirewallLine()
{
    char *token;
    while ((token = strtok(NULL, w_space))) {
	wordlistAdd(&Config.inside_firewall_list, token);
    }
}

static void
parseDnsTestnameLine()
{
    char *token;
    while ((token = strtok(NULL, w_space))) {
	wordlistAdd(&Config.dns_testname_list, token);
    }
}

static void
parseHttpPortLine()
{
    char *token;
    int i;
    GetInteger(i);
    if (i < 0)
	i = 0;
    Config.Port.http = (u_short) i;
}

static void
parseIcpPortLine()
{
    char *token;
    int i;
    GetInteger(i);
    if (i < 0)
	i = 0;
    Config.Port.icp = (u_short) i;
}

static void
parseDebugOptionsLine()
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

static void
parsePidFilenameLine()
{
    char *token;
    token = strtok(NULL, w_space);
    safe_free(Config.pidFilename);
    if (token == NULL)
	self_destruct();
    Config.pidFilename = xstrdup(token);
}

static void
parseVisibleHostnameLine()
{
    char *token;
    token = strtok(NULL, w_space);
    safe_free(Config.visibleHostname);
    if (token == NULL)
	self_destruct();
    Config.visibleHostname = xstrdup(token);
}

static void
parseFtpUserLine()
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.ftpUser);
    Config.ftpUser = xstrdup(token);
}

static void
parseCacheAnnounceLine()
{
    char *token;
    int i;
    GetInteger(i);
    Config.Announce.rate = i * 3600;	/* hours to seconds */
}

static void
parseAnnounceToLine()
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
parseSslProxyLine()
{
    char *token;
    char *t;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.sslProxy.host);
    Config.sslProxy.port = 0;
    if ((t = strchr(token, ':'))) {
	*t++ = '\0';
	Config.sslProxy.port = atoi(t);
    }
    Config.sslProxy.host = xstrdup(token);
}

static void
parseIntegerValue(int *iptr)
{
    char *token;
    int i;
    GetInteger(i);
    *iptr = i;
}

static void
parseErrHtmlLine()
{
    char *token;
    if ((token = strtok(NULL, "")))
	Config.errHtmlText = xstrdup(token);
}

int
parseConfigFile(char *file_name)
{
    FILE *fp = NULL;
    char *token = NULL;
    LOCAL_ARRAY(char, tmp_line, BUFSIZ);

    configFreeMemory();
    configSetFactoryDefaults();
    aclDestroyAcls();
    aclDestroyDenyInfoList(&DenyInfoList);
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

	if (!strcmp(token, "cache_host"))
	    parseCacheHostLine();

	else if (!strcmp(token, "cache_host_domain"))
	    parseHostDomainLine();
	else if (!strcmp(token, "cache_host_acl"))
	    parseHostAclLine();

	else if (!strcmp(token, "neighbor_timeout"))
	    parseIntegerValue(&Config.neighborTimeout);
	else if (!strcmp(token, "neighbour_timeout"))	/* alternate spelling */
	    parseIntegerValue(&Config.neighborTimeout);

	else if (!strcmp(token, "cache_dir"))
	    parseDirLine();

	else if (!strcmp(token, "cache_log"))
	    parseLogLine();

	else if (!strcmp(token, "cache_access_log"))
	    parseAccessLogLine();

	else if (!strcmp(token, "cache_store_log"))
	    parseStoreLogLine();

	else if (!strcmp(token, "logfile_rotate"))
	    parseIntegerValue(&Config.Log.rotateNumber);

	else if (!strcmp(token, "httpd_accel_with_proxy"))
	    parseOnOff(&Config.Accel.withProxy);

	else if (!strcmp(token, "httpd_accel"))
	    parseHttpdAccelLine();

	else if (!strcmp(token, "cache_effective_user"))
	    parseEffectiveUserLine();

	else if (!strcmp(token, "cache_swap_high"))
	    parseIntegerValue(&Config.Swap.highWaterMark);

	else if (!strcmp(token, "cache_swap_low"))
	    parseIntegerValue(&Config.Swap.lowWaterMark);

	else if (!strcmp(token, "cache_mem_high"))
	    parseIntegerValue(&Config.Mem.highWaterMark);

	else if (!strcmp(token, "cache_mem_low"))
	    parseIntegerValue(&Config.Mem.lowWaterMark);

	else if (!strcmp(token, "cache_hot_vm_factor"))
	    parseHotVmFactorLine();

	else if (!strcmp(token, "cache_mem"))
	    parseMemLine();

	else if (!strcmp(token, "cache_swap"))
	    parseSwapLine();

	else if (!strcmp(token, "cache_mgr"))
	    parseMgrLine();

	else if (!strcmp(token, "acl"))
	    aclParseAclLine();

	else if (!strcmp(token, "deny_info"))
	    aclParseDenyInfoLine(&DenyInfoList);

	else if (!strcmp(token, "http_access"))
	    aclParseAccessLine(&HTTPAccessList);

	else if (!strcmp(token, "icp_access"))
	    aclParseAccessLine(&ICPAccessList);

	else if (!strcmp(token, "hierarchy_stoplist"))
	    parseHierarchyStoplistLine();

	else if (!strcmp(token, "gopher"))
	    parseGopherLine();

	else if (!strcmp(token, "http"))
	    parseHttpLine();

	else if (!strcmp(token, "ftp"))
	    parseFtpLine();

	else if (!strcmp(token, "ttl_pattern"))
	    parseTTLPattern(0, 0);
	else if (!strcmp(token, "ttl_pattern/i"))
	    parseTTLPattern(1, 0);
	else if (!strcmp(token, "ttl_force_pattern"))
	    parseTTLPattern(0, 1);
	else if (!strcmp(token, "ttl_force_pattern/i"))
	    parseTTLPattern(1, 1);

	else if (!strcmp(token, "quick_abort"))
	    parseQuickAbort();

	else if (!strcmp(token, "negative_ttl"))
	    parseMinutesLine(&Config.negativeTtl);
	else if (!strcmp(token, "negative_dns_ttl"))
	    parseMinutesLine(&Config.negativeDnsTtl);
	else if (!strcmp(token, "positive_dns_ttl"))
	    parseMinutesLine(&Config.positiveDnsTtl);
	else if (!strcmp(token, "read_timeout"))
	    parseMinutesLine(&Config.readTimeout);
	else if (!strcmp(token, "clean_rate"))
	    parseMinutesLine(&Config.cleanRate);
	else if (!strcmp(token, "client_lifetime"))
	    parseMinutesLine(&Config.lifetimeDefault);
	else if (!strcmp(token, "expire_age"))
	    parseMinutesLine(&Config.expireAge);

	else if (!strcmp(token, "shutdown_lifetime"))
	    parseIntegerValue(&Config.lifetimeShutdown);

	else if (!strcmp(token, "request_size"))
	    parseRequestSizeLine();

	else if (!strcmp(token, "connect_timeout"))
	    parseIntegerValue(&Config.connectTimeout);

	else if (!strcmp(token, "cache_ftp_program"))
	    parseFtpProgramLine();

	else if (!strcmp(token, "cache_ftp_options"))
	    parseFtpOptionsLine();

	else if (!strcmp(token, "cache_dns_program"))
	    parseDnsProgramLine();

	else if (!strcmp(token, "dns_children"))
	    parseIntegerValue(&Config.dnsChildren);

	else if (!strcmp(token, "redirect_program"))
	    parseRedirectProgramLine();

	else if (!strcmp(token, "redirect_children"))
	    parseIntegerValue(&Config.redirectChildren);

#if USE_PROXY_AUTH
	else if (!strcmp(token, "proxy_auth"))
	    parseProxyAuthLine();
#endif /* USE_PROXY_AUTH */

	else if (!strcmp(token, "source_ping"))
	    parseOnOff(&Config.sourcePing);

	else if (!strcmp(token, "emulate_httpd_log"))
	    parseOnOff(&Config.commonLogFormat);

#if LOG_FULL_HEADERS
	else if (!strcmp(token, "log_mime_hdrs"))
	    parseOnOff(&Config.logMimeHdrs);

#endif /* LOG_FULL_HEADERS */
	else if (!strcmp(token, "ident_lookup"))
	    parseOnOff(&Config.identLookup);

	else if (!strcmp(token, "append_domain"))
	    parseAppendDomainLine();

	else if (!strcmp(token, "wais_relay"))
	    parseWAISRelayLine();

	else if (!strcmp(token, "local_ip"))
	    parseIPLine(&Config.local_ip_list);

	else if (!strcmp(token, "firewall_ip"))
	    parseIPLine(&Config.firewall_ip_list);

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

	else if (!strcmp(token, "client_netmask"))
	    parseAddressLine(&Config.Addrs.client_netmask);

	else if (!strcmp(token, "tcp_recv_bufsize"))
	    parseIntegerValue(&Config.tcpRcvBufsz);

	else if (!strcmp(token, "log_fqdn"))
	    parseOnOff(&Config.Log.log_fqdn);

	else if (!strcmp(token, "bind_address"))
	    parseAddressLine(&Config.Addrs.tcp_incoming);

	else if (!strcmp(token, "outbound_address"))
	    parseAddressLine(&Config.Addrs.tcp_outgoing);

	else if (!strcmp(token, "http_port") || !strcmp(token, "ascii_port"))
	    parseHttpPortLine();

	else if (!strcmp(token, "icp_port") || !strcmp(token, "udp_port"))
	    parseIcpPortLine();

	else if (!strcmp(token, "inside_firewall"))
	    parseInsideFirewallLine();

	else if (!strcmp(token, "dns_testnames"))
	    parseDnsTestnameLine();

	else if (!strcmp(token, "single_parent_bypass"))
	    parseOnOff(&Config.singleParentBypass);

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

	else if (!strcmp(token, "ssl_proxy"))
	    parseSslProxyLine();

	else if (!strcmp(token, "err_html_text"))
	    parseErrHtmlLine();

	else if (!strcmp(token, "ipcache_size"))
	    parseIntegerValue(&Config.ipcache.size);
	else if (!strcmp(token, "ipcache_low"))
	    parseIntegerValue(&Config.ipcache.low);
	else if (!strcmp(token, "ipcache_high"))
	    parseIntegerValue(&Config.ipcache.high);

	else {
	    debug(3, 0, "parseConfigFile: line %d unrecognized: '%s'\n",
		config_lineno,
		config_input_line);
	}
    }

    /* Sanity checks */
    if (Config.lifetimeDefault < Config.readTimeout) {
	printf("WARNING: client_lifetime (%d seconds) is less than read_timeout (%d seconds).\n",
	    Config.lifetimeDefault, Config.readTimeout);
	printf("         This may cause serious problems with your cache!!!\n");
	printf("         Change your configuration file.\n");
	fflush(stdout);		/* print message */
    }
    if (Config.Swap.maxSize < (Config.Mem.maxSize >> 10)) {
	printf("WARNING: cache_swap (%d kbytes) is less than cache_mem (%d bytes).\n", Config.Swap.maxSize, Config.Mem.maxSize);
	printf("         This will cause serious problems with your cache!!!\n");
	printf("         Change your configuration file.\n");
	fflush(stdout);		/* print message */
    }
    if (Config.cleanRate < 1)
	Config.cleanRate = 86400 * 365;		/* one year */
    if (Config.Announce.rate < 1)
	Config.Announce.rate = 86400 * 365;	/* one year */
    if (Config.dnsChildren < 1) {
	printf("WARNING: dns_children was set to a bad value: %d\n",
	    Config.dnsChildren);
	Config.dnsChildren = DefaultDnsChildren;
	printf("Setting it to the default (%d).\n", DefaultDnsChildren);
    } else if (Config.dnsChildren > DefaultDnsChildrenMax) {
	printf("WARNING: dns_children was set to a bad value: %d\n",
	    Config.dnsChildren);
	printf("Setting it to the maximum (%d).\n", DefaultDnsChildrenMax);
	Config.dnsChildren = DefaultDnsChildrenMax;
    }
    if (Config.redirectChildren < 1) {
	printf("WARNING: redirect_children was set to a bad value: %d\n",
	    Config.redirectChildren);
	Config.redirectChildren = DefaultRedirectChildren;
	printf("Setting it to the default (%d).\n", DefaultRedirectChildren);
    } else if (Config.redirectChildren > DefaultRedirectChildrenMax) {
	printf("WARNING: redirect_children was set to a bad value: %d\n",
	    Config.redirectChildren);
	printf("Setting it to the maximum (%d).\n", DefaultRedirectChildrenMax);
	Config.redirectChildren = DefaultRedirectChildrenMax;
    }
    fclose(fp);

    configDoConfigure();
    return 0;
}

u_short
setHttpPortNum(u_short port)
{
    return (Config.Port.http = port);
}
u_short
setIcpPortNum(u_short port)
{
    return (Config.Port.icp = port);
}

static char *
safe_xstrdup(char *p)
{
    return p ? xstrdup(p) : p;
}

static void
configFreeMemory()
{
    safe_free(Config.Wais.relayHost);
    safe_free(Config.Log.log);
    safe_free(Config.Log.access);
    safe_free(Config.Log.store);
    safe_free(Config.adminEmail);
    safe_free(Config.effectiveUser);
    safe_free(Config.effectiveGroup);
    safe_free(Config.Program.ftpget);
    safe_free(Config.Program.ftpget_opts);
    safe_free(Config.Program.dnsserver);
    safe_free(Config.Program.redirect);
    safe_free(Config.Accel.host);
    safe_free(Config.Accel.prefix);
    safe_free(Config.appendDomain);
    safe_free(Config.debugOptions);
    safe_free(Config.pidFilename);
    safe_free(Config.visibleHostname);
    safe_free(Config.ftpUser);
#if USE_PROXY_AUTH
    safe_free(Config.proxyAuthFile);
    safe_free(Config.proxyAuthIgnoreDomain);
#endif /* USE_PROXY_AUTH */
    safe_free(Config.Announce.host);
    safe_free(Config.Announce.file);
    safe_free(Config.errHtmlText);
    wordlistDestroy(&Config.cache_dirs);
    wordlistDestroy(&Config.hierarchy_stoplist);
    wordlistDestroy(&Config.local_domain_list);
    wordlistDestroy(&Config.inside_firewall_list);
    wordlistDestroy(&Config.dns_testname_list);
    safe_free(Config.sslProxy.host);
    ttlFreeList();
}


static void
configSetFactoryDefaults()
{
    Config.Mem.maxSize = DefaultMemMaxSize;
    Config.Mem.highWaterMark = DefaultMemHighWaterMark;
    Config.Mem.lowWaterMark = DefaultMemLowWaterMark;
    Config.Swap.maxSize = DefaultSwapMaxSize;
    Config.Swap.highWaterMark = DefaultSwapHighWaterMark;
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

    Config.expireAge = DefaultExpireAge;
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
    Config.redirectChildren = DefaultRedirectChildren;
    Config.hotVmFactor = DefaultHotVmFactor;
    Config.sourcePing = DefaultSourcePing;
    Config.quickAbort.min = DefaultQuickAbortMin;
    Config.quickAbort.pct = DefaultQuickAbortPct;
    Config.quickAbort.max = DefaultQuickAbortMax;
    Config.commonLogFormat = DefaultCommonLogFormat;
#if LOG_FULL_HEADERS
    Config.logMimeHdrs = DefaultLogMimeHdrs;
#endif /* LOG_FULL_HEADERS */
    Config.debugOptions = safe_xstrdup(DefaultDebugOptions);
    Config.neighborTimeout = DefaultNeighborTimeout;
    Config.stallDelay = DefaultStallDelay;
    Config.singleParentBypass = DefaultSingleParentBypass;
    Config.adminEmail = safe_xstrdup(DefaultAdminEmail);
    Config.effectiveUser = safe_xstrdup(DefaultEffectiveUser);
    Config.effectiveGroup = safe_xstrdup(DefaultEffectiveGroup);
    Config.appendDomain = safe_xstrdup(DefaultAppendDomain);
    Config.errHtmlText = safe_xstrdup(DefaultErrHtmlText);

    Config.Port.http = DefaultHttpPortNum;
    Config.Port.icp = DefaultIcpPortNum;
    Config.Log.log = safe_xstrdup(DefaultCacheLogFile);
    Config.Log.access = safe_xstrdup(DefaultAccessLogFile);
    Config.Log.store = safe_xstrdup(DefaultStoreLogFile);
    Config.Log.rotateNumber = DefaultLogRotateNumber;
    Config.Program.ftpget = safe_xstrdup(DefaultFtpgetProgram);
    Config.Program.ftpget_opts = safe_xstrdup(DefaultFtpgetOptions);
    Config.Program.dnsserver = safe_xstrdup(DefaultDnsserverProgram);
    Config.Program.redirect = safe_xstrdup(DefaultRedirectProgram);
    Config.Accel.host = safe_xstrdup(DefaultAccelHost);
    Config.Accel.prefix = safe_xstrdup(DefaultAccelPrefix);
    Config.Accel.port = DefaultAccelPort;
    Config.Accel.withProxy = DefaultAccelWithProxy;
    Config.pidFilename = safe_xstrdup(DefaultPidFilename);
    Config.visibleHostname = safe_xstrdup(DefaultVisibleHostname);
#if USE_PROXY_AUTH
    Config.proxyAuthFile = safe_xstrdup(DefaultProxyAuthFile);
    Config.proxyAuthIgnoreDomain = safe_xstrdup(DefaultProxyAuthIgnoreDomain);
#endif /* USE_PROXY_AUTH */
    Config.ftpUser = safe_xstrdup(DefaultFtpUser);
    Config.Announce.host = safe_xstrdup(DefaultAnnounceHost);
    Config.Announce.port = DefaultAnnouncePort;
    Config.Announce.file = safe_xstrdup(DefaultAnnounceFile);
    Config.Announce.rate = DefaultAnnounceRate;
    Config.tcpRcvBufsz = DefaultTcpRcvBufsz;
    Config.Addrs.tcp_outgoing.s_addr = DefaultTcpOutgoingAddr;
    Config.Addrs.tcp_incoming.s_addr = DefaultTcpIncomingAddr;
    Config.Addrs.udp_outgoing.s_addr = DefaultUdpOutgoingAddr;
    Config.Addrs.udp_incoming.s_addr = DefaultUdpIncomingAddr;
    Config.Addrs.client_netmask.s_addr = DefaultClientNetmask;
    Config.sslProxy.port = DefaultSslProxyPort;
    Config.sslProxy.host = safe_xstrdup(DefaultSslProxyHost);
    Config.ipcache.size = DefaultIpcacheSize;
    Config.ipcache.low = DefaultIpcacheLow;
    Config.ipcache.high = DefaultIpcacheHigh;
}

static void
configDoConfigure()
{
    httpd_accel_mode = Config.Accel.prefix ? 1 : 0;
    sprintf(ForwardedBy, "Forwarded: by http://%s:%d/",
	getMyHostname(), Config.Port.http);
    if (Config.errHtmlText == NULL)
	Config.errHtmlText = xstrdup("");
    storeConfigure();
}
