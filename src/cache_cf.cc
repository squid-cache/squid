/*
 * $Id: cache_cf.cc,v 1.182 1997/04/30 03:11:58 wessels Exp $
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

#define DefaultMemMaxSize 	(8 << 20)	/* 8 MB */
#define DefaultMemHighWaterMark 90	/* 90% */
#define DefaultMemLowWaterMark  75	/* 75% */
#define DefaultSwapMaxSize	0
#define DefaultSwapHighWaterMark 95	/* 95% */
#define DefaultSwapLowWaterMark  90	/* 90% */
#define DefaultNetdbHigh	1000	/* counts, not percents */
#define DefaultNetdbLow		 900
#define DefaultNetdbPeriod       300	/* 5 minutes */

#define DefaultWaisRelayHost	(char *)NULL
#define DefaultWaisRelayPort	0

#define DefaultReferenceAge	(86400*365)	/* 1 year */
#define DefaultNegativeTtl	(5 * 60)	/* 5 min */
#define DefaultNegativeDnsTtl	(2 * 60)	/* 2 min */
#define DefaultPositiveDnsTtl	(360 * 60)	/* 6 hours */
#define DefaultReadTimeout      (15 * 60)       /* 15 min */
#define DefaultConnectTimeout   120     /* 2 min */
#define DefaultDeferTimeout     3600    /* 1 hour */
#define DefaultClientLifetime   86400   /* 1 day */
#define DefaultShutdownLifetime 30      /* 30 seconds */
#define DefaultCleanRate        -1      /* disabled */
#define DefaultDnsChildren	5	/* 5 processes */
#define DefaultOptionsResDefnames 0	/* default off */
#define DefaultOptionsAnonymizer  0	/* default off */
#define DefaultRedirectChildren	5	/* 5 processes */
#define DefaultMaxRequestSize	(100 << 10)	/* 100Kb */

#define DefaultHttpPortNum	CACHE_HTTP_PORT
#define DefaultIcpPortNum	CACHE_ICP_PORT

#define DefaultLogLogFqdn      0	/* default off */
#define DefaultCacheLogFile	DEFAULT_CACHE_LOG
#define DefaultAccessLogFile	DEFAULT_ACCESS_LOG
#define DefaultUseragentLogFile	(char *)NULL	/* default NONE */
#define DefaultStoreLogFile	DEFAULT_STORE_LOG
#define DefaultSwapLogFile	(char *)NULL	/* default swappath(0) */
#if USE_PROXY_AUTH
#define DefaultProxyAuthFile    (char *)NULL	/* default NONE */
#endif /* USE_PROXY_AUTH */
#define DefaultLogRotateNumber  10
#define DefaultAdminEmail	"webmaster"
#define DefaultFtpgetProgram	DEFAULT_FTPGET
#define DefaultFtpgetOptions	""
#define DefaultDnsserverProgram DEFAULT_DNSSERVER
#define DefaultPingerProgram    DEFAULT_PINGER
#define DefaultUnlinkdProgram   DEFAULT_UNLINKD
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
#define DefaultPidFilename      DEFAULT_PID_FILE
#define DefaultVisibleHostname  (char *)NULL	/* default NONE */
#define DefaultFtpUser		"squid@"	/* Default without domain */
#define DefaultAnnounceHost	"sd.cache.nlanr.net"
#define DefaultAnnouncePort	3131
#define DefaultAnnounceFile	(char *)NULL	/* default NONE */
#define DefaultAnnounceRate	0	/* Default off */
#define DefaultTcpRcvBufsz	0	/* use system default */
#define DefaultUdpMaxHitObjsz	SQUID_UDP_SO_SNDBUF	/* from configure */
#define DefaultTcpIncomingAddr	INADDR_ANY
#define DefaultTcpOutgoingAddr	no_addr.s_addr
#define DefaultUdpIncomingAddr	INADDR_ANY
#define DefaultUdpOutgoingAddr	no_addr.s_addr
#define DefaultClientNetmask    0xFFFFFFFFul
#define DefaultPassProxy	NULL
#define DefaultSslProxy		NULL
#define DefaultIpcacheSize	1024
#define DefaultIpcacheLow	90
#define DefaultIpcacheHigh	95
#define DefaultMinDirectHops	4
#define DefaultMaxObjectSize	(4<<20)		/* 4Mb */
#define DefaultAvgObjectSize	20	/* 20k */
#define DefaultObjectsPerBucket	50

#define DefaultOptionsLogUdp	1	/* on */
#define DefaultOptionsEnablePurge 0	/* default off */
#define DefaultOptionsClientDb	1	/* default on */
#define DefaultOptionsQueryIcmp	0	/* default off */


int httpd_accel_mode = 0;	/* for fast access */
const char *DefaultSwapDir = DEFAULT_SWAP_DIR;
const char *DefaultConfigFile = DEFAULT_CONFIG_FILE;
char *ConfigFile = NULL;	/* the whole thing */
const char *cfg_filename = NULL;	/* just the last part */

static const char *const w_space = " \t\n\r";
static const char *const list_sep = ", \t\n\r";
char config_input_line[BUFSIZ];
int config_lineno = 0;

static char fatal_str[BUFSIZ];
static char *safe_xstrdup _PARAMS((const char *p));
static void parseOnOff _PARAMS((int *));
static void parseIntegerValue _PARAMS((int *));
static void parseString _PARAMS((char **));
static void self_destruct _PARAMS((void));
static void wordlistAdd _PARAMS((wordlist **, const char *));

static void configDoConfigure _PARAMS((void));
static void configSetFactoryDefaults _PARAMS((void));
static void parseAddressLine _PARAMS((struct in_addr *));
static void parseAnnounceToLine _PARAMS((void));
static void parseAppendDomainLine _PARAMS((void));
static void parseCacheAnnounceLine _PARAMS((void));
static void parseCacheHostLine _PARAMS((void));
static void parseDebugOptionsLine _PARAMS((void));
static void parseEffectiveUserLine _PARAMS((void));
static void parseErrHtmlLine _PARAMS((void));
static void parseFtpOptionsLine _PARAMS((void));
static void parseFtpUserLine _PARAMS((void));
static void parseWordlist _PARAMS((wordlist **));
static void parseHostAclLine _PARAMS((void));
static void parseHostDomainLine _PARAMS((void));
static void parseHostDomainTypeLine _PARAMS((void));
static void parseHttpPortLine _PARAMS((void));
static void parseHttpdAccelLine _PARAMS((void));
static void parseIcpPortLine _PARAMS((void));
static void parseMcastGroupLine _PARAMS((void));
static void parseMemLine _PARAMS((void));
static void parseMgrLine _PARAMS((void));
static void parseKilobytes _PARAMS((int *));
static void parseRefreshPattern _PARAMS((int icase));
static void parseVisibleHostnameLine _PARAMS((void));
static void parseWAISRelayLine _PARAMS((void));
static void parseMinutesLine _PARAMS((int *));
static void parseCachemgrPasswd _PARAMS((void));
static void parsePathname _PARAMS((char **, int fatal));
static void parseProxyLine _PARAMS((peer **));
static void parseHttpAnonymizer _PARAMS((int *));
static int parseTimeUnits _PARAMS((const char *unit));
static void parseTimeLine _PARAMS((int *iptr, const char *units));

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
    wordlist *n = NULL;

    for (w = *list; w; w = n) {
	n = w->next;
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
parseCacheHostLine(void)
{
    char *type = NULL;
    char *hostname = NULL;
    char *token = NULL;
    u_short http_port = CACHE_HTTP_PORT;
    u_short icp_port = CACHE_ICP_PORT;
    int options = 0;
    int weight = 1;
    int mcast_ttl = 0;
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
	} else if (!strcasecmp(token, "multicast-responder")) {
	    options |= NEIGHBOR_MCAST_RESPONDER;
	} else if (!strncasecmp(token, "weight=", 7)) {
	    weight = atoi(token + 7);
	} else if (!strncasecmp(token, "ttl=", 4)) {
	    mcast_ttl = atoi(token + 4);
	    if (mcast_ttl < 0)
		mcast_ttl = 0;
	    if (mcast_ttl > 128)
		mcast_ttl = 128;
	} else if (!strncasecmp(token, "default", 7)) {
	    options |= NEIGHBOR_DEFAULT_PARENT;
	} else if (!strncasecmp(token, "round-robin", 11)) {
	    options |= NEIGHBOR_ROUNDROBIN;
	} else {
	    debug(3, 0, "parseCacheHostLine: token='%s'\n", token);
	    self_destruct();
	}
    }
    if (weight < 1)
	weight = 1;
    neighborAdd(hostname, type, http_port, icp_port, options,
	weight, mcast_ttl);
}


static void
parseHostDomainLine(void)
{
    char *host = NULL;
    char *domain = NULL;
    if (!(host = strtok(NULL, w_space)))
	self_destruct();
    while ((domain = strtok(NULL, list_sep)))
	neighborAddDomainPing(host, domain);
}

static void
parseHostDomainTypeLine(void)
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
parseHostAclLine(void)
{
    char *host = NULL;
    char *aclname = NULL;
    if (!(host = strtok(NULL, w_space)))
	self_destruct();
    while ((aclname = strtok(NULL, list_sep)))
	neighborAddAcl(host, aclname);
}

static void
parseMemLine(void)
{
    char *token;
    int i;
    GetInteger(i);
    Config.Mem.maxSize = i << 20;
}


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

static void
parseQuickAbort(void)
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
parseKilobytes(int *val)
{
    char *token;
    int i;
    GetInteger(i);
    *val = i * 1024;
}

static void
parseMgrLine(void)
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.adminEmail);
    Config.adminEmail = xstrdup(token);
}

#if USE_PROXY_AUTH
static void
parseProxyAuthLine(void)
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.proxyAuth.File);
    aclDestroyRegexList(Config.proxyAuth.IgnoreDomains);
    Config.proxyAuth.IgnoreDomains = NULL;
    Config.proxyAuth.File = xstrdup(token);
    aclParseRegexList(&Config.proxyAuth.IgnoreDomains, 1);
}
#endif /* USE_PROXY_AUTH */

static void
parseHttpdAccelLine(void)
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
parseEffectiveUserLine(void)
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
parsePathname(char **path, int fatal)
{
    char *token;
    struct stat sb;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(*path);
    *path = xstrdup(token);
    if (fatal && stat(token, &sb) < 0) {
	debug(50, 1, "parsePathname: %s: %s\n", token, xstrerror());
	self_destruct();
    }
}

static void
parseFtpOptionsLine(void)
{
    char *token;
    token = strtok(NULL, null_string);
    if (token == NULL)
	self_destruct();
    safe_free(Config.Program.ftpget_opts);
    Config.Program.ftpget_opts = xstrdup(token);
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
parseWAISRelayLine(void)
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
}

static void
parseWordlist(wordlist ** list)
{
    char *token;
    while ((token = strtok(NULL, w_space)))
	wordlistAdd(list, token);
}

static void
parseAppendDomainLine(void)
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
    const struct hostent *hp;
    token = strtok(NULL, w_space);
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
parseMcastGroupLine(void)
{
    char *token = NULL;
    while ((token = strtok(NULL, w_space)))
	wordlistAdd(&Config.mcast_group_list, token);
}

static void
parseHttpPortLine(void)
{
    char *token;
    int i;
    GetInteger(i);
    if (i < 0)
	i = 0;
    Config.Port.http = (u_short) i;
}

static void
parseIcpPortLine(void)
{
    char *token;
    int i;
    GetInteger(i);
    if (i < 0)
	i = 0;
    Config.Port.icp = (u_short) i;
}

static void
parseDebugOptionsLine(void)
{
    char *token;
    token = strtok(NULL, null_string);
    safe_free(Config.debugOptions);
    if (token == NULL) {
	Config.debugOptions = NULL;
	return;
    }
    Config.debugOptions = xstrdup(token);
}

static void
parseVisibleHostnameLine(void)
{
    char *token;
    token = strtok(NULL, w_space);
    safe_free(Config.visibleHostname);
    if (token == NULL)
	self_destruct();
    Config.visibleHostname = xstrdup(token);
}

static void
parseFtpUserLine(void)
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    safe_free(Config.ftpUser);
    Config.ftpUser = xstrdup(token);
}

static void
parseCacheAnnounceLine(void)
{
    char *token;
    int i;
    GetInteger(i);
    Config.Announce.rate = i * 3600;	/* hours to seconds */
    if (Config.Announce.rate > 0)
	Config.Announce.on = 1;
}

static void
parseAnnounceToLine(void)
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
parseVizHackLine(void)
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
parseProxyLine(peer ** E)
{
    char *token;
    char *t;
    peer *e;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    if (*E) {
	peerDestroy(*E);
	*E = NULL;
    }
    e = xcalloc(1, sizeof(peer));
    if ((t = strchr(token, ':'))) {
	*t++ = '\0';
	e->http_port = atoi(t);
    }
    e->host = xstrdup(token);
    *E = e;
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
parseString(char **sptr)
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    *sptr = xstrdup(token);
}

static void
parseErrHtmlLine(void)
{
    char *token;
    if ((token = strtok(NULL, null_string)))
	Config.errHtmlText = xstrdup(token);
}

static void
parseCachemgrPasswd(void)
{
    char *passwd = NULL;
    wordlist *actions = NULL;
    parseString(&passwd);
    parseWordlist(&actions);
    objcachePasswdAdd(&Config.passwd_list, passwd, actions);
    wordlistDestroy(&actions);
}

static void
parseHttpAnonymizer(int *iptr)
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == NULL)
	self_destruct();
    if (!strcasecmp(token, "off"))
	*iptr = ANONYMIZER_NONE;
    else if (!strcasecmp(token, "paranoid"))
	*iptr = ANONYMIZER_PARANOID;
    else
	*iptr = ANONYMIZER_STANDARD;
}

static void
parseCacheDir(void)
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
    storeAddSwapDisk(dir, size, l1, l2, readonly);
}

int
parseConfigFile(const char *file_name)
{
    FILE *fp = NULL;
    char *token = NULL;
    LOCAL_ARRAY(char, tmp_line, BUFSIZ);

    configFreeMemory();
    configSetFactoryDefaults();
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
	else if (!strcmp(token, "neighbor_type_domain"))
	    parseHostDomainTypeLine();

	else if (!strcmp(token, "neighbor_timeout"))
	    parseIntegerValue(&Config.neighborTimeout);
	else if (!strcmp(token, "neighbour_timeout"))	/* alternate spelling */
	    parseIntegerValue(&Config.neighborTimeout);

	else if (!strcmp(token, "cache_dir"))
	    parseCacheDir();

	else if (!strcmp(token, "cache_log"))
	    parsePathname(&Config.Log.log, 0);

	else if (!strcmp(token, "cache_access_log"))
	    parsePathname(&Config.Log.access, 0);

	else if (!strcmp(token, "cache_store_log"))
	    parsePathname(&Config.Log.store, 0);

	else if (!strcmp(token, "cache_swap_log"))
	    parsePathname(&Config.Log.swap, 0);

#if USE_USERAGENT_LOG
	else if (!strcmp(token, "useragent_log"))
	    parsePathname(&Config.Log.useragent, 0);
#endif

	else if (!strcmp(token, "logfile_rotate"))
	    parseIntegerValue(&Config.Log.rotateNumber);

	else if (!strcmp(token, "httpd_accel_with_proxy"))
	    parseOnOff(&Config.Accel.withProxy);

	else if (!strcmp(token, "httpd_accel_uses_host_header"))
	    parseOnOff(&opt_accel_uses_host);

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

	else if (!strcmp(token, "cache_mem"))
	    parseMemLine();

	else if (!strcmp(token, "cache_mgr"))
	    parseMgrLine();

	else if (!strcmp(token, "acl"))
	    aclParseAclLine();

	else if (!strcmp(token, "deny_info"))
	    aclParseDenyInfoLine(&Config.denyInfoList);

	else if (!strcmp(token, "http_access"))
	    aclParseAccessLine(&Config.accessList.HTTP);
	else if (!strcmp(token, "icp_access"))
	    aclParseAccessLine(&Config.accessList.ICP);
	else if (!strcmp(token, "miss_access"))
	    aclParseAccessLine(&Config.accessList.MISS);
	else if (!strcmp(token, "never_direct"))
	    aclParseAccessLine(&Config.accessList.NeverDirect);
	else if (!strcmp(token, "always_direct"))
	    aclParseAccessLine(&Config.accessList.AlwaysDirect);

	else if (!strcmp(token, "hierarchy_stoplist"))
	    parseWordlist(&Config.hierarchy_stoplist);

	else if (!strcmp(token, "cache_stoplist"))
	    parseWordlist(&Config.cache_stoplist);
	else if (!strcmp(token, "cache_stoplist_pattern"))
	    aclParseRegexList(&Config.cache_stop_relist, 0);
	else if (!strcmp(token, "cache_stoplist_pattern/i"))
	    aclParseRegexList(&Config.cache_stop_relist, 1);

	else if (!strcmp(token, "refresh_pattern"))
	    parseRefreshPattern(0);
	else if (!strcmp(token, "refresh_pattern/i"))
	    parseRefreshPattern(1);

	else if (!strcmp(token, "quick_abort"))
	    parseQuickAbort();

	else if (!strcmp(token, "negative_ttl"))
	    parseMinutesLine(&Config.negativeTtl);
	else if (!strcmp(token, "negative_dns_ttl"))
	    parseMinutesLine(&Config.negativeDnsTtl);
	else if (!strcmp(token, "positive_dns_ttl"))
	    parseMinutesLine(&Config.positiveDnsTtl);
        else if (!strcmp(token, "read_timeout"))
            parseMinutesLine(&Config.Timeout.read);
        else if (!strcmp(token, "connect_timeout"))
            parseIntegerValue(&Config.Timeout.connect);
        else if (!strcmp(token, "defer_timeout"))
            parseIntegerValue(&Config.Timeout.defer);
        else if (!strcmp(token, "client_lifetime"))
            parseIntegerValue(&Config.Timeout.lifetime);
        else if (!strcmp(token, "shutdown_lifetime"))
            parseIntegerValue(&Config.shutdownLifetime);
	else if (!strcmp(token, "clean_rate"))
	    parseMinutesLine(&Config.cleanRate);
	else if (!strcmp(token, "reference_age"))
	    parseTimeLine(&Config.referenceAge, "minutes");

	else if (!strcmp(token, "request_size"))
	    parseKilobytes(&Config.maxRequestSize);

	else if (!strcmp(token, "cache_ftp_program"))
	    parsePathname(&Config.Program.ftpget, 1);
	else if (!strcmp(token, "ftpget_program"))
	    parsePathname(&Config.Program.ftpget, 1);

	else if (!strcmp(token, "cache_ftp_options"))
	    parseFtpOptionsLine();
	else if (!strcmp(token, "ftpget_options"))
	    parseFtpOptionsLine();

	else if (!strcmp(token, "cache_dns_program"))
	    parsePathname(&Config.Program.dnsserver, 1);

	else if (!strcmp(token, "dns_children"))
	    parseIntegerValue(&Config.dnsChildren);
	else if (!strcmp(token, "dns_defnames"))
	    parseOnOff(&Config.Options.res_defnames);

	else if (!strcmp(token, "redirect_program"))
	    parsePathname(&Config.Program.redirect, 1);

	else if (!strcmp(token, "redirect_children"))
	    parseIntegerValue(&Config.redirectChildren);

	else if (!strcmp(token, "pinger_program"))
	    parsePathname(&Config.Program.pinger, 1);

	else if (!strcmp(token, "unlinkd_program"))
	    parsePathname(&Config.Program.unlinkd, 1);

#if USE_PROXY_AUTH
	else if (!strcmp(token, "proxy_auth"))
	    parseProxyAuthLine();
	else if (!strcmp(token, "proxy_auth_ignore"))
	    aclParseRegexList(&Config.proxyAuth.IgnoreDomains, 1);
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

	else if (!strcmp(token, "mcast_groups"))
	    parseMcastGroupLine();

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

	else if (!strcmp(token, "dns_testnames"))
	    parseWordlist(&Config.dns_testname_list);

	else if (!strcmp(token, "single_parent_bypass"))
	    parseOnOff(&Config.singleParentBypass);

	else if (!strcmp(token, "debug_options"))
	    parseDebugOptionsLine();

	else if (!strcmp(token, "pid_filename"))
	    parsePathname(&Config.pidFilename, 0);

	else if (!strcmp(token, "visible_hostname"))
	    parseVisibleHostnameLine();

	else if (!strcmp(token, "ftp_user"))
	    parseFtpUserLine();

	else if (!strcmp(token, "cache_announce"))
	    parseCacheAnnounceLine();

	else if (!strcmp(token, "announce_to"))
	    parseAnnounceToLine();

	else if (!strcmp(token, "ssl_proxy"))
	    parseProxyLine(&Config.sslProxy);
	else if (!strcmp(token, "passthrough_proxy"))
	    parseProxyLine(&Config.passProxy);

	else if (!strcmp(token, "err_html_text"))
	    parseErrHtmlLine();

	else if (!strcmp(token, "ipcache_size"))
	    parseIntegerValue(&Config.ipcache.size);
	else if (!strcmp(token, "ipcache_low"))
	    parseIntegerValue(&Config.ipcache.low);
	else if (!strcmp(token, "ipcache_high"))
	    parseIntegerValue(&Config.ipcache.high);

	else if (!strcmp(token, "memory_pools"))
	    parseOnOff(&opt_mem_pools);
	else if (!strcmp(token, "udp_hit_obj"))
	    parseOnOff(&opt_udp_hit_obj);
	else if (!strcmp(token, "udp_hit_obj_size"))
	    parseIntegerValue(&Config.udpMaxHitObjsz);
	else if (!strcmp(token, "forwarded_for"))
	    parseOnOff(&opt_forwarded_for);
	else if (!strcmp(token, "log_icp_queries"))
	    parseOnOff(&Config.Options.log_udp);
	else if (!strcmp(token, "http_anonymizer"))
	    parseHttpAnonymizer(&Config.Options.anonymizer);
	else if (!strcmp(token, "client_db"))
	    parseOnOff(&Config.Options.client_db);
	else if (!strcmp(token, "query_icmp"))
	    parseOnOff(&Config.Options.query_icmp);

	else if (!strcmp(token, "minimum_direct_hops"))
	    parseIntegerValue(&Config.minDirectHops);

	else if (!strcmp(token, "cachemgr_passwd"))
	    parseCachemgrPasswd();

	else if (!strcmp(token, "store_objects_per_bucket"))
	    parseIntegerValue(&Config.Store.objectsPerBucket);
	else if (!strcmp(token, "store_avg_object_size"))
	    parseIntegerValue(&Config.Store.avgObjectSize);
	else if (!strcmp(token, "maximum_object_size"))
	    parseKilobytes(&Config.Store.maxObjectSize);

	else if (!strcmp(token, "viz_hack_addr"))
	    parseVizHackLine();

	else if (!strcmp(token, "netdb_high"))
	    parseIntegerValue(&Config.Netdb.high);
	else if (!strcmp(token, "netdb_low"))
	    parseIntegerValue(&Config.Netdb.low);
	else if (!strcmp(token, "netdb_ping_period"))
	    parseTimeLine(&Config.Netdb.period, "seconds");

	/* If unknown, treat as a comment line */
	else {
	    debug(3, 0, "parseConfigFile: line %d unrecognized: '%s'\n",
		config_lineno,
		config_input_line);
	}
    }

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
    return 0;
}

static char *
safe_xstrdup(const char *p)
{
    return p ? xstrdup(p) : NULL;
}

void
configFreeMemory(void)
{
    safe_free(Config.Wais.relayHost);
    safe_free(Config.Log.log);
    safe_free(Config.Log.access);
    safe_free(Config.Log.store);
    safe_free(Config.Log.swap);
    safe_free(Config.adminEmail);
    safe_free(Config.effectiveUser);
    safe_free(Config.effectiveGroup);
    safe_free(Config.Program.ftpget);
    safe_free(Config.Program.ftpget_opts);
    safe_free(Config.Program.dnsserver);
    safe_free(Config.Program.redirect);
    safe_free(Config.Program.unlinkd);
    safe_free(Config.Program.pinger);
    safe_free(Config.Accel.host);
    safe_free(Config.Accel.prefix);
    safe_free(Config.appendDomain);
    safe_free(Config.debugOptions);
    safe_free(Config.pidFilename);
    safe_free(Config.visibleHostname);
    safe_free(Config.ftpUser);
#if USE_PROXY_AUTH
    safe_free(Config.proxyAuth.File);
    aclDestroyRegexList(Config.proxyAuth.IgnoreDomains);
    Config.proxyAuth.IgnoreDomains = NULL;
#endif /* USE_PROXY_AUTH */
    safe_free(Config.Announce.host);
    safe_free(Config.Announce.file);
    safe_free(Config.errHtmlText);
    peerDestroy(Config.sslProxy);
    peerDestroy(Config.passProxy);
    wordlistDestroy(&Config.hierarchy_stoplist);
    wordlistDestroy(&Config.mcast_group_list);
    wordlistDestroy(&Config.dns_testname_list);
    wordlistDestroy(&Config.cache_stoplist);
    objcachePasswdDestroy(&Config.passwd_list);
    refreshFreeMemory();
}


static void
configSetFactoryDefaults(void)
{
    memset(&Config, '\0', sizeof(Config));
    Config.Mem.maxSize = DefaultMemMaxSize;
    Config.Mem.highWaterMark = DefaultMemHighWaterMark;
    Config.Mem.lowWaterMark = DefaultMemLowWaterMark;
    Config.Swap.maxSize = DefaultSwapMaxSize;
    Config.Swap.highWaterMark = DefaultSwapHighWaterMark;
    Config.Swap.lowWaterMark = DefaultSwapLowWaterMark;
    Config.Netdb.high = DefaultNetdbHigh;
    Config.Netdb.low = DefaultNetdbLow;
    Config.Netdb.period = DefaultNetdbPeriod;

    Config.Wais.relayHost = safe_xstrdup(DefaultWaisRelayHost);
    Config.Wais.relayPort = DefaultWaisRelayPort;

    Config.referenceAge = DefaultReferenceAge;
    Config.negativeTtl = DefaultNegativeTtl;
    Config.negativeDnsTtl = DefaultNegativeDnsTtl;
    Config.positiveDnsTtl = DefaultPositiveDnsTtl;
    Config.Timeout.read = DefaultReadTimeout;
    Config.Timeout.connect = DefaultConnectTimeout;
    Config.Timeout.defer = DefaultDeferTimeout;
    Config.Timeout.lifetime = DefaultClientLifetime;
    Config.shutdownLifetime = DefaultShutdownLifetime;
    Config.maxRequestSize = DefaultMaxRequestSize;
    Config.cleanRate = DefaultCleanRate;
    Config.dnsChildren = DefaultDnsChildren;
    Config.redirectChildren = DefaultRedirectChildren;
    Config.sourcePing = DefaultSourcePing;
    Config.quickAbort.min = DefaultQuickAbortMin;
    Config.quickAbort.pct = DefaultQuickAbortPct;
    Config.quickAbort.max = DefaultQuickAbortMax;
    Config.commonLogFormat = DefaultCommonLogFormat;
#if LOG_FULL_HEADERS
    Config.logMimeHdrs = DefaultLogMimeHdrs;
#endif /* LOG_FULL_HEADERS */
    Config.identLookup = DefaultIdentLookup;
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
    Config.Log.log_fqdn = DefaultLogLogFqdn;
    Config.Log.log = safe_xstrdup(DefaultCacheLogFile);
    Config.Log.access = safe_xstrdup(DefaultAccessLogFile);
    Config.Log.store = safe_xstrdup(DefaultStoreLogFile);
    Config.Log.swap = safe_xstrdup(DefaultSwapLogFile);
#if USE_USERAGENT_LOG
    Config.Log.useragent = safe_xstrdup(DefaultUseragentLogFile);
#endif
    Config.Log.rotateNumber = DefaultLogRotateNumber;
    Config.Program.ftpget = safe_xstrdup(DefaultFtpgetProgram);
    Config.Program.ftpget_opts = safe_xstrdup(DefaultFtpgetOptions);
    Config.Program.dnsserver = safe_xstrdup(DefaultDnsserverProgram);
    Config.Program.redirect = safe_xstrdup(DefaultRedirectProgram);
    Config.Program.pinger = safe_xstrdup(DefaultPingerProgram);
    Config.Program.unlinkd = safe_xstrdup(DefaultUnlinkdProgram);
    Config.Accel.host = safe_xstrdup(DefaultAccelHost);
    Config.Accel.prefix = safe_xstrdup(DefaultAccelPrefix);
    Config.Accel.port = DefaultAccelPort;
    Config.Accel.withProxy = DefaultAccelWithProxy;
    Config.pidFilename = safe_xstrdup(DefaultPidFilename);
    Config.visibleHostname = safe_xstrdup(DefaultVisibleHostname);
#if USE_PROXY_AUTH
    Config.proxyAuth.File = safe_xstrdup(DefaultProxyAuthFile);
/*    Config.proxyAuth.IgnoreDomains = safe_xstrdup(DefaultproxyAuthIgnoreDomains); */
#endif /* USE_PROXY_AUTH */
    Config.ftpUser = safe_xstrdup(DefaultFtpUser);
    Config.Announce.host = safe_xstrdup(DefaultAnnounceHost);
    Config.Announce.port = DefaultAnnouncePort;
    Config.Announce.file = safe_xstrdup(DefaultAnnounceFile);
    Config.Announce.rate = DefaultAnnounceRate;
    Config.Announce.on = 0;
    Config.tcpRcvBufsz = DefaultTcpRcvBufsz;
    Config.udpMaxHitObjsz = DefaultUdpMaxHitObjsz;
    Config.Addrs.tcp_outgoing.s_addr = DefaultTcpOutgoingAddr;
    Config.Addrs.tcp_incoming.s_addr = DefaultTcpIncomingAddr;
    Config.Addrs.udp_outgoing.s_addr = DefaultUdpOutgoingAddr;
    Config.Addrs.udp_incoming.s_addr = DefaultUdpIncomingAddr;
    Config.Addrs.client_netmask.s_addr = DefaultClientNetmask;
    Config.passProxy = DefaultPassProxy;
    Config.sslProxy = DefaultSslProxy;
    Config.ipcache.size = DefaultIpcacheSize;
    Config.ipcache.low = DefaultIpcacheLow;
    Config.ipcache.high = DefaultIpcacheHigh;
    Config.minDirectHops = DefaultMinDirectHops;
    Config.Store.maxObjectSize = DefaultMaxObjectSize;
    Config.Store.avgObjectSize = DefaultAvgObjectSize;
    Config.Store.objectsPerBucket = DefaultObjectsPerBucket;
    Config.Options.log_udp = DefaultOptionsLogUdp;
    Config.Options.res_defnames = DefaultOptionsResDefnames;
    Config.Options.anonymizer = DefaultOptionsAnonymizer;
    Config.Options.enable_purge = DefaultOptionsEnablePurge;
    Config.Options.client_db = DefaultOptionsClientDb;
    Config.Options.query_icmp = DefaultOptionsQueryIcmp;
}

static void
configDoConfigure(void)
{
    httpd_accel_mode = Config.Accel.prefix ? 1 : 0;
    if (Config.errHtmlText == NULL)
	Config.errHtmlText = xstrdup(null_string);
    storeConfigure();
    if (httpd_accel_mode && !Config.Accel.withProxy) {
	safe_free(Config.Program.ftpget);
	Config.Program.ftpget = xstrdup("none");
    }
    if (httpd_accel_mode && !strcmp(Config.Accel.host, "virtual"))
	vhost_mode = 1;
    sprintf(ThisCache, "%s:%d (Squid/%s)",
	getMyHostname(),
	(int) Config.Port.http,
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
    if (!strncasecmp(unit, "second", 6))
	return 1;
    if (!strncasecmp(unit, "minute", 6))
	return 60;
    if (!strncasecmp(unit, "hour", 4))
	return 3600;
    if (!strncasecmp(unit, "day", 3))
	return 86400;
    if (!strncasecmp(unit, "week", 4))
	return 86400 * 7;
    if (!strncasecmp(unit, "fortnight", 9))
	return 86400 * 14;
    if (!strncasecmp(unit, "month", 5))
	return 86400 * 30;
    if (!strncasecmp(unit, "year", 4))
	return 86400 * 365.2522;
    if (!strncasecmp(unit, "decade", 6))
	return 86400 * 365.2522 * 10;
    debug(3, 1, "parseTimeUnits: unknown time unit '%s'\n", unit);
    return 0;
}
