/*
 * $Id: cache_cf.cc,v 1.198 1997/06/26 22:41:37 wessels Exp $
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
#define DefaultReadTimeout      (15 * 60)	/* 15 min */
#define DefaultConnectTimeout   120	/* 2 min */
#define DefaultDeferTimeout     3600	/* 1 hour */
#define DefaultRequestTimeout   30	/* 30 seconds */
#define DefaultClientLifetime   86400	/* 1 day */
#define DefaultShutdownLifetime 30	/* 30 seconds */
#define DefaultCleanRate        -1	/* disabled */
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
#define DefaultLogMimeHdrs	0	/* default off */
#define DefaultIdentLookup	0	/* default off */
#define DefaultQuickAbortMin	-1	/* default off */
#define DefaultQuickAbortPct	0	/* default off */
#define DefaultQuickAbortMax	0	/* default off */
#define DefaultNeighborTimeout  2	/* 2 seconds */
#define DefaultStallDelay	1	/* 1 seconds */
#define DefaultSingleParentBypass 0	/* default off */
#define DefaultPidFilename      DEFAULT_PID_FILE
#define DefaultMimeTable        DEFAULT_MIME_TABLE
#define DefaultVisibleHostname  (char *)NULL	/* default NONE */
#define DefaultFtpAnonUser	"squid@"	/* Default without domain */
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

#define DefaultFtpIconPrefix	"internal-"
#define DefaultFtpIconSuffix	null_string
#define DefaultFtpListWidth	32
#define DefaultFtpListWrap	0

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
static char *safe_xstrdup _PARAMS((const char *p));
static void self_destruct _PARAMS((void));
static void wordlistAdd _PARAMS((wordlist **, const char *));

static void configDoConfigure _PARAMS((void));
static void configSetFactoryDefaults _PARAMS((void));
static void parseRefreshPattern _PARAMS((int icase));
static int parseTimeUnits _PARAMS((const char *unit));
static void parseTimeLine _PARAMS((int *iptr, const char *units));

static void parse_string _PARAMS((char **));
static void parse_wordlist _PARAMS((wordlist **));
static void dump_all _PARAMS((void));
static void default_all _PARAMS((void));
static int parse_line _PARAMS((char[]));

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
    safe_free(Config.Program.dnsserver);
    safe_free(Config.Program.redirect);
    safe_free(Config.Program.unlinkd);
    safe_free(Config.Program.pinger);
    safe_free(Config.Accel.host);
    safe_free(Config.Accel.prefix);
    safe_free(Config.appendDomain);
    safe_free(Config.debugOptions);
    safe_free(Config.pidFilename);
    safe_free(Config.mimeTablePathname);
    safe_free(Config.visibleHostname);
#if USE_PROXY_AUTH
    safe_free(Config.proxyAuth.File);
    aclDestroyRegexList(Config.proxyAuth.IgnoreDomains);
    Config.proxyAuth.IgnoreDomains = NULL;
#endif /* USE_PROXY_AUTH */
    safe_free(Config.Announce.host);
    safe_free(Config.Announce.file);
    safe_free(Config.errHtmlText);
    safe_free(Config.Ftp.icon_prefix);
    safe_free(Config.Ftp.icon_suffix);
    safe_free(Config.Ftp.anon_user);
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
    Config.Timeout.request = DefaultRequestTimeout;
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
    Config.logMimeHdrs = DefaultLogMimeHdrs;
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
    Config.Program.dnsserver = safe_xstrdup(DefaultDnsserverProgram);
    Config.Program.redirect = safe_xstrdup(DefaultRedirectProgram);
    Config.Program.pinger = safe_xstrdup(DefaultPingerProgram);
    Config.Program.unlinkd = safe_xstrdup(DefaultUnlinkdProgram);
    Config.Accel.host = safe_xstrdup(DefaultAccelHost);
    Config.Accel.prefix = safe_xstrdup(DefaultAccelPrefix);
    Config.Accel.port = DefaultAccelPort;
    Config.Accel.withProxy = DefaultAccelWithProxy;
    Config.pidFilename = safe_xstrdup(DefaultPidFilename);
    Config.mimeTablePathname = safe_xstrdup(DefaultMimeTable);
    Config.visibleHostname = safe_xstrdup(DefaultVisibleHostname);
#if USE_PROXY_AUTH
    Config.proxyAuth.File = safe_xstrdup(DefaultProxyAuthFile);
/*    Config.proxyAuth.IgnoreDomains = safe_xstrdup(DefaultproxyAuthIgnoreDomains); */
#endif /* USE_PROXY_AUTH */
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
    Config.Ftp.icon_prefix = safe_xstrdup(DefaultFtpIconPrefix);
    Config.Ftp.icon_suffix = safe_xstrdup(DefaultFtpIconSuffix);
    Config.Ftp.list_width = DefaultFtpListWidth;
    Config.Ftp.list_wrap = DefaultFtpListWrap;
    Config.Ftp.anon_user = safe_xstrdup(DefaultFtpAnonUser);
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
dump_cachehost(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_cachehost(void)
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
	    debug(3, 0) ("parseCacheHostLine: token='%s'\n", token);
	    self_destruct();
	}
    }
    if (weight < 1)
	weight = 1;
    neighborAdd(hostname, type, http_port, icp_port, options,
	weight, mcast_ttl);
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
dump_effectiveuser(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_effectiveuser(void)
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

static void
dump_pathname_check(char path[])
{
    printf("%s", path);
}

static void
parse_pathname_check(char *path[])
{
    struct stat sb;

    parse_string(path);

    if (stat(*path, &sb) < 0) {
	debug(50, 1) ("parse_pathname_check: %s: %s\n", *path, xstrerror());
	self_destruct();
    }
}

static void
dump_proxy(peer * E)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_proxy(peer ** E)
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
    e->tcp_up = 1;
    *E = e;
}

#if USE_PROXY_AUTH
static void
dump_proxyauth(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_proxyauth(void)
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
dump_quickabort(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_quickabort(void)
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
    aclParseRegexList(var, 0);
}

static void
dump_regexlist_icase(relist * var)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_regexlist_icase(relist ** var)
{
    aclParseRegexList(var, 1);
}

static void
dump_string(char var[])
{
    printf("%s", var);
}

static void
parse_string(char *var[])
{
    char *token = strtok(NULL, w_space);

    safe_free(*var);
    if (token == NULL)
	self_destruct();
    *var = xstrdup(token);
}

static void
dump_string_optional(const char *var)
{
    printf("%s", var);
}

static void
parse_string_optional(char *volatile *var)
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
dump_waisrelay(void)
{
    debug(0,0)("XXX need to fix\n");
}

static void
parse_waisrelay(void)
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

static void
parse_proxyauth(void)
{
	fatal("not implemented");
}

static void
dump_proxyauth(void)
{
	fatal("not implemented");
}

#include "cf_parser.c"
