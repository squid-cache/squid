/* $Id: cache_cf.cc,v 1.10 1996/03/29 21:14:32 wessels Exp $ */

/* DEBUG: Section 3             cache_cf: Configuration file parsing */

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
	int relayPort;
    } Wais;
    int negativeTtl;
    int readTimeout;
    int lifetimeDefault;
    int connectTimeout;
    int ageMaxDefault;
    int cleanRate;
    int dnsChildren;
    double hotVmFactor;
    struct {
	int ascii;
	int udp;
    } Port;
    struct {
	char *log;
	char *access;
	char *hierarchy;
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
	int port;
	int withProxy;
    } Accel;
    char *appendDomain;
    char *debugOptions;
    char *pidFilename;
    char *visibleHostname;
} Config;

#define DefaultMemMaxSize 	(16 << 20)	/* 16 MB */
#define DefaultMemHighWatherMark 90	/* 90% */
#define DefaultMemLowWatherMark  60	/* 60% */
#define DefaultSwapMaxSize	(100 << 10)	/* 100 MB (100*1024 kbytes) */
#define DefaultSwapHighWaterMark 90	/* 90% */
#define DefaultSwapLowWaterMark  60	/* 60% */

#define DefaultFtpDefaultTtl	(7 * 24 * 60 * 60)	/* 1 week */
#define DefaultFtpMaxObjSize	(4 << 20)	/* 4 MB */
#define DefaultGopherDefaultTtl	(7 * 24 * 60 * 60)	/* 1 week */
#define DefaultGopherMaxObjSize	(4 << 20)	/* 4 MB */
#define DefaultHttpDefaultTtl	(7 * 24 * 60 * 60)	/* 1 week */
#define DefaultHttpMaxObjSize	(4 << 20)	/* 4 MB */
#define DefaultWaisDefaultTtl	(7 * 24 * 60 * 60)	/* 1 week */
#define DefaultWaisMaxObjSize	(4 << 20)	/* 4 MB */
#define DefaultWaisRelayHost	(char *)NULL
#define DefaultWaisRelayPort	-1

#define DefaultNegativeTtl	(5 * 60)	/* 5 min */
#define DefaultReadTimeout	(15 * 60)	/* 15 min */
#define DefaultLifetimeDefault	(200 * 60)	/* 3+ hours */
#define DefaultConnectTimeout	(2 * 60)	/* 2 min */
#define DefaultDefaultAgeMax	(3600 * 24 * 30)	/* 30 days */
#define DefaultCleanRate	-1	/* disabled */
#define DefaultDnsChildren	5	/* 3 processes */
#define DefaultDnsChildrenMax	32	/* 32 processes */
#define DefaultHotVmFactor	0.0	/* disabled */

#define DefaultAsciiPortNum	CACHE_HTTP_PORT
#define DefaultUdpPortNum	CACHE_ICP_PORT

#define DefaultCacheLogFile	"cache.log"
#define DefaultAccessLogFile	"cache.access.log"
#define DefaultHierarchyLogFile "cache.hierarchy.log"
#define DefaultLogRotateNumber  10
#define DefaultAdminEmail	"webmaster"
#define DefaultFtpgetProgram	"ftpget"
#define DefaultFtpgetOptions	""
#define DefaultDnsserverProgram "dnsserver"
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
#define DefaultStallDelay	3	/* 3 seconds */
#define DefaultSingleParentBypass 0	/* default off */
#define DefaultPidFilename      (char *)NULL	/* default NONE */
#define DefaultVisibleHostname  (char *)NULL	/* default NONE */

extern char *config_file;

stoplist *http_stoplist = NULL;
stoplist *gopher_stoplist = NULL;
stoplist *ftp_stoplist = NULL;
stoplist *bind_addr_list = NULL;
stoplist *local_domain_list = NULL;
stoplist *inside_firewall_list = NULL;

ip_acl *proxy_ip_acl = NULL;
ip_acl *accel_ip_acl = NULL;
ip_acl *manager_ip_acl = NULL;
ip_acl *local_ip_list = NULL;

int zap_disk_store = 0;		/* off, try to rebuild from disk */
int httpd_accel_mode = 0;	/* for fast access */
int emulate_httpd_log = DefaultCommonLogFormat;		/* for fast access */
time_t neighbor_timeout = DefaultNeighborTimeout;	/* for fast access */
int single_parent_bypass = 0;
int getDnsChildren();

char w_space[] = " \t\n";

static void configSetFactoryDefaults();
static void configDoConfigure();
static char fatal_str[BUFSIZ];

void self_destruct(in_string)
     char *in_string;
{
    sprintf(fatal_str, "Bungled cached.conf: %s", in_string);
    fatal(fatal_str);
}

int ip_acl_match(c1, c2, c3, c4, a1, a2, a3, a4)
     int c1;
     int c2;
     int c3;
     int c4;
     int a1;
     int a2;
     int a3;
     int a4;
{
    if (!((a1 == 0) || (a1 == c1)))
	return 0;
    if (!((a2 == 0) || (a2 == c2)))
	return 0;
    if (!((a3 == 0) || (a3 == c3)))
	return 0;
    if (!((a4 == 0) || (a4 == c4)))
	return 0;

    return 1;
}


ip_access_type
ip_access_check(address, list)
     struct in_addr address;
     ip_acl *list;
{
    int c1, c2, c3, c4;
    ip_acl *p;
    unsigned int naddr = 0;	/* network byte-order IP addr */

    if (!list)
	return IP_ALLOW;

    naddr = htonl(address.s_addr);
    c1 = ((int) naddr & 0xff000000) >> 24;
    c2 = ((int) naddr & 0x00ff0000) >> 16;
    c3 = ((int) naddr & 0x0000ff00) >> 8;
    c4 = ((int) naddr & 0x000000ff);

    debug(3, 10, "ip_access_check: Using %d.%d.%d.%d\n", c1, c2, c3, c4);

    if ((c1 == 127) && (c2 == 0) && (c3 == 0) && (c4 == 1))
	return IP_ALLOW;	/* always allow localhost */

    for (p = list; p; p = p->next) {
	debug(3, 10, "ip_access_check: %d.%d.%d.%d vs %d.%d.%d.%d\n",
	    c1, c2, c3, c4, p->a1, p->a2, p->a3, p->a4);
	if (ip_acl_match(c1, c2, c3, c4, p->a1, p->a2, p->a3, p->a4))
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

    if (!ip_str) {
	return;
    }
    if (!(*list)) {
	/* empty list */
	*list = (ip_acl *) xcalloc(1, sizeof(ip_acl));
	(*list)->next = NULL;
	q = *list;
    } else {
	p = *list;
	while (p->next)
	    p = p->next;
	q = (ip_acl *) xcalloc(1, sizeof(ip_acl));
	q->next = NULL;
	p->next = q;
    }

    /* decode ip address */
    if (strstr(ip_str, "all") || strstr(ip_str, "ALL") ||
	strstr(ip_str, "All")) {
	a1 = a2 = a3 = a4 = 0;
    } else {
	a1 = a2 = a3 = a4 = 0;
	sscanf(ip_str, "%d.%d.%d.%d", &a1, &a2, &a3, &a4);
    }

    q->access = access;
    q->a1 = a1;
    q->a2 = a2;
    q->a3 = a3;
    q->a4 = a4;

}


void addToStopList(list, key)
     stoplist **list;
     char *key;
{
    stoplist *p, *q;

    if (!(*list)) {
	/* empty list */
	*list = (stoplist *) xcalloc(1, sizeof(stoplist));
	(*list)->key = xstrdup(key);
	(*list)->next = NULL;
    } else {
	p = *list;
	while (p->next)
	    p = p->next;
	q = (stoplist *) xcalloc(1, sizeof(stoplist));
	q->key = xstrdup(key);
	q->next = NULL;
	p->next = q;
    }
}

/* Use this #define in all the parse*() functions.  Assumes 
 * ** char *token and char *line_in are defined
 */

#define GetInteger(var) \
	token = strtok(NULL, w_space); \
	if( token == (char *) NULL) \
		self_destruct(line_in); \
	if (sscanf(token, "%d", &var) != 1) \
		self_destruct(line_in);


static void parseCacheHostLine(line_in)
     char *line_in;
{
    char *type = NULL;
    char *hostname = NULL;
    char *token = NULL;
    int ascii_port = CACHE_HTTP_PORT;
    int udp_port = CACHE_ICP_PORT;
    int proxy_only = 0;

    /* Parse a cache_host line */
    if (!(hostname = strtok(NULL, w_space)))
	self_destruct(line_in);
    if (!(type = strtok(NULL, w_space)))
	self_destruct(line_in);

    GetInteger(ascii_port);
    GetInteger(udp_port);
    if ((token = strtok(NULL, w_space))) {
	if (!strcasecmp(token, "proxy-only"))
	    proxy_only = 1;
    }
    neighbors_cf_add(hostname, type, ascii_port, udp_port, proxy_only);
}

static void parseHostDomainLine(line_in)
     char *line_in;
{
    char *host = NULL;
    char *domain = NULL;

    if (!(host = strtok(NULL, w_space)))
	self_destruct(line_in);
    while ((domain = strtok(NULL, ", \t\n"))) {
	if (neighbors_cf_domain(host, domain) == 0)
	    self_destruct(line_in);
    }
}

static void parseMailTraceLine(line_in)
     char *line_in;
{
    fprintf(stderr, "'mail_trace' not supported in this version; ignored.\n");
}


static void parseSourcePingLine(line_in)
     char *line_in;
{
    char *srcping;

    srcping = strtok(NULL, w_space);
    if (srcping == (char *) NULL)
	self_destruct(line_in);

    /* set source_ping, default is off. */
    if (!strcasecmp(srcping, "on"))
	Config.sourcePing = 1;
    else if (!strcasecmp(srcping, "off"))
	Config.sourcePing = 0;
    else
	Config.sourcePing = 0;
}


static void parseQuickAbortLine(line_in)
     char *line_in;
{
    char *abort;

    abort = strtok(NULL, w_space);
    if (abort == (char *) NULL)
	self_destruct(line_in);

    if (!strcasecmp(abort, "on") || !strcasecmp(abort, "quick"))
	Config.quickAbort = 1;
    else if (!strcmp(abort, "off") || !strcasecmp(abort, "normal"))
	Config.quickAbort = 0;
    else
	Config.quickAbort = 0;

}

static void parseMemLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.Mem.maxSize = i << 20;
}

static void parseMemHighLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.Mem.highWatherMark = i;
}

static void parseMemLowLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.Mem.lowWaterMark = i;
}

static void parseHotVmFactorLine(line_in)
     char *line_in;
{
    char *token = NULL;
    double d;

    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    if (sscanf(token, "%lf", &d) != 1)
	self_destruct(line_in);
    if (d < 0)
	self_destruct(line_in);
    Config.hotVmFactor = d;
}

static void parseSwapLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.Swap.maxSize = i << 10;
}

static void parseSwapHighLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.Swap.highWatherMark = i;
}

static void parseSwapLowLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.Swap.lowWaterMark = i;
}

static void parseHttpLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.Http.maxObjSize = i << 20;
    GetInteger(i);
    Config.Http.defaultTtl = i * 60;
}

static void parseGopherLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.Gopher.maxObjSize = i << 20;
    GetInteger(i);
    Config.Gopher.defaultTtl = i * 60;
}

static void parseFtpLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.Ftp.maxObjSize = i << 20;
    GetInteger(i);
    Config.Ftp.defaultTtl = i * 60;
}

static void parseTTLPattern(line_in)
     char *line_in;
{
    char *token;
    char *pattern;
    time_t abs_ttl = 0;
    int pct_age = 0;
    time_t age_max = Config.ageMaxDefault;
    int i;

    token = strtok(NULL, w_space);	/* token: regex pattern */
    if (token == (char *) NULL)
	self_destruct(line_in);
    pattern = xstrdup(token);

    GetInteger(i);		/* token: abs_ttl */
    abs_ttl = (time_t) (i * 60);	/* convert minutes to seconds */

    token = strtok(NULL, w_space);	/* token: pct_age */
    if (token != (char *) NULL) {	/* pct_age is optional */
	if (sscanf(token, "%d", &pct_age) != 1)
	    self_destruct(line_in);
    }
    token = strtok(NULL, w_space);	/* token: age_max */
    if (token != (char *) NULL) {	/* age_max is optional */
	if (sscanf(token, "%d", &i) != 1)
	    self_destruct(line_in);
	age_max = (time_t) (i * 60);	/* convert minutes to seconds */
    }
    ttlAddToList(pattern, abs_ttl, pct_age, age_max);

    safe_free(pattern);
}

static void parseNegativeLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.negativeTtl = i * 60;
}

static void parseReadTimeoutLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.readTimeout = i * 60;
}

static void parseLifetimeLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.lifetimeDefault = i * 60;
}

static void parseConnectTimeout(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.connectTimeout = i;
}

static void parseCleanRateLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.cleanRate = i * 60;
}

static void parseDnsChildrenLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.dnsChildren = i;
}

static void parseMgrLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    safe_free(Config.adminEmail);
    Config.adminEmail = xstrdup(token);
}

static void parseDirLine(line_in)
     char *line_in;
{
    char *token;

    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    storeAddSwapDisk(xstrdup(token));

}

static void parseHttpdAccelLine(line_in)
     char *line_in;
{
    char *token;
    char buf[1024];
    int i;

    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    safe_free(Config.Accel.host);
    Config.Accel.host = xstrdup(token);
    GetInteger(i);
    Config.Accel.port = i;
    safe_free(Config.Accel.prefix);
    sprintf(buf, "http://%s:%d", Config.Accel.host, Config.Accel.port);
    Config.Accel.prefix = xstrdup(buf);
    httpd_accel_mode = 1;
}

static void parseHttpdAccelWithProxyLine(line_in)
     char *line_in;
{
    char *proxy;

    proxy = strtok(NULL, w_space);
    if (proxy == (char *) NULL)
	self_destruct(line_in);

    /* set httpd_accel_with_proxy, default is off. */
    if (!strcasecmp(proxy, "on"))
	Config.Accel.withProxy = 1;
    else if (!strcasecmp(proxy, "off"))
	Config.Accel.withProxy = 0;
    else
	Config.Accel.withProxy = 0;
}

static void parseEffectiveUserLine(line_in)
     char *line_in;
{
    char *token;

    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    safe_free(Config.effectiveUser);
    safe_free(Config.effectiveGroup);
    Config.effectiveUser = xstrdup(token);

    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	return;			/* group is optional */
    Config.effectiveGroup = xstrdup(token);
}

static void parseLogLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    safe_free(Config.Log.log);
    Config.Log.log = xstrdup(token);
}

static void parseAccessLogLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    safe_free(Config.Log.access);
    Config.Log.access = xstrdup(token);
}

static void parseHierachyLogLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    safe_free(Config.Log.hierarchy);
    Config.Log.hierarchy = xstrdup(token);
}

static void parseLogfileRotateLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.Log.rotateNumber = i;
}

static void parseFtpProgramLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    safe_free(Config.Program.ftpget);
    Config.Program.ftpget = xstrdup(token);
}

static void parseFtpOptionsLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, "");	/* Note "", don't separate these */
    if (token == (char *) NULL)
	self_destruct(line_in);
    safe_free(Config.Program.ftpget_opts);
    Config.Program.ftpget_opts = xstrdup(token);
}

static void parseDnsProgramLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    safe_free(Config.Program.dnsserver);
    Config.Program.dnsserver = xstrdup(token);
}

static void parseEmulateLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    if (!strcasecmp(token, "on") || !strcasecmp(token, "enable"))
	Config.commonLogFormat = 1;
    else
	Config.commonLogFormat = 0;
}

static void parseWAISRelayLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    safe_free(Config.Wais.relayHost);
    Config.Wais.relayHost = xstrdup(token);
    GetInteger(i);
    Config.Wais.relayPort = i;
    GetInteger(i);
    Config.Wais.maxObjSize = i << 20;
}

static void parseProxyAllowLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	return;
    addToIPACL(&proxy_ip_acl, token, IP_ALLOW);
}

static void parseAccelAllowLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	return;
    addToIPACL(&accel_ip_acl, token, IP_ALLOW);
}

static void parseManagerAllowLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	return;
    addToIPACL(&manager_ip_acl, token, IP_ALLOW);
}

static void parseProxyDenyLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	return;
    addToIPACL(&proxy_ip_acl, token, IP_DENY);
}

static void parseAccelDenyLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	return;
    addToIPACL(&accel_ip_acl, token, IP_DENY);
}

static void parseManagerDenyLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	return;
    addToIPACL(&manager_ip_acl, token, IP_DENY);
}

static void parseLocalIPLine(line_in)
     char *line_in;
{
    char *token;
    while ((token = strtok(NULL, w_space))) {
	addToIPACL(&local_ip_list, token, IP_DENY);
    }
}

static void parseHttpStopLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	return;
    addToStopList(&http_stoplist, token);
}

static void parseGopherStopLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	return;
    addToStopList(&gopher_stoplist, token);
}
static void parseFtpStopLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	return;
    addToStopList(&ftp_stoplist, token);
}

static void parseAppendDomainLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    if (*token != '.')
	self_destruct(line_in);
    safe_free(Config.appendDomain);
    Config.appendDomain = xstrdup(token);
}

static void parseBindAddressLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    debug(3, 1, "parseBindAddressLine: adding %s\n", token);
    addToStopList(&bind_addr_list, token);
}

static void parseBlockListLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	return;
    blockAddToList(token);
}

static void parseLocalDomainLine(line_in)
     char *line_in;
{
    char *token;
    while ((token = strtok(NULL, w_space))) {
	addToStopList(&local_domain_list, token);
    }
}

static void parseInsideFirewallLine(line_in)
     char *line_in;
{
    char *token;
    while ((token = strtok(NULL, w_space))) {
	addToStopList(&inside_firewall_list, token);
    }
}

static void parseAsciiPortLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.Port.ascii = i;
}

static void parseUdpPortLine(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.Port.udp = i;
}

static void parseNeighborTimeout(line_in)
     char *line_in;
{
    char *token;
    int i;
    GetInteger(i);
    Config.neighborTimeout = i;
}

static void parseSingleParentBypassLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    if (token == (char *) NULL)
	self_destruct(line_in);
    if (!strcasecmp(token, "on"))
	Config.singleParentBypass = 1;
}

static void parseDebugOptionsLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, "");	/* Note "", don't separate these */
    safe_free(Config.debugOptions);
    if (token == (char *) NULL) {
	Config.debugOptions = NULL;
	return;
    }
    Config.debugOptions = xstrdup(token);
}

static void parsePidFilenameLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    safe_free(Config.pidFilename);
    if (token == (char *) NULL)
	self_destruct(line_in);
    Config.pidFilename = xstrdup(token);
}

static void parseVisibleHostnameLine(line_in)
     char *line_in;
{
    char *token;
    token = strtok(NULL, w_space);
    safe_free(Config.visibleHostname);
    if (token == (char *) NULL)
	self_destruct(line_in);
    Config.visibleHostname = xstrdup(token);
}

int parseConfigFile(file_name)
     char *file_name;
{
    FILE *fp = NULL;
    char *token = NULL;
    static char tmp_line[BUFSIZ];
    static char line_in[BUFSIZ];

    /* Initialize a few global strings, in case they aren't user defined */

    configSetFactoryDefaults();

    if ((fp = fopen(file_name, "r")) == NULL) {
	sprintf(fatal_str, "Unable to open configuration file: %s", file_name);
	fatal(fatal_str);
    }
    memset(line_in, '\0', BUFSIZ);
    while (fgets(line_in, BUFSIZ, fp)) {
	if (line_in[0] == '#' || line_in[0] == '\n' || line_in[0] == '\0')
	    continue;		/* skip comments */

	if (line_in[0] == '\n')
	    continue;
	debug(3, 5, "Processing: '%s'\n", line_in);
	strcpy(tmp_line, line_in);
	if ((token = strtok(tmp_line, w_space)) == NULL)
	    continue;

	/* Parse a cache_host line */
	if (!strcmp(token, "cache_host"))
	    parseCacheHostLine(line_in);

	/* Parse a cache_host_domain line */
	else if (!strcmp(token, "cache_host_domain"))
	    parseHostDomainLine(line_in);

	/* Parse a neighbor_timeout line */
	else if (!strcmp(token, "neighbor_timeout"))
	    parseNeighborTimeout(line_in);
	else if (!strcmp(token, "neighbour_timeout"))	/* alternate spelling */
	    parseNeighborTimeout(line_in);

	/* Parse a cache_dir line */
	else if (!strcmp(token, "cache_dir"))
	    parseDirLine(line_in);

	/* Parse a cache_log line */
	else if (!strcmp(token, "cache_log"))
	    parseLogLine(line_in);

	/* Parse a cache_access_log line */
	else if (!strcmp(token, "cache_access_log"))
	    parseAccessLogLine(line_in);

	/* Parse a cache_hierarchy_log line */
	else if (!strcmp(token, "cache_hierarchy_log"))
	    parseHierachyLogLine(line_in);

	/* Parse a logfile_rotate line */
	else if (!strcmp(token, "logfile_rotate"))
	    parseLogfileRotateLine(line_in);

	/* Parse a httpd_accel_with_proxy line */
	else if (!strcmp(token, "httpd_accel_with_proxy"))
	    parseHttpdAccelWithProxyLine(line_in);

	/* Parse a httpd_accel line */
	else if (!strcmp(token, "httpd_accel"))
	    parseHttpdAccelLine(line_in);

	/* Parse a cache_effective_user line */
	else if (!strcmp(token, "cache_effective_user"))
	    parseEffectiveUserLine(line_in);

	/* Parse a cache_mem_high line */
	else if (!strcmp(token, "cache_swap_high"))
	    parseSwapHighLine(line_in);

	/* Parse a cache_mem_low line */
	else if (!strcmp(token, "cache_swap_low"))
	    parseSwapLowLine(line_in);

	/* Parse a cache_mem_high line */
	else if (!strcmp(token, "cache_mem_high"))
	    parseMemHighLine(line_in);

	/* Parse a cache_mem_low line */
	else if (!strcmp(token, "cache_mem_low"))
	    parseMemLowLine(line_in);

	/* Parse a cache_hot_vm_factor line */
	else if (!strcmp(token, "cache_hot_vm_factor"))
	    parseHotVmFactorLine(line_in);

	/* Parse a cache_mem line */
	/* XXX: this must be AFTER cache_mem_low, etc. */
	else if (!strcmp(token, "cache_mem"))
	    parseMemLine(line_in);

	/* Parse a cache_swap line */
	else if (!strcmp(token, "cache_swap"))
	    parseSwapLine(line_in);

	/* Parse a cache_mgr line */
	else if (!strcmp(token, "cache_mgr"))
	    parseMgrLine(line_in);

	/* Parse a proxy_allow line */
	else if (!strcmp(token, "proxy_allow"))
	    parseProxyAllowLine(line_in);

	/* Parse a proxy_deny line */
	else if (!strcmp(token, "proxy_deny"))
	    parseProxyDenyLine(line_in);

	/* Parse a accel_allow line */
	else if (!strcmp(token, "accel_allow"))
	    parseAccelAllowLine(line_in);

	/* Parse a accel_deny line */
	else if (!strcmp(token, "accel_deny"))
	    parseAccelDenyLine(line_in);

	/* Parse a manager_allow line */
	else if (!strcmp(token, "manager_allow"))
	    parseManagerAllowLine(line_in);

	/* Parse a manager_deny line */
	else if (!strcmp(token, "manager_deny"))
	    parseManagerDenyLine(line_in);

	/* Parse a http_stop line */
	else if (!strcmp(token, "http_stop"))
	    parseHttpStopLine(line_in);

	/* Parse a gopher_stop line */
	else if (!strcmp(token, "gopher_stop"))
	    parseGopherStopLine(line_in);

	/* Parse a ftp_stop line */
	else if (!strcmp(token, "ftp_stop"))
	    parseFtpStopLine(line_in);

	/* Parse a gopher protocol line */
	/* XXX: Must go after any gopher* token */
	else if (!strcmp(token, "gopher"))
	    parseGopherLine(line_in);

	/* Parse a http protocol line */
	/* XXX: Must go after any http* token */
	else if (!strcmp(token, "http"))
	    parseHttpLine(line_in);

	/* Parse a ftp protocol line */
	/* XXX: Must go after any ftp* token */
	else if (!strcmp(token, "ftp"))
	    parseFtpLine(line_in);

	else if (!strcmp(token, "ttl_pattern"))
	    parseTTLPattern(line_in);

	/* Parse a blocklist line */
	else if (!strcmp(token, "blocklist"))
	    parseBlockListLine(line_in);

	/* Parse a negative_ttl line */
	else if (!strcmp(token, "negative_ttl"))
	    parseNegativeLine(line_in);

	/* Parse a read_timeout line */
	else if (!strcmp(token, "read_timeout"))
	    parseReadTimeoutLine(line_in);

	/* Parse a clean_rate line */
	else if (!strcmp(token, "clean_rate"))
	    parseCleanRateLine(line_in);

	/* Parse a client_lifetime line */
	else if (!strcmp(token, "client_lifetime"))
	    parseLifetimeLine(line_in);

	/* Parse a connect_timeout line */
	else if (!strcmp(token, "connect_timeout"))
	    parseConnectTimeout(line_in);

	/* Parse a cache_ftp_program line */
	else if (!strcmp(token, "cache_ftp_program"))
	    parseFtpProgramLine(line_in);

	/* Parse a cache_ftp_options line */
	else if (!strcmp(token, "cache_ftp_options"))
	    parseFtpOptionsLine(line_in);

	/* Parse a cache_dns_program line */
	else if (!strcmp(token, "cache_dns_program"))
	    parseDnsProgramLine(line_in);

	/* Parse a cache_dns_program line */
	else if (!strcmp(token, "dns_children"))
	    parseDnsChildrenLine(line_in);

	/* Parse mail trace line */
	else if (!strcmp(token, "mail_trace"))
	    parseMailTraceLine(line_in);

	/* Parse source_ping line */
	else if (!strcmp(token, "source_ping"))
	    parseSourcePingLine(line_in);

	/* Parse quick_abort line */
	else if (!strcmp(token, "quick_abort"))
	    parseQuickAbortLine(line_in);

	/* Parse emulate_httpd_log line */
	else if (!strcmp(token, "emulate_httpd_log"))
	    parseEmulateLine(line_in);

	else if (!strcmp(token, "append_domain"))
	    parseAppendDomainLine(line_in);

	else if (!strcmp(token, "wais_relay"))
	    parseWAISRelayLine(line_in);

	/* Parse a local_ip line */
	else if (!strcmp(token, "local_ip"))
	    parseLocalIPLine(line_in);

	/* Parse a local_domain line */
	else if (!strcmp(token, "local_domain"))
	    parseLocalDomainLine(line_in);

	/* Parse a bind_address line */
	else if (!strcmp(token, "bind_address"))
	    parseBindAddressLine(line_in);

	/* Parse a ascii_port line */
	else if (!strcmp(token, "ascii_port"))
	    parseAsciiPortLine(line_in);

	/* Parse a udp_port line */
	else if (!strcmp(token, "udp_port"))
	    parseUdpPortLine(line_in);

	else if (!strcmp(token, "inside_firewall"))
	    parseInsideFirewallLine(line_in);

	else if (!strcmp(token, "single_parent_bypass"))
	    parseSingleParentBypassLine(line_in);

	else if (!strcmp(token, "debug_options"))
	    parseDebugOptionsLine(line_in);

	else if (!strcmp(token, "pid_filename"))
	    parsePidFilenameLine(line_in);

	else if (!strcmp(token, "visible_hostname"))
	    parseVisibleHostnameLine(line_in);

	/* If unknown, treat as a comment line */
	else {
	    /* EMPTY */ ;
	}
    }

    /* Add INADDR_ANY to end of bind_addr_list as last chance */
    addToStopList(&bind_addr_list, "0.0.0.0");

    /* Sanity checks */
    if (getClientLifetime() < getReadTimeout()) {
	printf("WARNING: client_lifetime (%d seconds) is less than read_timeout (%d seconds).\n",
	    getClientLifetime(), getReadTimeout());
	printf("         This may cause serious problems with your cache!!!\n");
	printf("         Change your cached.conf file.\n");
	fflush(stdout);		/* print message */
    }
    if (getCacheSwapMax() < (getCacheMemMax() >> 10)) {
	printf("WARNING: cache_swap (%d kbytes) is less than cache_mem (%d bytes).\n", getCacheSwapMax(), getCacheMemMax());
	printf("         This will cause serious problems with your cache!!!\n");
	printf("         Change your cached.conf file.\n");
	Config.Swap.maxSize = getCacheMemMax() >> 10;
	printf("         For this run, however, cached will use %d kbytes for cache_swap.\n", getCacheSwapMax());
	fflush(stdout);		/* print message */
    }
    if (getCleanRate() > -1 && getCleanRate() < 60) {
	Config.cleanRate = (30 * 60);
	printf("WARNING: clean_rate is less than one minute.\n");
	printf("         This will cause serious problems with your cache!!!\n");
	printf("         Change your cached.conf file.\n");
	printf("         For this run, however, cached will use %d minutes for clean_rate.\n", (int) (getCleanRate() / 60));
	fflush(stdout);		/* print message */
    }
    storeSanityCheck();

    if (accel_ip_acl == NULL)
	accel_ip_acl = proxy_ip_acl;

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
int getWaisRelayPort()
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
int getLogfileRotateNumber()
{
    return Config.Log.rotateNumber;
}
char *getCacheLogFile()
{
    return Config.Log.log;
}
int getAsciiPortNum()
{
    return Config.Port.ascii;
}
int getUdpPortNum()
{
    return Config.Port.udp;
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

int setAsciiPortNum(p)
     int p;
{
    return (Config.Port.ascii = p);
}
int setUdpPortNum(p)
     int p;
{
    return (Config.Port.udp = p);
}


char *safe_xstrdup(p)
     char *p;
{
    return p ? xstrdup(p) : p;
}

int safe_strlen(p)
     char *p;
{
    return p ? strlen(p) : -1;
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
    Config.readTimeout = DefaultReadTimeout;
    Config.lifetimeDefault = DefaultLifetimeDefault;
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

    Config.Port.ascii = DefaultAsciiPortNum;
    Config.Port.udp = DefaultUdpPortNum;
    Config.Log.log = safe_xstrdup(DefaultCacheLogFile);
    Config.Log.access = safe_xstrdup(DefaultAccessLogFile);
    Config.Log.hierarchy = safe_xstrdup(DefaultHierarchyLogFile);
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
}

static void configDoConfigure()
{
    httpd_accel_mode = Config.Accel.prefix ? 1 : 0;
    emulate_httpd_log = Config.commonLogFormat;
    neighbor_timeout = (time_t) Config.neighborTimeout;
    single_parent_bypass = Config.singleParentBypass;

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
