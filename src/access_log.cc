
/*
 * $Id: access_log.cc,v 1.77 2002/10/13 20:34:57 robertc Exp $
 *
 * DEBUG: section 46    Access Log
 * AUTHOR: Duane Wessels
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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

static void accessLogSquid(AccessLogEntry * al);
static void accessLogCommon(AccessLogEntry * al);
static Logfile *logfile = NULL;
#if HEADERS_LOG
static Logfile *headerslog = NULL;
#endif

#if MULTICAST_MISS_STREAM
static int mcast_miss_fd = -1;
static struct sockaddr_in mcast_miss_to;
static void mcast_encode(unsigned int *, size_t, const unsigned int *);
#endif

const char *log_tags[] =
{
    "NONE",
    "TCP_HIT",
    "TCP_MISS",
    "TCP_REFRESH_HIT",
    "TCP_REF_FAIL_HIT",
    "TCP_REFRESH_MISS",
    "TCP_CLIENT_REFRESH_MISS",
    "TCP_IMS_HIT",
    "TCP_SWAPFAIL_MISS",
    "TCP_NEGATIVE_HIT",
    "TCP_MEM_HIT",
    "TCP_DENIED",
    "TCP_OFFLINE_HIT",
#if LOG_TCP_REDIRECTS
    "TCP_REDIRECT",
#endif
    "UDP_HIT",
    "UDP_MISS",
    "UDP_DENIED",
    "UDP_INVALID",
    "UDP_MISS_NOFETCH",
    "ICP_QUERY",
    "LOG_TYPE_MAX"
};

#if FORW_VIA_DB
typedef struct {
    hash_link hash;
    int n;
} fvdb_entry;
static hash_table *via_table = NULL;
static hash_table *forw_table = NULL;
static void fvdbInit(void);
static void fvdbDumpTable(StoreEntry * e, hash_table * hash);
static void fvdbCount(hash_table * hash, const char *key);
static OBJH fvdbDumpVia;
static OBJH fvdbDumpForw;
static FREE fvdbFreeEntry;
static void fvdbClear(void);
#endif

static int LogfileStatus = LOG_DISABLE;
#define LOG_BUF_SZ (MAX_URL<<2)

static const char c2x[] =
"000102030405060708090a0b0c0d0e0f"
"101112131415161718191a1b1c1d1e1f"
"202122232425262728292a2b2c2d2e2f"
"303132333435363738393a3b3c3d3e3f"
"404142434445464748494a4b4c4d4e4f"
"505152535455565758595a5b5c5d5e5f"
"606162636465666768696a6b6c6d6e6f"
"707172737475767778797a7b7c7d7e7f"
"808182838485868788898a8b8c8d8e8f"
"909192939495969798999a9b9c9d9e9f"
"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
"e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

/* log_quote -- URL-style encoding on MIME headers. */

char *
log_quote(const char *header)
{
    int c;
    int i;
    char *buf;
    char *buf_cursor;
    if (header == NULL) {
	buf = static_cast<char *>(xcalloc(1, 1));
	*buf = '\0';
	return buf;
    }
    buf = static_cast<char *>(xcalloc(1, (strlen(header) * 3) + 1));
    buf_cursor = buf;
    /*
     * We escape: \x00-\x1F"#%;<>?{}|\\\\^~`\[\]\x7F-\xFF 
     * which is the default escape list for the CPAN Perl5 URI module
     * modulo the inclusion of space (x40) to make the raw logs a bit
     * more readable.
     */
    while ((c = *(const unsigned char *) header++) != '\0') {
#if !OLD_LOG_MIME
	if (c == '\r') {
	    *buf_cursor++ = '\\';
	    *buf_cursor++ = 'r';
	} else if (c == '\n') {
	    *buf_cursor++ = '\\';
	    *buf_cursor++ = 'n';
	} else
#endif
	    if (c <= 0x1F
		|| c >= 0x7F
#if OLD_LOG_MIME
		|| c == '"'
		|| c == '#'
		|| c == '%'
		|| c == ';'
		|| c == '<'
		|| c == '>'
		|| c == '?'
		|| c == '{'
		|| c == '}'
		|| c == '|'
		|| c == '\\'
		|| c == '^'
		|| c == '~'
		|| c == '`'
#endif
		|| c == '['
	    || c == ']') {
	    *buf_cursor++ = '%';
	    i = c * 2;
	    *buf_cursor++ = c2x[i];
	    *buf_cursor++ = c2x[i + 1];
#if !OLD_LOG_MIME
	} else if (c == '\\') {
	    *buf_cursor++ = '\\';
	    *buf_cursor++ = '\\';
#endif
	} else {
	    *buf_cursor++ = (char) c;
	}
    }
    *buf_cursor = '\0';
    return buf;
}

static char *
username_quote(const char *header)
/* copy of log_quote. Bugs there will be found here */
{
    int c;
    int i;
    char *buf;
    char *buf_cursor;
    if (header == NULL) {
	buf = static_cast<char *>(xcalloc(1, 1));
	*buf = '\0';
	return buf;
    }
    buf = static_cast<char *>(xcalloc(1, (strlen(header) * 3) + 1));
    buf_cursor = buf;
    /*
     * We escape: space \x00-\x1F and space (0x40) and \x7F-\xFF
     * to prevent garbage in the logs. CR and LF are also there just in case. 
     */
    while ((c = *(const unsigned char *) header++) != '\0') {
	if (c == '\r') {
	    *buf_cursor++ = '\\';
	    *buf_cursor++ = 'r';
	} else if (c == '\n') {
	    *buf_cursor++ = '\\';
	    *buf_cursor++ = 'n';
	} else if (c <= 0x1F
		|| c >= 0x7F
	    || c == ' ') {
	    *buf_cursor++ = '%';
	    i = c * 2;
	    *buf_cursor++ = c2x[i];
	    *buf_cursor++ = c2x[i + 1];
	} else {
	    *buf_cursor++ = (char) c;
	}
    }
    *buf_cursor = '\0';
    return buf;
}

static char *
accessLogFormatName(const char *name)
{
    if (NULL == name)
	return NULL;
    return username_quote(name);
}

static void
accessLogSquid(AccessLogEntry * al)
{
    const char *client = NULL;
    char *user = NULL;
    if (Config.onoff.log_fqdn)
	client = fqdncache_gethostbyaddr(al->cache.caddr, FQDN_LOOKUP_IF_MISS);
    if (client == NULL)
	client = inet_ntoa(al->cache.caddr);
    user = accessLogFormatName(al->cache.authuser ?
	al->cache.authuser : al->cache.rfc931);
    logfilePrintf(logfile, "%9d.%03d %6d %s %s/%03d %ld %s %s %s %s%s/%s %s",
	(int) current_time.tv_sec,
	(int) current_time.tv_usec / 1000,
	al->cache.msec,
	client,
	log_tags[al->cache.code],
	al->http.code,
	(long int) al->cache.size,
	al->_private.method_str,
	al->url,
	user && *user ? user : dash_str,
	al->hier.ping.timedout ? "TIMEOUT_" : "",
	hier_strings[al->hier.code],
	al->hier.host,
	al->http.content_type);
    safe_free(user);
}

static void
accessLogCommon(AccessLogEntry * al)
{
    const char *client = NULL;
    char *user1 = NULL, *user2 = NULL;
    if (Config.onoff.log_fqdn)
	client = fqdncache_gethostbyaddr(al->cache.caddr, 0);
    if (client == NULL)
	client = inet_ntoa(al->cache.caddr);
    user1 = accessLogFormatName(al->cache.authuser);
    user2 = accessLogFormatName(al->cache.rfc931);
    logfilePrintf(logfile, "%s %s %s [%s] \"%s %s HTTP/%d.%d\" %d %ld %s:%s",
	client,
	user2 ? user2 : dash_str,
	user1 ? user1 : dash_str,
	mkhttpdlogtime(&squid_curtime),
	al->_private.method_str,
	al->url,
	al->http.version.major, al->http.version.minor,
	al->http.code,
	(long int) al->cache.size,
	log_tags[al->cache.code],
	hier_strings[al->hier.code]);
    safe_free(user1);
    safe_free(user2);
}

void
accessLogLog(AccessLogEntry * al)
{
    if (LogfileStatus != LOG_ENABLE)
	return;
    if (al->url == NULL)
	al->url = dash_str;
    if (!al->http.content_type || *al->http.content_type == '\0')
	al->http.content_type = dash_str;
    if (al->icp.opcode)
	al->_private.method_str = icp_opcode_str[al->icp.opcode];
    else
	al->_private.method_str = RequestMethodStr[al->http.method];
    if (al->hier.host[0] == '\0')
	xstrncpy(al->hier.host, dash_str, SQUIDHOSTNAMELEN);

    if (Config.onoff.common_log)
	accessLogCommon(al);
    else
	accessLogSquid(al);
    if (Config.onoff.log_mime_hdrs) {
	char *ereq = log_quote(al->headers.request);
	char *erep = log_quote(al->headers.reply);
	logfilePrintf(logfile, " [%s] [%s]\n", ereq, erep);
	safe_free(ereq);
	safe_free(erep);
    } else {
	logfilePrintf(logfile, "\n");
    }
    logfileFlush(logfile);
#if MULTICAST_MISS_STREAM
    if (al->cache.code != LOG_TCP_MISS)
	(void) 0;
    else if (al->http.method != METHOD_GET)
	(void) 0;
    else if (mcast_miss_fd < 0)
	(void) 0;
    else {
	unsigned int ibuf[365];
	size_t isize;
	xstrncpy((char *) ibuf, al->url, 364 * sizeof(int));
	isize = ((strlen(al->url) + 8) / 8) * 2;
	if (isize > 364)
	    isize = 364;
	mcast_encode((unsigned int *) ibuf, isize,
	    (const unsigned int *) Config.mcast_miss.encode_key);
	comm_udp_sendto(mcast_miss_fd,
	    &mcast_miss_to, sizeof(mcast_miss_to),
	    ibuf, isize * sizeof(int));
    }
#endif
}

void
accessLogRotate(void)
{
#if FORW_VIA_DB
    fvdbClear();
#endif
    if (NULL == logfile)
	return;
    logfileRotate(logfile);
#if HEADERS_LOG
    logfileRotate(headerslog);
#endif
}

void
accessLogClose(void)
{
    if (NULL == logfile)
	return;
    logfileClose(logfile);
    logfile = NULL;
#if HEADERS_LOG
    logfileClose(headerslog);
    headerslog = NULL;
#endif
}

void
hierarchyNote(HierarchyLogEntry * hl,
    hier_code code,
    const char *cache_peer)
{
    assert(hl != NULL);
    hl->code = code;
    xstrncpy(hl->host, cache_peer, SQUIDHOSTNAMELEN);
}

void
accessLogInit(void)
{
    assert(sizeof(log_tags) == (LOG_TYPE_MAX + 1) * sizeof(char *));
    if (strcasecmp(Config.Log.access, "none") == 0)
	return;
    logfile = logfileOpen(Config.Log.access, MAX_URL << 1, 1);
    LogfileStatus = LOG_ENABLE;
#if HEADERS_LOG
    headerslog = logfileOpen("/usr/local/squid/logs/headers.log", 512);
    assert(NULL != headerslog);
#endif
#if FORW_VIA_DB
    fvdbInit();
#endif
#if MULTICAST_MISS_STREAM
    if (Config.mcast_miss.addr.s_addr != no_addr.s_addr) {
	memset(&mcast_miss_to, '\0', sizeof(mcast_miss_to));
	mcast_miss_to.sin_family = AF_INET;
	mcast_miss_to.sin_port = htons(Config.mcast_miss.port);
	mcast_miss_to.sin_addr.s_addr = Config.mcast_miss.addr.s_addr;
	mcast_miss_fd = comm_open(SOCK_DGRAM,
	    0,
	    Config.Addrs.udp_incoming,
	    Config.mcast_miss.port,
	    COMM_NONBLOCKING,
	    "Multicast Miss Stream");
	if (mcast_miss_fd < 0)
	    fatal("Cannot open Multicast Miss Stream Socket");
	debug(46, 1) ("Multicast Miss Stream Socket opened on FD %d\n",
	    mcast_miss_fd);
	mcastSetTtl(mcast_miss_fd, Config.mcast_miss.ttl);
	if (strlen(Config.mcast_miss.encode_key) < 16)
	    fatal("mcast_encode_key is too short, must be 16 characters");
    }
#endif
}

const char *
accessLogTime(time_t t)
{
    struct tm *tm;
    static char buf[128];
    static time_t last_t = 0;
    if (t != last_t) {
	tm = localtime(&t);
	strftime(buf, 127, "%Y/%m/%d %H:%M:%S", tm);
	last_t = t;
    }
    return buf;
}


#if FORW_VIA_DB

static void
fvdbInit(void)
{
    via_table = hash_create((HASHCMP *) strcmp, 977, hash4);
    forw_table = hash_create((HASHCMP *) strcmp, 977, hash4);
    cachemgrRegister("via_headers", "Via Request Headers", fvdbDumpVia, 0, 1);
    cachemgrRegister("forw_headers", "X-Forwarded-For Request Headers",
	fvdbDumpForw, 0, 1);
}

static void
fvdbCount(hash_table * hash, const char *key)
{
    fvdb_entry *fv;
    if (NULL == hash)
	return;
    fv = hash_lookup(hash, key);
    if (NULL == fv) {
	fv = static_cast <fvdb_entry *>(xcalloc(1, sizeof(fvdb_entry)));
	fv->hash.key = xstrdup(key);
	hash_join(hash, &fv->hash);
    }
    fv->n++;
}

void
fvdbCountVia(const char *key)
{
    fvdbCount(via_table, key);
}

void
fvdbCountForw(const char *key)
{
    fvdbCount(forw_table, key);
}

static void
fvdbDumpTable(StoreEntry * e, hash_table * hash)
{
    hash_link *h;
    fvdb_entry *fv;
    if (hash == NULL)
	return;
    hash_first(hash);
    while ((h = hash_next(hash))) {
	fv = (fvdb_entry *) h;
	storeAppendPrintf(e, "%9d %s\n", fv->n, hashKeyStr(&fv->hash));
    }
}

static void
fvdbDumpVia(StoreEntry * e)
{
    fvdbDumpTable(e, via_table);
}

static void
fvdbDumpForw(StoreEntry * e)
{
    fvdbDumpTable(e, forw_table);
}

static
void
fvdbFreeEntry(void *data)
{
    fvdb_entry *fv = data;
    xfree(fv->hash.key);
    xfree(fv);
}

static void
fvdbClear(void)
{
    hashFreeItems(via_table, fvdbFreeEntry);
    hashFreeMemory(via_table);
    via_table = hash_create((HASHCMP *) strcmp, 977, hash4);
    hashFreeItems(forw_table, fvdbFreeEntry);
    hashFreeMemory(forw_table);
    forw_table = hash_create((HASHCMP *) strcmp, 977, hash4);
}

#endif

#if MULTICAST_MISS_STREAM
/*
 * From http://www.io.com/~paulhart/game/algorithms/tea.html
 *
 * size of 'ibuf' must be a multiple of 2.
 * size of 'key' must be 4.
 * 'ibuf' is modified in place, encrypted data is written in
 * network byte order.
 */
static void
mcast_encode(unsigned int *ibuf, size_t isize, const unsigned int *key)
{
    unsigned int y;
    unsigned int z;
    unsigned int sum;
    const unsigned int delta = 0x9e3779b9;
    unsigned int n = 32;
    const unsigned int k0 = htonl(key[0]);
    const unsigned int k1 = htonl(key[1]);
    const unsigned int k2 = htonl(key[2]);
    const unsigned int k3 = htonl(key[3]);
    int i;
    for (i = 0; i < isize; i += 2) {
	y = htonl(ibuf[i]);
	z = htonl(ibuf[i + 1]);
	sum = 0;
	for (n = 32; n; n--) {
	    sum += delta;
	    y += (z << 4) + (k0 ^ z) + (sum ^ (z >> 5)) + k1;
	    z += (y << 4) + (k2 ^ y) + (sum ^ (y >> 5)) + k3;
	}
	ibuf[i] = htonl(y);
	ibuf[i + 1] = htonl(z);
    }
}

#endif

#if HEADERS_LOG
void
headersLog(int cs, int pq, method_t m, void *data)
{
    HttpReply *rep;
    request_t *req;
    unsigned short magic = 0;
    unsigned char M = (unsigned char) m;
    unsigned short S;
    char *hmask;
    int ccmask = 0;
    if (0 == pq) {
	/* reply */
	rep = data;
	req = NULL;
	magic = 0x0050;
	hmask = rep->header.mask;
	if (rep->cache_control)
	    ccmask = rep->cache_control->mask;
    } else {
	/* request */
	req = data;
	rep = NULL;
	magic = 0x0051;
	hmask = req->header.mask;
	if (req->cache_control)
	    ccmask = req->cache_control->mask;
    }
    if (0 == cs) {
	/* client */
	magic |= 0x4300;
    } else {
	/* server */
	magic |= 0x5300;
    }
    magic = htons(magic);
    ccmask = htonl(ccmask);
    if (0 == pq)
	S = (unsigned short) rep->sline.status;
    else
	S = (unsigned short) HTTP_STATUS_NONE;
    logfileWrite(headerslog, &magic, sizeof(magic));
    logfileWrite(headerslog, &M, sizeof(M));
    logfileWrite(headerslog, &S, sizeof(S));
    logfileWrite(headerslog, hmask, sizeof(HttpHeaderMask));
    logfileWrite(headerslog, &ccmask, sizeof(int));
    logfileFlush(headerslog);
}

#endif

void
accessLogFreeMemory(AccessLogEntry * aLogEntry)
{
    safe_free(aLogEntry->headers.request);
    safe_free(aLogEntry->headers.reply);
    safe_free(aLogEntry->cache.authuser);
}

int
logTypeIsATcpHit(log_type code)
{
    /* this should be a bitmap for better optimization */
    if (code == LOG_TCP_HIT)
	return 1;
    if (code == LOG_TCP_IMS_HIT)
	return 1;
    if (code == LOG_TCP_REFRESH_FAIL_HIT)
	return 1;
    if (code == LOG_TCP_REFRESH_HIT)
	return 1;
    if (code == LOG_TCP_NEGATIVE_HIT)
	return 1;
    if (code == LOG_TCP_MEM_HIT)
	return 1;
    if (code == LOG_TCP_OFFLINE_HIT)
	return 1;
    return 0;
}

