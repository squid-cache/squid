
/*
 * $Id: access_log.cc,v 1.1 1997/06/21 02:36:47 wessels Exp $
 *
 * DEBUG: section 46    Access Log
 * AUTHOR: Duane Wessels
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

#define MAX_LINELEN (4096)
#define max(a,b)  ((a)>(b)? (a): (b))

static int LogfileStatus = LOG_DISABLE;
static int LogfileFD = -1;
static char LogfileName[SQUID_MAXPATHLEN];
#define LOG_BUF_SZ (MAX_URL<<2)
static char log_buf[LOG_BUF_SZ];

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

static char *
log_quote(const char *header)
{
    int c, i;
    char *buf, *buf_cursor;
    if (header == NULL) {
	buf = xcalloc(1, 1);
	*buf = '\0';
	return buf;
    }
    buf = xcalloc((strlen(header) * 3) + 1, 1);
    buf_cursor = buf;
    /*
     * We escape: \x00-\x1F"#%;<>?{}|\\\\^~`\[\]\x7F-\xFF 
     * which is the default escape list for the CPAN Perl5 URI module
     * modulo the inclusion of space (x40) to make the raw logs a bit
     * more readable.
     */
    while ((c = *(const unsigned char *) header++)) {
	if (c <= 0x1F
	    || c >= 0x7F
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
	    || c == '['
	    || c == ']') {
	    *buf_cursor++ = '%';
	    i = c * 2;
	    *buf_cursor++ = c2x[i];
	    *buf_cursor++ = c2x[i + 1];
	} else {
	    *buf_cursor++ = c;
	}
    }
    *buf_cursor = '\0';
    return buf;
}

static int
accessLogSquid(AccessLogEntry * al)
{
    const char *client = dash_str;
    if (Config.Log.log_fqdn)
	client = fqdncache_gethostbyaddr(al->cache.caddr, 0);
    if (client == NULL)
	client = inet_ntoa(al->cache.caddr);
    return snprintf(log_buf, LOG_BUF_SZ,
	"%9d.%03d %6d %s %s/%03d %d %s %s %s %s%s/%s %s\n",
	(int) current_time.tv_sec,
	(int) current_time.tv_usec / 1000,
	al->cache.msec,
	client,
	log_tags[al->cache.code],
	al->http.code,
	al->cache.size,
	al->private.method_str,
	al->url,
	al->cache.ident,
	al->hier.icp.timeout ? "TIMEOUT_" : "",
	hier_strings[al->hier.code],
	al->hier.host,
	al->http.content_type);
}

static int
accessLogCommon(AccessLogEntry * al)
{
    const char *client = dash_str;
    if (Config.Log.log_fqdn)
	client = fqdncache_gethostbyaddr(al->cache.caddr, 0);
    if (client == NULL)
	client = inet_ntoa(al->cache.caddr);
    return snprintf(log_buf, LOG_BUF_SZ,
	"%s %s - [%s] \"%s %s\" %d %d %s:%s\n",
	client,
	al->cache.ident,
	mkhttpdlogtime(&squid_curtime),
	al->private.method_str,
	al->url,
	al->http.code,
	al->cache.size,
	log_tags[al->cache.code],
	hier_strings[al->hier.code]);
}

void
accessLogLog(AccessLogEntry * al)
{
    int x;
    int l;
    if (LogfileStatus != LOG_ENABLE)
	return;
    if (al->url == NULL)
	al->url = dash_str;
    if (!al->http.content_type || *al->http.content_type == '\0')
	al->http.content_type = dash_str;
    if (!al->cache.ident || *al->cache.ident == '\0')
	al->cache.ident = dash_str;
    if (al->icp.opcode)
	al->private.method_str = IcpOpcodeStr[al->icp.opcode];
    else
	al->private.method_str = RequestMethodStr[al->http.method];
    if (Config.commonLogFormat)
	l = accessLogCommon(al);
    else
	l = accessLogSquid(al);
    if (Config.logMimeHdrs) {
	char *ereq = log_quote(al->headers.request);
	char *erep = log_quote(al->headers.reply);
	if (LOG_BUF_SZ - l > 0)
	    l += snprintf(log_buf + l, LOG_BUF_SZ - l, " [%s] [%s]\n",
		ereq, erep);
	safe_free(ereq);
	safe_free(erep);
    }
    x = file_write(LogfileFD,
	xstrdup(log_buf),
	l,
	NULL,
	NULL,
	xfree);
    if (x != DISK_OK)
	debug(46, 1) ("log_append: File write failed.\n");
}

void
accessLogRotate(void)
{
    int i;
    LOCAL_ARRAY(char, from, MAXPATHLEN);
    LOCAL_ARRAY(char, to, MAXPATHLEN);
    char *fname = NULL;
    struct stat sb;
    if ((fname = LogfileName) == NULL)
	return;
#ifdef S_ISREG
    if (stat(fname, &sb) == 0)
	if (S_ISREG(sb.st_mode) == 0)
	    return;
#endif
    debug(46, 1) ("accessLogRotate: Rotating\n");
    /* Rotate numbers 0 through N up one */
    for (i = Config.Log.rotateNumber; i > 1;) {
	i--;
	snprintf(from, MAXPATHLEN, "%s.%d", fname, i - 1);
	snprintf(to, MAXPATHLEN, "%s.%d", fname, i);
	rename(from, to);
    }
    /* Rotate the current log to .0 */
    if (Config.Log.rotateNumber > 0) {
	snprintf(to, MAXPATHLEN, "%s.%d", fname, 0);
	rename(fname, to);
    }
    /* Close and reopen the log.  It may have been renamed "manually"
     * before HUP'ing us. */
    file_close(LogfileFD);
    LogfileFD = file_open(fname, O_WRONLY | O_CREAT, NULL, NULL);
    if (LogfileFD == DISK_ERROR) {
	debug(46, 0) ("accessLogRotate: Cannot open logfile: %s\n", fname);
	LogfileStatus = LOG_DISABLE;
	fatal("Cannot open logfile.");
    }
}

void
accessLogClose(void)
{
    file_close(LogfileFD);
}

void
accessLogOpen(const char *fname)
{
	assert(fname);
        xstrncpy(LogfileName, fname, SQUID_MAXPATHLEN);
        LogfileFD = file_open(LogfileName, O_WRONLY | O_CREAT, NULL, NULL);  
        if (LogfileFD == DISK_ERROR) {
            debug(50, 0) ("%s: %s\n", LogfileName, xstrerror());
            fatal("Cannot open logfile.");
        }
	LogfileStatus = LOG_ENABLE;
}

void
hierarchyNote(HierarchyLogEntry *hl,
    hier_code code,
    icp_ping_data * icpdata,
    const char *cache_host)
{
    assert(hl != NULL);
    hl->code = code;
    if (icpdata)
	hl->icp = *icpdata;
    xstrncpy(hl->host, cache_host, SQUIDHOSTNAMELEN);
    hl->icp.stop = current_time;
}
