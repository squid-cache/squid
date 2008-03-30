
/*
 * $Id: access_log.cc,v 1.128 2007/08/13 18:25:14 hno Exp $
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
#include "AccessLogEntry.h"

// Store.h Required by configuration directives parsing/dumping only
#include "Store.h"

#include "ACLChecklist.h"

#include "HttpReply.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "SquidTime.h"
#include "CacheManager.h"

static void accessLogSquid(AccessLogEntry * al, Logfile * logfile);
static void accessLogCommon(AccessLogEntry * al, Logfile * logfile);
static void accessLogCustom(AccessLogEntry * al, customlog * log);
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
        "TCP_REFRESH_UNMODIFIED",
        "TCP_REFRESH_FAIL",
        "TCP_REFRESH_MODIFIED",
        "TCP_CLIENT_REFRESH_MISS",
        "TCP_IMS_HIT",
        "TCP_SWAPFAIL_MISS",
        "TCP_NEGATIVE_HIT",
        "TCP_MEM_HIT",
        "TCP_DENIED",
        "TCP_DENIED_REPLY",
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

typedef struct
{
    hash_link hash;
    int n;
}

fvdb_entry;
static hash_table *via_table = NULL;
static hash_table *forw_table = NULL;
static void fvdbInit();
static void fvdbDumpTable(StoreEntry * e, hash_table * hash);
static void fvdbCount(hash_table * hash, const char *key);
static OBJH fvdbDumpVia;
static OBJH fvdbDumpForw;
static FREE fvdbFreeEntry;
static void fvdbClear(void);
static void fvdbRegisterWithCacheManager(CacheManager & manager);
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
                    || c == '%'
#if OLD_LOG_MIME
                    || c == '"'
                    || c == '#'
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
                   || c == '%'
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

    if (name[0] == '\0')
        return NULL;

    return username_quote(name);
}

static char *
log_quoted_string(const char *str)
{
    char *out = (char *)xmalloc(strlen(str) * 2 + 1);
    char *p = out;

    while (*str) {
        int l = strcspn(str, "\"\\\r\n\t");
        memcpy(p, str, l);
        str += l;
        p += l;

        switch (*str) {

        case '\0':
            break;

        case '\r':
            *p++ = '\\';
            *p++ = 'r';
            str++;
            break;

        case '\n':
            *p++ = '\\';
            *p++ = 'n';
            str++;
            break;

        case '\t':
            *p++ = '\\';
            *p++ = 't';
            str++;
            break;

        default:
            *p++ = '\\';
            *p++ = *str;
            str++;
            break;
        }
    }

    *p++ = '\0';
    return out;
}

/*
 * Bytecodes for the configureable logformat stuff
 */
typedef enum {
    LFT_NONE,			/* dummy */
    LFT_STRING,

    LFT_CLIENT_IP_ADDRESS,
    LFT_CLIENT_FQDN,
    LFT_CLIENT_PORT,

    /*LFT_SERVER_IP_ADDRESS, */
    LFT_SERVER_IP_OR_PEER_NAME,
    /*LFT_SERVER_PORT, */

    LFT_LOCAL_IP,
    LFT_LOCAL_PORT,
    /*LFT_LOCAL_NAME, */

    LFT_TIME_SECONDS_SINCE_EPOCH,
    LFT_TIME_SUBSECOND,
    LFT_TIME_LOCALTIME,
    LFT_TIME_GMT,
    LFT_TIME_TO_HANDLE_REQUEST,

    LFT_REQUEST_HEADER,
    LFT_REQUEST_HEADER_ELEM,
    LFT_REQUEST_ALL_HEADERS,

    LFT_REPLY_HEADER,
    LFT_REPLY_HEADER_ELEM,
    LFT_REPLY_ALL_HEADERS,

    LFT_USER_NAME,
    LFT_USER_LOGIN,
    LFT_USER_IDENT,
    /*LFT_USER_REALM, */
    /*LFT_USER_SCHEME, */
    LFT_USER_EXTERNAL,

    LFT_HTTP_CODE,
    /*LFT_HTTP_STATUS, */

    LFT_SQUID_STATUS,
    /*LFT_SQUID_ERROR, */
    LFT_SQUID_HIERARCHY,

    LFT_MIME_TYPE,

    LFT_REQUEST_METHOD,
    LFT_REQUEST_URI,
    LFT_REQUEST_URLPATH,
    /*LFT_REQUEST_QUERY, * // * this is not needed. see strip_query_terms */
    LFT_REQUEST_VERSION,

    /*LFT_REQUEST_SIZE_TOTAL, */
    /*LFT_REQUEST_SIZE_LINE, */
    /*LFT_REQUEST_SIZE_HEADERS, */
    /*LFT_REQUEST_SIZE_BODY, */
    /*LFT_REQUEST_SIZE_BODY_NO_TE, */

    LFT_REPLY_SIZE_TOTAL,
    LFT_REPLY_HIGHOFFSET,
    LFT_REPLY_OBJECTSIZE,
    /*LFT_REPLY_SIZE_LINE, */
    /*LFT_REPLY_SIZE_HEADERS, */
    /*LFT_REPLY_SIZE_BODY, */
    /*LFT_REPLY_SIZE_BODY_NO_TE, */

    LFT_TAG,
    LFT_EXT_LOG,

    LFT_PERCENT			/* special string cases for escaped chars */
} logformat_bcode_t;

enum log_quote {
    LOG_QUOTE_NONE = 0,
    LOG_QUOTE_QUOTES,
    LOG_QUOTE_BRAKETS,
    LOG_QUOTE_URL,
    LOG_QUOTE_RAW
};

struct _logformat_token
{
    logformat_bcode_t type;
    union {
        char *string;

        struct {
            char *header;
            char *element;
            char separator;
        }

        header;
        char *timespec;
    } data;
    unsigned char width;
    unsigned char precision;

    enum log_quote quote;

unsigned int left:
    1;

unsigned int space:
    1;

unsigned int zero:
    1;
    int divisor;
    logformat_token *next;	/* todo: move from linked list to array */
};

struct logformat_token_table_entry
{
    const char *config;
    logformat_bcode_t token_type;
    int options;
};

struct logformat_token_table_entry logformat_token_table[] =
    {

        {">a", LFT_CLIENT_IP_ADDRESS},

        { ">p", LFT_CLIENT_PORT},
        {">A", LFT_CLIENT_FQDN},

        /*{ "<a", LFT_SERVER_IP_ADDRESS }, */
        /*{ "<p", LFT_SERVER_PORT }, */
        {"<A", LFT_SERVER_IP_OR_PEER_NAME},

	/* {"oa", LFT_OUTGOING_IP}, */
	/* {"ot", LFT_OUTGOING_TOS}, */

        {"la", LFT_LOCAL_IP},
        {"lp", LFT_LOCAL_PORT},
        /*{ "lA", LFT_LOCAL_NAME }, */

        {"ts", LFT_TIME_SECONDS_SINCE_EPOCH},
        {"tu", LFT_TIME_SUBSECOND},
        {"tl", LFT_TIME_LOCALTIME},
        {"tg", LFT_TIME_GMT},
        {"tr", LFT_TIME_TO_HANDLE_REQUEST},

        {">h", LFT_REQUEST_HEADER},
        {">h", LFT_REQUEST_ALL_HEADERS},
        {"<h", LFT_REPLY_HEADER},
        {"<h", LFT_REPLY_ALL_HEADERS},

        {"un", LFT_USER_NAME},
        {"ul", LFT_USER_LOGIN},
        /*{ "ur", LFT_USER_REALM }, */
        /*{ "us", LFT_USER_SCHEME }, */
        {"ui", LFT_USER_IDENT},
        {"ue", LFT_USER_EXTERNAL},

        {"Hs", LFT_HTTP_CODE},
        /*{ "Ht", LFT_HTTP_STATUS }, */

        {"Ss", LFT_SQUID_STATUS},
        /*{ "Se", LFT_SQUID_ERROR }, */
        {"Sh", LFT_SQUID_HIERARCHY},

        {"mt", LFT_MIME_TYPE},

        {"rm", LFT_REQUEST_METHOD},
        {"ru", LFT_REQUEST_URI},	/* doesn't include the query-string */
        {"rp", LFT_REQUEST_URLPATH},	/* doesn't include the host */
        /* { "rq", LFT_REQUEST_QUERY }, * /     / * the query-string, INCLUDING the leading ? */
        {">v", LFT_REQUEST_VERSION},
        {"rv", LFT_REQUEST_VERSION},

        /*{ ">st", LFT_REQUEST_SIZE_TOTAL }, */
        /*{ ">sl", LFT_REQUEST_SIZE_LINE }, * / / * the request line "GET ... " */
        /*{ ">sh", LFT_REQUEST_SIZE_HEADERS }, */
        /*{ ">sb", LFT_REQUEST_SIZE_BODY }, */
        /*{ ">sB", LFT_REQUEST_SIZE_BODY_NO_TE }, */

        {"<st", LFT_REPLY_SIZE_TOTAL},
        {"<sH", LFT_REPLY_HIGHOFFSET},
        {"<sS", LFT_REPLY_OBJECTSIZE},
        /*{ "<sl", LFT_REPLY_SIZE_LINE }, * /   / * the reply line (protocol, code, text) */
        /*{ "<sh", LFT_REPLY_SIZE_HEADERS }, */
        /*{ "<sb", LFT_REPLY_SIZE_BODY }, */
        /*{ "<sB", LFT_REPLY_SIZE_BODY_NO_TE }, */

        {"et", LFT_TAG},
        {"ea", LFT_EXT_LOG},

        {"%", LFT_PERCENT},

        {NULL, LFT_NONE}		/* this must be last */
    };

static void
accessLogCustom(AccessLogEntry * al, customlog * log)
{
    logformat *lf;
    Logfile *logfile;
    logformat_token *fmt;
    static MemBuf mb;
    char tmp[1024];
    String sb;

    mb.reset();

    lf = log->logFormat;
    logfile = log->logfile;

    for (fmt = lf->format; fmt != NULL; fmt = fmt->next) {	/* for each token */
        const char *out = NULL;
        int quote = 0;
        long int outint = 0;
        int doint = 0;
        int dofree = 0;
        int64_t outoff = 0;
        int dooff = 0;

        switch (fmt->type) {

        case LFT_NONE:
            out = "";
            break;

        case LFT_STRING:
            out = fmt->data.string;
            break;

        case LFT_CLIENT_IP_ADDRESS:
            out = inet_ntoa(al->cache.caddr);
            break;

        case LFT_CLIENT_FQDN:
            out = fqdncache_gethostbyaddr(al->cache.caddr, FQDN_LOOKUP_IF_MISS);

            if (!out)
                out = inet_ntoa(al->cache.caddr);

            break;

        case LFT_CLIENT_PORT:
	    if (al->request) {
		outint = al->request->client_port;
		doint = 1;
	    }
	    break;

            /* case LFT_SERVER_IP_ADDRESS: */

        case LFT_SERVER_IP_OR_PEER_NAME:
            out = al->hier.host;

            break;

            /* case LFT_SERVER_PORT: */

        case LFT_LOCAL_IP:
            if (al->request)
                out = inet_ntoa(al->request->my_addr);

            break;

        case LFT_LOCAL_PORT:
            if (al->request) {
                outint = al->request->my_port;
                doint = 1;
            }

            break;

        case LFT_TIME_SECONDS_SINCE_EPOCH:
	    // some platforms store time in 32-bit, some 64-bit...
            outoff = static_cast<int64_t>(current_time.tv_sec);
            dooff = 1;
            break;

        case LFT_TIME_SUBSECOND:
            outint = current_time.tv_usec / fmt->divisor;
            doint = 1;
            break;


        case LFT_TIME_LOCALTIME:

        case LFT_TIME_GMT: {
                const char *spec;

                struct tm *t;
                spec = fmt->data.timespec;

                if (!spec)
                    spec = "%d/%b/%Y %H:%M:%S";

                if (fmt->type == LFT_TIME_LOCALTIME)
                    t = localtime(&squid_curtime);
                else
                    t = gmtime(&squid_curtime);

                strftime(tmp, sizeof(tmp), spec, t);

                out = tmp;
            }

            break;

        case LFT_TIME_TO_HANDLE_REQUEST:
            outint = al->cache.msec;
            doint = 1;
            break;

        case LFT_REQUEST_HEADER:

            if (al->request)
                sb = al->request->header.getByName(fmt->data.header.header);

            out = sb.buf();

            quote = 1;

            break;

        case LFT_REPLY_HEADER:
            if (al->reply)
                sb = al->reply->header.getByName(fmt->data.header.header);

            out = sb.buf();

            quote = 1;

            break;

        case LFT_REQUEST_HEADER_ELEM:
            if (al->request)
                sb = al->request->header.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator);

            out = sb.buf();

            quote = 1;

            break;

        case LFT_REPLY_HEADER_ELEM:
            if (al->reply)
                sb = al->reply->header.getByNameListMember(fmt->data.header.header, fmt->data.header.element, fmt->data.header.separator);

            out = sb.buf();

            quote = 1;

            break;

        case LFT_REQUEST_ALL_HEADERS:
            out = al->headers.request;

            quote = 1;

            break;

        case LFT_REPLY_ALL_HEADERS:
            out = al->headers.reply;

            quote = 1;

            break;

        case LFT_USER_NAME:
            out = accessLogFormatName(al->cache.authuser);

            if (!out)
                out = accessLogFormatName(al->cache.extuser);

#if USE_SSL

            if (!out)
                out = accessLogFormatName(al->cache.ssluser);

#endif

            if (!out)
                out = accessLogFormatName(al->cache.rfc931);

            dofree = 1;

            break;

        case LFT_USER_LOGIN:
            out = accessLogFormatName(al->cache.authuser);

            dofree = 1;

            break;

        case LFT_USER_IDENT:
            out = accessLogFormatName(al->cache.rfc931);

            dofree = 1;

            break;

        case LFT_USER_EXTERNAL:
            out = accessLogFormatName(al->cache.extuser);

            dofree = 1;

            break;

            /* case LFT_USER_REALM: */
            /* case LFT_USER_SCHEME: */

        case LFT_HTTP_CODE:
            outint = al->http.code;

            doint = 1;

            break;

            /* case LFT_HTTP_STATUS:
             *           out = statusline->text;
             *     quote = 1;
             *     break;
             */

        case LFT_SQUID_STATUS:
            out = log_tags[al->cache.code];

            break;

            /* case LFT_SQUID_ERROR: */

        case LFT_SQUID_HIERARCHY:
            if (al->hier.ping.timedout)
                mb.append("TIMEOUT_", 8);

            out = hier_strings[al->hier.code];

            break;

        case LFT_MIME_TYPE:
            out = al->http.content_type;

            break;

        case LFT_REQUEST_METHOD:
            out = al->_private.method_str;

            break;

        case LFT_REQUEST_URI:
            out = al->url;

            break;

        case LFT_REQUEST_URLPATH:
	    if (al->request) {
		out = al->request->urlpath.buf();
		quote = 1;
	    }
            break;

        case LFT_REQUEST_VERSION:
            snprintf(tmp, sizeof(tmp), "%d.%d", (int) al->http.version.major, (int) al->http.version.minor);

            out = tmp;

            break;

            /*case LFT_REQUEST_SIZE_TOTAL: */
            /*case LFT_REQUEST_SIZE_LINE: */
            /*case LFT_REQUEST_SIZE_HEADERS: */
            /*case LFT_REQUEST_SIZE_BODY: */
            /*case LFT_REQUEST_SIZE_BODY_NO_TE: */

        case LFT_REPLY_SIZE_TOTAL:
            outoff = al->cache.size;

            dooff = 1;

            break;

        case LFT_REPLY_HIGHOFFSET:
            outoff = al->cache.highOffset;

            dooff = 1;

            break;

        case LFT_REPLY_OBJECTSIZE:
            outoff = al->cache.objectSize;

            dooff = 1;

            break;

            /*case LFT_REPLY_SIZE_LINE: */
            /*case LFT_REPLY_SIZE_HEADERS: */
            /*case LFT_REPLY_SIZE_BODY: */
            /*case LFT_REPLY_SIZE_BODY_NO_TE: */

        case LFT_TAG:
            if (al->request)
                out = al->request->tag.buf();

            quote = 1;

            break;

        case LFT_EXT_LOG:
            if (al->request)
                out = al->request->extacl_log.buf();

            quote = 1;

            break;

        case LFT_PERCENT:
            out = "%";

            break;
        }

	if (dooff) {
            snprintf(tmp, sizeof(tmp), "%0*" PRId64, fmt->zero ? (int) fmt->width : 0, outoff);
            out = tmp;
	    
        } else if (doint) {
            snprintf(tmp, sizeof(tmp), "%0*ld", fmt->zero ? (int) fmt->width : 0, outint);
            out = tmp;
        }

        if (out && *out) {
            if (quote || fmt->quote != LOG_QUOTE_NONE) {
                char *newout = NULL;
                int newfree = 0;

                switch (fmt->quote) {

                case LOG_QUOTE_NONE:
                    newout = rfc1738_escape_unescaped(out);
                    break;

                case LOG_QUOTE_QUOTES:
                    newout = log_quoted_string(out);
                    newfree = 1;
                    break;

                case LOG_QUOTE_BRAKETS:
                    newout = log_quote(out);
                    newfree = 1;
                    break;

                case LOG_QUOTE_URL:
                    newout = rfc1738_escape(out);
                    break;

                case LOG_QUOTE_RAW:
                    break;
                }

                if (newout) {
                    if (dofree)
                        safe_free(out);

                    out = newout;

                    dofree = newfree;
                }
            }

            if (fmt->width) {
                if (fmt->left)
                    mb.Printf("%-*s", (int) fmt->width, out);
                else
                    mb.Printf("%*s", (int) fmt->width, out);
            } else
                mb.append(out, strlen(out));
        } else {
            mb.append("-", 1);
        }

        if (fmt->space)
            mb.append(" ", 1);

        sb.clean();

        if (dofree)
            safe_free(out);
    }

    logfilePrintf(logfile, "%s\n", mb.buf);
}

/* parses a single token. Returns the token length in characters,
 * and fills in the lt item with the token information.
 * def is for sure null-terminated
 */
static int
accessLogGetNewLogFormatToken(logformat_token * lt, char *def, enum log_quote *quote)
{
    char *cur = def;

    struct logformat_token_table_entry *lte;
    int l;

    memset(lt, 0, sizeof(*lt));
    l = strcspn(cur, "%");

    if (l > 0) {
        char *cp;
        /* it's a string for sure, until \0 or the next % */
        cp = (char *)xmalloc(l + 1);
        xstrncpy(cp, cur, l + 1);
        lt->type = LFT_STRING;
        lt->data.string = cp;

        while (l > 0) {
            switch(*cur) {

            case '"':

                if (*quote == LOG_QUOTE_NONE)
                    *quote = LOG_QUOTE_QUOTES;
                else if (*quote == LOG_QUOTE_QUOTES)
                    *quote = LOG_QUOTE_NONE;

                break;

            case '[':
                if (*quote == LOG_QUOTE_NONE)
                    *quote = LOG_QUOTE_BRAKETS;

                break;

            case ']':
                if (*quote == LOG_QUOTE_BRAKETS)
                    *quote = LOG_QUOTE_NONE;

                break;
            }

            cur++;
            l--;
        }

        goto done;
    }

    if (!*cur)
        goto done;

    cur++;

    switch (*cur) {

    case '"':
        lt->quote = LOG_QUOTE_QUOTES;
        cur++;
        break;

    case '\'':
        lt->quote = LOG_QUOTE_RAW;
        cur++;
        break;

    case '[':
        lt->quote = LOG_QUOTE_BRAKETS;
        cur++;
        break;

    case '#':
        lt->quote = LOG_QUOTE_URL;
        cur++;
        break;

    default:
        lt->quote = *quote;
        break;
    }

    if (*cur == '-') {
        lt->left = 1;
        cur++;
    }

    if (*cur == '0') {
        lt->zero = 1;
        cur++;
    }

    if (xisdigit(*cur))
        lt->width = strtol(cur, &cur, 10);

    if (*cur == '.')
        lt->precision = strtol(cur + 1, &cur, 10);

    if (*cur == '{') {
        char *cp;
        cur++;
        l = strcspn(cur, "}");
        cp = (char *)xmalloc(l + 1);
        xstrncpy(cp, cur, l + 1);
        lt->data.string = cp;
        cur += l;

        if (*cur == '}')
            cur++;
    }

    lt->type = LFT_NONE;

    for (lte = logformat_token_table; lte->config != NULL; lte++) {
        if (strncmp(lte->config, cur, strlen(lte->config)) == 0) {
            lt->type = lte->token_type;
            cur += strlen(lte->config);
            break;
        }
    }

    if (lt->type == LFT_NONE) {
        fatalf("Can't parse configuration token: '%s'\n",
               def);
    }

    if (*cur == ' ') {
        lt->space = 1;
        cur++;
    }

done:

    switch (lt->type) {

    case LFT_REQUEST_HEADER:

    case LFT_REPLY_HEADER:

        if (lt->data.string) {
            char *header = lt->data.string;
            char *cp = strchr(header, ':');

            if (cp) {
                *cp++ = '\0';

                if (*cp == ',' || *cp == ';' || *cp == ':')
                    lt->data.header.separator = *cp++;
                else
                    lt->data.header.separator = ',';

                lt->data.header.element = cp;

                lt->type = (lt->type == LFT_REQUEST_HEADER) ?
                           LFT_REQUEST_HEADER_ELEM :
                           LFT_REPLY_HEADER_ELEM;
            }

            lt->data.header.header = header;
        } else {
            lt->type = (lt->type == LFT_REQUEST_HEADER) ?
                       LFT_REQUEST_ALL_HEADERS :
                       LFT_REPLY_ALL_HEADERS;
            Config.onoff.log_mime_hdrs = 1;
        }

        break;

    case LFT_CLIENT_FQDN:
        Config.onoff.log_fqdn = 1;
        break;

    case LFT_TIME_SUBSECOND:
        lt->divisor = 1000;

        if (lt->precision) {
            int i;
            lt->divisor = 1000000;

            for (i = lt->precision; i > 1; i--)
                lt->divisor /= 10;

            if (!lt->divisor)
                lt->divisor = 0;
        }

        break;

    default:
        break;
    }

    return (cur - def);
}

int
accessLogParseLogFormat(logformat_token ** fmt, char *def)
{
    char *cur, *eos;
    logformat_token *new_lt, *last_lt;
    enum log_quote quote = LOG_QUOTE_NONE;

    debugs(46, 2, "accessLogParseLogFormat: got definition '" << def << "'");

    /* very inefficent parser, but who cares, this needs to be simple */
    /* First off, let's tokenize, we'll optimize in a second pass.
     * A token can either be a %-prefixed sequence (usually a dynamic
     * token but it can be an escaped sequence), or a string. */
    cur = def;
    eos = def + strlen(def);
    *fmt = new_lt = last_lt = (logformat_token *)xmalloc(sizeof(logformat_token));
    cur += accessLogGetNewLogFormatToken(new_lt, cur, &quote);

    while (cur < eos) {
        new_lt = (logformat_token *)xmalloc(sizeof(logformat_token));
        last_lt->next = new_lt;
        last_lt = new_lt;
        cur += accessLogGetNewLogFormatToken(new_lt, cur, &quote);
    }

    return 1;
}

void
accessLogDumpLogFormat(StoreEntry * entry, const char *name, logformat * definitions)
{
    logformat_token *t;
    logformat *format;

    struct logformat_token_table_entry *te;
    debugs(46, 0, "accessLogDumpLogFormat called");

    for (format = definitions; format; format = format->next) {
        debugs(46, 0, "Dumping logformat definition for " << format->name);
        storeAppendPrintf(entry, "logformat %s ", format->name);

        for (t = format->format; t; t = t->next) {
            if (t->type == LFT_STRING)
                storeAppendPrintf(entry, "%s", t->data.string);
            else {
                char argbuf[256];
                char *arg = NULL;
                logformat_bcode_t type = t->type;

                switch (type) {
                    /* special cases */

                case LFT_STRING:
                    break;

                case LFT_REQUEST_HEADER_ELEM:

                case LFT_REPLY_HEADER_ELEM:

                    if (t->data.header.separator != ',')
                        snprintf(argbuf, sizeof(argbuf), "%s:%c%s", t->data.header.header, t->data.header.separator, t->data.header.element);
                    else
                        snprintf(argbuf, sizeof(argbuf), "%s:%s", t->data.header.header, t->data.header.element);

                    arg = argbuf;

                    type = (type == LFT_REQUEST_HEADER_ELEM) ?
                           LFT_REQUEST_HEADER :
                           LFT_REPLY_HEADER;

                    break;

                case LFT_REQUEST_ALL_HEADERS:

                case LFT_REPLY_ALL_HEADERS:

                    type = (type == LFT_REQUEST_ALL_HEADERS) ?
                           LFT_REQUEST_HEADER :
                           LFT_REPLY_HEADER;

                    break;

                default:
                    if (t->data.string)
                        arg = t->data.string;

                    break;
                }

                entry->append("%", 1);

                switch (t->quote) {

                case LOG_QUOTE_QUOTES:
                    entry->append("\"", 1);
                    break;

                case LOG_QUOTE_BRAKETS:
                    entry->append("[", 1);
                    break;

                case LOG_QUOTE_URL:
                    entry->append("#", 1);
                    break;

                case LOG_QUOTE_RAW:
                    entry->append("'", 1);
                    break;

                case LOG_QUOTE_NONE:
                    break;
                }

                if (t->left)
                    entry->append("-", 1);

                if (t->zero)
                    entry->append("0", 1);

                if (t->width)
                    storeAppendPrintf(entry, "%d", (int) t->width);

                if (t->precision)
                    storeAppendPrintf(entry, ".%d", (int) t->precision);

                if (arg)
                    storeAppendPrintf(entry, "{%s}", arg);

                for (te = logformat_token_table; te->config != NULL; te++) {
                    if (te->token_type == t->type) {
                        storeAppendPrintf(entry, "%s", te->config);
                        break;
                    }
                }

                if (t->space)
                    entry->append(" ", 1);

                assert(te->config != NULL);
            }
        }

        entry->append("\n", 1);
    }

}

void
accessLogFreeLogFormat(logformat_token ** tokens)
{
    while (*tokens) {
        logformat_token *token = *tokens;
        *tokens = token->next;
        safe_free(token->data.string);
        xfree(token);
    }
}

static void
accessLogSquid(AccessLogEntry * al, Logfile * logfile)
{
    const char *client = NULL;
    const char *user = NULL;

    if (Config.onoff.log_fqdn)
        client = fqdncache_gethostbyaddr(al->cache.caddr, FQDN_LOOKUP_IF_MISS);

    if (client == NULL)
        client = inet_ntoa(al->cache.caddr);

    user = accessLogFormatName(al->cache.authuser);

    if (!user)
        user = accessLogFormatName(al->cache.extuser);

#if USE_SSL

    if (!user)
        user = accessLogFormatName(al->cache.ssluser);

#endif

    if (!user)
        user = accessLogFormatName(al->cache.rfc931);

    if (user && !*user)
        safe_free(user);

    if (!Config.onoff.log_mime_hdrs) {
        logfilePrintf(logfile, "%9ld.%03d %6d %s %s/%03d %"PRId64" %s %s %s %s%s/%s %s",
                      (long int) current_time.tv_sec,
                      (int) current_time.tv_usec / 1000,
                      al->cache.msec,
                      client,
                      log_tags[al->cache.code],
                      al->http.code,
                      al->cache.size,
                      al->_private.method_str,
                      al->url,
                      user ? user : dash_str,
                      al->hier.ping.timedout ? "TIMEOUT_" : "",
                      hier_strings[al->hier.code],
                      al->hier.host,
                      al->http.content_type);
    } else {
        char *ereq = log_quote(al->headers.request);
        char *erep = log_quote(al->headers.reply);
        logfilePrintf(logfile, "%9ld.%03d %6d %s %s/%03d %"PRId64" %s %s %s %s%s/%s %s [%s] [%s]",
                      (long int) current_time.tv_sec,
                      (int) current_time.tv_usec / 1000,
                      al->cache.msec,
                      client,
                      log_tags[al->cache.code],
                      al->http.code,
                      al->cache.size,
                      al->_private.method_str,
                      al->url,
                      user ? user : dash_str,
                      al->hier.ping.timedout ? "TIMEOUT_" : "",
                      hier_strings[al->hier.code],
                      al->hier.host,
                      al->http.content_type,
                      ereq,
                      erep);
        safe_free(ereq);
        safe_free(erep);
    }
    logfilePrintf(logfile, "\n");
    safe_free(user);
}

static void
accessLogCommon(AccessLogEntry * al, Logfile * logfile)
{
    const char *client = NULL;
    char *user1 = NULL, *user2 = NULL;

    if (Config.onoff.log_fqdn)
        client = fqdncache_gethostbyaddr(al->cache.caddr, 0);

    if (client == NULL)
        client = inet_ntoa(al->cache.caddr);

    user1 = accessLogFormatName(al->cache.authuser);

    user2 = accessLogFormatName(al->cache.rfc931);

    logfilePrintf(logfile, "%s %s %s [%s] \"%s %s HTTP/%d.%d\" %d %"PRId64" %s:%s",
                  client,
                  user2 ? user2 : dash_str,
                  user1 ? user1 : dash_str,
                  mkhttpdlogtime(&squid_curtime),
                  al->_private.method_str,
                  al->url,
                  al->http.version.major, al->http.version.minor,
                  al->http.code,
                  al->cache.size,
                  log_tags[al->cache.code],
                  hier_strings[al->hier.code]);

    safe_free(user1);

    safe_free(user2);

    if (Config.onoff.log_mime_hdrs) {
        char *ereq = log_quote(al->headers.request);
        char *erep = log_quote(al->headers.reply);
        logfilePrintf(logfile, " [%s] [%s]\n", ereq, erep);
        safe_free(ereq);
        safe_free(erep);
    } else {
        logfilePrintf(logfile, "\n");
    }

}

void
accessLogLog(AccessLogEntry * al, ACLChecklist * checklist)
{
    customlog *log;

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

    for (log = Config.Log.accesslogs; log; log = log->next) {
        if(checklist && log->aclList && !checklist->matchAclListFast(log->aclList))
            continue;

        switch (log->type) {

        case CLF_AUTO:

            if (Config.onoff.common_log)
                accessLogCommon(al, log->logfile);
            else
                accessLogSquid(al, log->logfile);

            break;

        case CLF_SQUID:
            accessLogSquid(al, log->logfile);

            break;

        case CLF_COMMON:
            accessLogCommon(al, log->logfile);

            break;

        case CLF_CUSTOM:
            accessLogCustom(al, log);

            break;

        case CLF_NONE:
            goto last;

        default:
            fatalf("Unknown log format %d\n", log->type);

            break;
        }

        logfileFlush(log->logfile);

        if (!checklist)
            break;
    }

last:
    (void)0; /* NULL statement for label */

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
    customlog *log;
#if FORW_VIA_DB

    fvdbClear();
#endif

    for (log = Config.Log.accesslogs; log; log = log->next) {
        if (log->logfile) {
            logfileRotate(log->logfile);
        }
    }

#if HEADERS_LOG

    logfileRotate(headerslog);

#endif
}

void
accessLogClose(void)
{
    customlog *log;

    for (log = Config.Log.accesslogs; log; log = log->next) {
        if (log->logfile) {
            logfileClose(log->logfile);
            log->logfile = NULL;
        }
    }

#if HEADERS_LOG

    logfileClose(headerslog);

    headerslog = NULL;

#endif
}

HierarchyLogEntry::HierarchyLogEntry() :
        code(HIER_NONE),
        cd_lookup(LOOKUP_NONE),
        n_choices(0),
        n_ichoices(0)
{
    memset(host, '\0', SQUIDHOSTNAMELEN);
    memset(cd_host, '\0', SQUIDHOSTNAMELEN);

    peer_select_start.tv_sec =0;
    peer_select_start.tv_usec =0;

    store_complete_stop.tv_sec =0;
    store_complete_stop.tv_usec =0;
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
    customlog *log;
    assert(sizeof(log_tags) == (LOG_TYPE_MAX + 1) * sizeof(char *));

    for (log = Config.Log.accesslogs; log; log = log->next) {
        if (log->type == CLF_NONE)
            continue;

        log->logfile = logfileOpen(log->filename, MAX_URL << 1, 1);

        LogfileStatus = LOG_ENABLE;
    }

#if HEADERS_LOG

    headerslog = logfileOpen("/usr/local/squid/logs/headers.log", 512);

    assert(NULL != headerslog);

#endif
#if MULTICAST_MISS_STREAM

    if (Config.mcast_miss.addr.s_addr != no_addr.s_addr) {
        memset(&mcast_miss_to, '\0', sizeof(mcast_miss_to));
        mcast_miss_to.sin_family = AF_INET;
        mcast_miss_to.sin_port = htons(Config.mcast_miss.port);
        mcast_miss_to.sin_addr.s_addr = Config.mcast_miss.addr.s_addr;
        mcast_miss_fd = comm_open(SOCK_DGRAM,
                                  IPPROTO_UDP,
                                  Config.Addrs.udp_incoming,
                                  Config.mcast_miss.port,
                                  COMM_NONBLOCKING,
                                  "Multicast Miss Stream");

        if (mcast_miss_fd < 0)
            fatal("Cannot open Multicast Miss Stream Socket");

        debugs(46, 1, "Multicast Miss Stream Socket opened on FD " << mcast_miss_fd);

        mcastSetTtl(mcast_miss_fd, Config.mcast_miss.ttl);

        if (strlen(Config.mcast_miss.encode_key) < 16)
            fatal("mcast_encode_key is too short, must be 16 characters");
    }

#endif
#if FORW_VIA_DB

    fvdbInit();

#endif
}

void
accessLogRegisterWithCacheManager(CacheManager & manager)
{
#if FORW_VIA_DB

    fvdbRegisterWithCacheManager(manager);

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
}

static void
fvdbRegisterWithCacheManager(CacheManager & manager)
{
    manager.registerAction("via_headers", "Via Request Headers", fvdbDumpVia, 0, 1);
    manager.registerAction("forw_headers", "X-Forwarded-For Request Headers",
                           fvdbDumpForw, 0, 1);
}

static void
fvdbCount(hash_table * hash, const char *key)
{
    fvdb_entry *fv;

    if (NULL == hash)
        return;

    fv = (fvdb_entry *)hash_lookup(hash, key);

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
    fvdb_entry *fv = static_cast <fvdb_entry *>(data);
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
headersLog(int cs, int pq, method_t method, void *data)
{
    HttpReply *rep;
    HttpRequest *req;
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

    HTTPMSGUNLOCK(aLogEntry->reply);
    HTTPMSGUNLOCK(aLogEntry->request);
}

int
logTypeIsATcpHit(log_type code)
{
    /* this should be a bitmap for better optimization */

    if (code == LOG_TCP_HIT)
        return 1;

    if (code == LOG_TCP_IMS_HIT)
        return 1;

    if (code == LOG_TCP_REFRESH_FAIL)
        return 1;

    if (code == LOG_TCP_REFRESH_UNMODIFIED)
        return 1;

    if (code == LOG_TCP_NEGATIVE_HIT)
        return 1;

    if (code == LOG_TCP_MEM_HIT)
        return 1;

    if (code == LOG_TCP_OFFLINE_HIT)
        return 1;

    return 0;
}

