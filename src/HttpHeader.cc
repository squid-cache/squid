
/*
 * $Id: HttpHeader.cc,v 1.28 1998/03/31 17:52:08 rousskov Exp $
 *
 * DEBUG: section 55    HTTP Header
 * AUTHOR: Alex Rousskov
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

/*
 * On naming conventions:
 * 
 * HTTP/1.1 defines message-header as 
 * 
 * message-header = field-name ":" [ field-value ] CRLF
 * field-name     = token
 * field-value    = *( field-content | LWS )
 * 
 * HTTP/1.1 does not give a name name a group of all message-headers in a message.
 * Squid 1.1 seems to refer to that group _plus_ start-line as "headers".
 * 
 * HttpHeader is an object that represents all message-headers in a message.
 * HttpHeader does not manage start-line.
 * 
 * HttpHeader is implemented as a collection of header "entries".
 * An entry is a (field_id, field_name, field_value) triplet.
 */


/* To-Do: fix parseCount stats @?@ @?@ */


/*
 * local types
 */

/* per header statistics */
typedef struct {
    const char *label;
    StatHist hdrUCountDistr;
    StatHist fieldTypeDistr;
    StatHist ccTypeDistr;
} HttpHeaderStat;


/* use this and only this to initialize HttpHeaderPos */
#define HttpHeaderInitPos (-1)


/*
 * local constants and vars
 */

/*
 * A table with major attributes for every known field. 
 * We calculate name lengths and reorganize this array on start up. 
 * After reorganization, field id can be used as an index to the table.
 */
static const HttpHeaderFieldAttrs HeadersAttrs[] =
{
    {"Accept", HDR_ACCEPT, ftStr},
    {"Accept-Charset", HDR_ACCEPT_CHARSET, ftStr},
    {"Accept-Encoding", HDR_ACCEPT_ENCODING, ftStr},
    {"Accept-Language", HDR_ACCEPT_LANGUAGE, ftStr},
    {"Accept-Ranges", HDR_ACCEPT_RANGES, ftStr},
    {"Age", HDR_AGE, ftInt},
    {"Cache-Control", HDR_CACHE_CONTROL, ftPCc},
    {"Connection", HDR_CONNECTION, ftStr},	/* for now */
    {"Content-Encoding", HDR_CONTENT_ENCODING, ftStr},
    {"Content-Length", HDR_CONTENT_LENGTH, ftInt},
    {"Content-MD5", HDR_CONTENT_MD5, ftStr},	/* for now */
    {"Content-Range", HDR_CONTENT_RANGE, ftPContRange},
    {"Content-Type", HDR_CONTENT_TYPE, ftStr},
    {"Date", HDR_DATE, ftDate_1123},
    {"ETag", HDR_ETAG, ftStr},	/* for now */
    {"Expires", HDR_EXPIRES, ftDate_1123},
    {"Host", HDR_HOST, ftStr},
    {"If-Modified-Since", HDR_IMS, ftDate_1123},
    {"Last-Modified", HDR_LAST_MODIFIED, ftDate_1123},
    {"Location", HDR_LOCATION, ftStr},
    {"Max-Forwards", HDR_MAX_FORWARDS, ftInt},
    {"Mime-Version", HDR_MIME_VERSION, ftStr}, /* for now */
    {"Proxy-Authenticate", HDR_PROXY_AUTHENTICATE, ftStr},
    {"Proxy-Connection", HDR_PROXY_CONNECTION, ftStr},
    {"Public", HDR_PUBLIC, ftStr},
    {"Range", HDR_RANGE, ftPRange},
    {"Retry-After", HDR_RETRY_AFTER, ftStr},	/* for now */
    {"Server", HDR_SERVER, ftStr},
    {"Set-Cookie", HDR_SET_COOKIE, ftStr},
    {"Upgrade", HDR_UPGRADE, ftStr},	/* for now */
    {"Warning", HDR_WARNING, ftStr},	/* for now */
    {"WWW-Authenticate", HDR_WWW_AUTHENTICATE, ftStr},
    {"X-Cache", HDR_X_CACHE, ftStr},
    {"Other:", HDR_OTHER, ftStr}	/* ':' will not allow matches */
};
static HttpHeaderFieldInfo *Headers = NULL;

/*
 * headers with field values defined as #(values) in HTTP/1.1
 * Headers that are currently not recognized, are commented out.
 */
static HttpHeaderMask ListHeadersMask; /* set run-time using  ListHeadersArr */
static http_hdr_type ListHeadersArr[] =
{
    HDR_ACCEPT,
    HDR_ACCEPT_CHARSET, HDR_ACCEPT_ENCODING, HDR_ACCEPT_LANGUAGE,
    HDR_ACCEPT_RANGES,
    /* HDR_ALLOW, */
    HDR_CACHE_CONTROL, HDR_CONNECTION,
    HDR_CONTENT_ENCODING,
    /* HDR_CONTENT_LANGUAGE, */
    /*  HDR_IF_MATCH, HDR_IF_NONE_MATCH, HDR_PRAGMA, */
    /* HDR_TRANSFER_ENCODING, */
    HDR_UPGRADE,		/* HDR_VARY, */
    /* HDR_VIA, HDR_WARNING, */
    HDR_WWW_AUTHENTICATE,
    /* HDR_EXPECT, HDR_TE, HDR_TRAILER */
};

static HttpHeaderMask ReplyHeadersMask; /* set run-time using ReplyHeaders */
static http_hdr_type ReplyHeadersArr[] =
{
    HDR_ACCEPT, HDR_ACCEPT_CHARSET, HDR_ACCEPT_ENCODING, HDR_ACCEPT_LANGUAGE,
    HDR_ACCEPT_RANGES, HDR_AGE, HDR_CACHE_CONTROL, HDR_CONTENT_LENGTH,
    HDR_CONTENT_MD5, HDR_CONTENT_RANGE, HDR_CONTENT_TYPE, HDR_DATE, HDR_ETAG,
    HDR_EXPIRES, HDR_LAST_MODIFIED, HDR_LOCATION, HDR_MAX_FORWARDS,
    HDR_MIME_VERSION, HDR_PUBLIC, HDR_RETRY_AFTER, HDR_SERVER, HDR_SET_COOKIE,
    HDR_UPGRADE, HDR_WARNING, HDR_PROXY_CONNECTION, HDR_X_CACHE, HDR_OTHER
};

static HttpHeaderMask RequestHeadersMask; /* set run-time using RequestHeaders */
static http_hdr_type RequestHeadersArr[] =
{
    HDR_RANGE, HDR_OTHER
};

/* header accounting */
static HttpHeaderStat HttpHeaderStats[] =
{
    {"reply"},
    {"request"},
    {"all"}
};
static int HttpHeaderStatCount = sizeof(HttpHeaderStats) / sizeof(*HttpHeaderStats);

/* global counters */
static int HeaderParsedCount = 0;
static int HeaderDestroyedCount = 0;
static int NonEmptyHeaderDestroyedCount = 0;
static int HeaderEntryParsedCount = 0;

/*
 * local routines
 */

#define assert_eid(id) assert((id) >= 0 && (id) < HDR_ENUM_END)

static HttpHeaderEntry *httpHeaderGetEntry(const HttpHeader * hdr, HttpHeaderPos * pos);
static void httpHeaderDelAt(HttpHeader * hdr, HttpHeaderPos pos);
/* static int httpHeaderDelById(HttpHeader * hdr, http_hdr_type id); */
static void httpHeaderAddEntry(HttpHeader * hdr, HttpHeaderEntry * e);
static String httpHeaderJoinEntries(const HttpHeader *hdr, http_hdr_type id);

static HttpHeaderEntry *httpHeaderEntryCreate(http_hdr_type id, const char *name, const char *value);
static void httpHeaderEntryDestroy(HttpHeaderEntry * e);
static HttpHeaderEntry *httpHeaderEntryParseCreate(const char *field_start, const char *field_end);
static HttpHeaderEntry *httpHeaderEntryClone(const HttpHeaderEntry * e);
static void httpHeaderNoteParsedEntry(http_hdr_type id, String value, int error);

static void httpHeaderStatInit(HttpHeaderStat * hs, const char *label);
static void httpHeaderStatDump(const HttpHeaderStat * hs, StoreEntry * e);

/* handy to determine the #elements in a static array */
#define countof(arr) (sizeof(arr)/sizeof(*arr))

/*
 * Module initialization routines
 */

void
httpHeaderInitModule()
{
    int i;
    /* check that we have enough space for masks */
    assert(8*sizeof(HttpHeaderMask) >= HDR_ENUM_END);
    Headers = httpHeaderBuildFieldsInfo(HeadersAttrs, HDR_ENUM_END);
    /* create masks */
    httpHeaderCalcMask(&ListHeadersMask, (const int *) ListHeadersArr, countof(ListHeadersArr));
    httpHeaderCalcMask(&ReplyHeadersMask, (const int *) ReplyHeadersArr, countof(ReplyHeadersArr));
    httpHeaderCalcMask(&RequestHeadersMask, (const int *) RequestHeadersArr, countof(RequestHeadersArr));
    /* init header stats */
    for (i = 0; i < HttpHeaderStatCount; i++)
	httpHeaderStatInit(HttpHeaderStats + i, HttpHeaderStats[i].label);
    httpHdrCcInitModule();
    cachemgrRegister("http_headers",
	"HTTP Header Statistics", httpHeaderStoreReport, 0);
}

void
httpHeaderCleanModule()
{
    httpHeaderDestroyFieldsInfo(Headers, HDR_ENUM_END);
    Headers = NULL;
    httpHdrCcCleanModule();
}

static void
httpHeaderStatInit(HttpHeaderStat * hs, const char *label)
{
    assert(hs);
    assert(label);
    hs->label = label;
    statHistEnumInit(&hs->hdrUCountDistr, 32);	/* not a real enum */
    statHistEnumInit(&hs->fieldTypeDistr, HDR_ENUM_END);
    statHistEnumInit(&hs->ccTypeDistr, CC_ENUM_END);
}

/*
 * HttpHeader Implementation
 */

void
httpHeaderInit(HttpHeader * hdr)
{
    assert(hdr);
    debug(55, 7) ("init-ing hdr: %p\n", hdr);
    memset(hdr, 0, sizeof(*hdr));
    arrayInit(&hdr->entries);
}

void
httpHeaderClean(HttpHeader * hdr)
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;

    debug(55, 7) ("cleaning hdr: %p\n", hdr);
    assert(hdr);

    statHistCount(&HttpHeaderStats[0].hdrUCountDistr, hdr->entries.count);
    HeaderDestroyedCount++;
    NonEmptyHeaderDestroyedCount += hdr->entries.count > 0;
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	/* fix this for req headers @?@ */
	statHistCount(&HttpHeaderStats[0].fieldTypeDistr, e->id);
	/* tmp hack to avoid coredumps */
	if (e->id < 0 || e->id >= HDR_ENUM_END)
	    debug(55, 0) ("httpHeaderClean BUG: entry[%d] is invalid (%d). Ignored.\n",
		pos, e->id);
	else
	/* end of hack */
	/* yes, this destroy() leaves us in an incosistent state */
	httpHeaderEntryDestroy(e);
    }
    arrayClean(&hdr->entries);
}

/* use fresh entries to replace old ones */
void
httpHeaderUpdate(HttpHeader *old, const HttpHeader *fresh)
{
    HttpHeaderEntry *e;
    HttpHeaderEntry *e_clone;
    HttpHeaderPos pos = HttpHeaderInitPos;
    assert(old && fresh);
    assert(old != fresh);
    debug(55, 7) ("updating hdr: %p <- %p\n", old, fresh);

    while ((e = httpHeaderGetEntry(fresh, &pos))) {
	httpHeaderDelByName(old, strBuf(e->name));
	e_clone = httpHeaderEntryClone(e);
	httpHeaderAddEntry(old, e_clone);
    }
}

/* just handy in parsing: resets and returns false */
static int
httpHeaderReset(HttpHeader * hdr)
{
    httpHeaderClean(hdr);
    httpHeaderInit(hdr);
    return 0;
}

int
httpHeaderParse(HttpHeader * hdr, const char *header_start, const char *header_end)
{
    const char *field_start = header_start;
    HttpHeaderEntry *e;

    assert(hdr);
    assert(header_start && header_end);
    debug(55, 7) ("parsing hdr: (%p)\n%s\n", hdr, getStringPrefix(header_start, header_end));
    HeaderParsedCount++;
    /* commonn format headers are "<name>:[ws]<value>" lines delimited by <CRLF> */
    while (field_start < header_end) {
	const char *field_end = field_start + strcspn(field_start, "\r\n");
	if (!*field_end || field_end > header_end)
	    return httpHeaderReset(hdr);	/* missing <CRLF> */
        e = httpHeaderEntryParseCreate(field_start, field_end);
	if (e != NULL)
	    httpHeaderAddEntry(hdr, e);
	else
	    debug(55, 2) ("warning: ignoring unparseable http header field near '%s'\n",
		getStringPrefix(field_start, field_end));
	field_start = field_end;
	/* skip CRLF */
	if (*field_start == '\r')
	    field_start++;
	if (*field_start == '\n')
	    field_start++;
    }
    return 1;  /* even if no fields where found, it is a valid header */
}

/*
 * packs all the entries into the buffer, 
 * returns number of bytes packed including terminating '\0'
 */
void
httpHeaderPackInto(const HttpHeader * hdr, Packer * p)
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    const HttpHeaderEntry *e;
    assert(hdr && p);
    debug(55, 7) ("packing hdr: (%p)\n", hdr);
    /* pack all entries one by one */
    while ((e = httpHeaderGetEntry(hdr, &pos)))
	httpHeaderEntryPackInto(e, p);
}

/* returns next valid entry */
static HttpHeaderEntry *
httpHeaderGetEntry(const HttpHeader * hdr, HttpHeaderPos * pos)
{
    assert(hdr && pos);
    assert(*pos >= HttpHeaderInitPos && *pos < hdr->entries.count);
    debug(55, 8) ("searching for next e in hdr %p from %d\n", hdr, *pos);
    for ((*pos)++; *pos < hdr->entries.count; (*pos)++) {
	if (hdr->entries.items[*pos])
	   return hdr->entries.items[*pos];
    }
    debug(55, 8) ("no more entries in hdr %p\n", hdr);
    return NULL;
}

/*
 * returns a pointer to a specified entry if any 
 * note that we return one entry so it does not make much sense to ask for
 * "list" headers
 */
HttpHeaderEntry *
httpHeaderFindEntry(const HttpHeader * hdr, http_hdr_type id)
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    assert(hdr);
    assert_eid(id);
    assert(!CBIT_TEST(ListHeadersMask, id));

    debug(55, 8) ("finding entry %d in hdr %p\n", id, hdr);
    /* check mask first */
    if (!CBIT_TEST(hdr->mask, id))
	return NULL;
    /* looks like we must have it, do linear search */
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	if (e->id == id)
	    return e;
    }
    /* hm.. we thought it was there, but it was not found */
    assert(0);
    return NULL; /* not reached */
}

/*
 * deletes all fields with a given name if any, returns #fields deleted; 
 */
int
httpHeaderDelByName(HttpHeader * hdr, const char *name)
{
    int count = 0;
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    httpHeaderMaskInit(&hdr->mask); /* temporal inconsistency */
    debug(55, 7) ("deleting '%s' fields in hdr %p\n", name, hdr);
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	if (!strCaseCmp(e->name, name)) {
	    httpHeaderDelAt(hdr, pos);
	    count++;
	} else
	    CBIT_SET(hdr->mask, e->id);
    }
    return count;
}

#if FUTURE_CODE
static int
httpHeaderDelById(HttpHeader * hdr, http_hdr_type id)
{
    int count = 0;
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    debug(55, 8) ("%p del-by-id %d\n", hdr, id);
    if (!CBIT_TEST(hdr->mask, id))
	return 0;
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	if (e->id == id) {
	    httpHeaderDelAt(hdr, pos);
	    count++;
	}
    }
    CBIT_CLR(hdr->mask, id);
    assert(count);
    return count;
}
#endif

/*
 * deletes an entry at pos and leaves a gap; leaving a gap makes it
 * possible to iterate(search) and delete fields at the same time
 */
static void
httpHeaderDelAt(HttpHeader * hdr, HttpHeaderPos pos)
{
    httpHeaderEntryDestroy(hdr->entries.items[pos]);
    hdr->entries.items[pos] = NULL;
}

/*
 * adds parsed entry (joins entries if neeeded); assumes e.value is dup()-ed and
 * clean()s it if needed. Thus, "e" should be treated as uninitialized after
 * this function returns.
 */
static void
httpHeaderAddEntry(HttpHeader * hdr, HttpHeaderEntry * e)
{
    assert(hdr && e);
    assert_eid(e->id);

    debug(55, 7) ("%p adding entry: %d at %d\n",
	hdr, e->id, hdr->entries.count);
    if (CBIT_TEST(hdr->mask, e->id))
	Headers[e->id].stat.repCount++;
    else
	CBIT_SET(hdr->mask, e->id);
    arrayAppend(&hdr->entries, e);
}

static String
httpHeaderJoinEntries(const HttpHeader *hdr, http_hdr_type id)
{
    String s = StringNull;
    HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;
    debug(55, 6) ("%p: joining for id %d\n", hdr, id);
    assert(CBIT_TEST(ListHeadersMask, id));
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	if (e->id == id) {
	    if (strLen(s)) {
		stringAppend(&s, ",", 1);
		stringAppend(&s, strBuf(e->value), strLen(e->value));
	    } else
		s = stringDup(&e->value);
	}
    }
    assert(strLen(s));
    debug(55, 6) ("%p: joined for id %d: %s\n", hdr, id, strBuf(s));
    return s;
}


/* test if a field is present */
int
httpHeaderHas(const HttpHeader * hdr, http_hdr_type id)
{
    assert(hdr);
    assert_eid(id);
    assert(id != HDR_OTHER);
    debug(55, 7) ("%p lookup for %d\n", hdr, id);
    return CBIT_TEST(hdr->mask, id);
}

void
httpHeaderPutInt(HttpHeader * hdr, http_hdr_type id, int number)
{
    assert_eid(id);
    assert(Headers[id].type == ftInt); /* must be of an appropriatre type */
    assert(number >= 0);
    httpHeaderAddEntry(hdr, httpHeaderEntryCreate(id, NULL, xitoa(number)));
}

void
httpHeaderPutTime(HttpHeader * hdr, http_hdr_type id, time_t time)
{
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123); /* must be of an appropriatre type */
    assert(time >= 0);
    httpHeaderAddEntry(hdr, httpHeaderEntryCreate(id, NULL, mkrfc1123(time)));
}

void
httpHeaderPutStr(HttpHeader * hdr, http_hdr_type id, const char *str)
{
    assert_eid(id);
    assert(Headers[id].type == ftStr); /* must be of an appropriatre type */
    assert(str);
    httpHeaderAddEntry(hdr, httpHeaderEntryCreate(id, NULL, str));
}

void
httpHeaderPutAuth(HttpHeader * hdr, const char *authScheme, const char *realm)
{
    MemBuf mb;
    assert(hdr && authScheme && realm);
    memBufDefInit(&mb);
    memBufPrintf(&mb, "%s realm=\"%s\"", authScheme, realm);
    httpHeaderPutStr(hdr, HDR_WWW_AUTHENTICATE, mb.buf);
    memBufClean(&mb);
}

/* add extension header (these fields are not parsed/analyzed/joined, etc.) */
void
httpHeaderPutExt(HttpHeader * hdr, const char *name, const char *value)
{
    assert(name && value);
    debug(55, 8) ("%p adds ext entry '%s: %s'\n", hdr, name, value);
    httpHeaderAddEntry(hdr, httpHeaderEntryCreate(HDR_OTHER, name, value));
}

int
httpHeaderGetInt(const HttpHeader * hdr, http_hdr_type id)
{
    HttpHeaderEntry *e;
    int value = -1;
    int ok;
    assert_eid(id);
    assert(Headers[id].type == ftInt);	/* must be of an appropriate type */
    if ((e = httpHeaderFindEntry(hdr, id))) {
	ok = httpHeaderParseInt(strBuf(e->value), &value);
	httpHeaderNoteParsedEntry(e->id, e->value, !ok);
    }
    return value;
}

time_t
httpHeaderGetTime(const HttpHeader * hdr, http_hdr_type id)
{
    HttpHeaderEntry *e;
    time_t value = -1;
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123);	/* must be of an appropriate type */
    if ((e = httpHeaderFindEntry(hdr, id))) {
	value = parse_rfc1123(strBuf(e->value));
	httpHeaderNoteParsedEntry(e->id, e->value, value < 0);
    }
    return value;
}

const char *
httpHeaderGetStr(const HttpHeader * hdr, http_hdr_type id)
{
    HttpHeaderEntry *e;
    assert_eid(id);
    assert(Headers[id].type == ftStr);	/* must be of an appropriate type */
    if ((e = httpHeaderFindEntry(hdr, id))) {
	httpHeaderNoteParsedEntry(e->id, e->value, 0); /* no errors are possible */
	return strBuf(e->value);
    }
    return NULL;
}

HttpHdrCc *
httpHeaderGetCc(const HttpHeader * hdr)
{
    HttpHdrCc *cc;
    String s;
    if (!CBIT_TEST(hdr->mask, HDR_CACHE_CONTROL))
	return NULL;
    s = httpHeaderJoinEntries(hdr, HDR_CACHE_CONTROL);
    cc = httpHdrCcParseCreate(strBuf(s));
    /* fix this for req headers @?@ */
    if (cc)
	httpHdrCcUpdateStats(cc, &HttpHeaderStats[0].ccTypeDistr);
    httpHeaderNoteParsedEntry(HDR_CACHE_CONTROL, s, !cc);
    stringClean(&s);
    return cc;
}

HttpHdrRange *
httpHeaderGetRange(const HttpHeader * hdr)
{
    HttpHdrRange *r;
    String s;
    if (!CBIT_TEST(hdr->mask, HDR_RANGE))
	return NULL;
    s = httpHeaderJoinEntries(hdr, HDR_RANGE);
    r = httpHdrRangeParseCreate(strBuf(s));
    httpHeaderNoteParsedEntry(HDR_RANGE, s, !r);
    stringClean(&s);
    return r;
}

HttpHdrContRange *
httpHeaderGetContRange(const HttpHeader * hdr)
{
    HttpHeaderEntry *e;
    HttpHdrContRange *cr = NULL;
    if ((e = httpHeaderFindEntry(hdr, HDR_CONTENT_RANGE))) {
	cr = httpHdrContRangeParseCreate(strBuf(e->value));
	httpHeaderNoteParsedEntry(e->id, e->value, !cr);
    }
    return cr;
}

#if FUTURE_CODE
HttpHdrConn *
httpHeaderGetConn(const HttpHeader * hdr)
{
    HttpHdrConn *conn;
    String s;
    if (!CBIT_TEST(hdr->mask, HDR_CONNECTION))
	return NULL;
    s = httpHeaderJoinEntries(hdr, HDR_CONNECTION);
    conn = httpHdrConnParseCreate(s);
    httpHeaderNoteParsedEntry(HDR_CONNECTION, s, !conn);
    stringClean(&s);
    return conn;
}
#endif

/*
 * HttpHeaderEntry
 */

static HttpHeaderEntry *
httpHeaderEntryCreate(http_hdr_type id, const char *name, const char *value)
{
    HttpHeaderEntry *e;
    assert_eid(id);
    e = memAllocate(MEM_HTTP_HDR_ENTRY);
    e->id = id;
    if (id != HDR_OTHER)
	e->name = Headers[id].name;
    else
	stringInit(&e->name, name);
    stringInit(&e->value, value);
    Headers[id].stat.aliveCount++;
    debug(55, 9) ("created entry %p: '%s: %s'\n", e, strBuf(e->name), strBuf(e->value));
    return e;
}

static void
httpHeaderEntryDestroy(HttpHeaderEntry * e)
{
    assert(e);
    assert_eid(e->id);
    debug(55, 9) ("destroying entry %p: '%s: %s'\n", e, strBuf(e->name), strBuf(e->value));
    /* clean name if needed */
    if (e->id == HDR_OTHER)
	stringClean(&e->name);
    stringClean(&e->value);
    assert(Headers[e->id].stat.aliveCount);
    Headers[e->id].stat.aliveCount--;
    e->id = -1;
    memFree(MEM_HTTP_HDR_ENTRY, e);
}

/* parses and inits header entry, returns new entry on success */
static HttpHeaderEntry *
httpHeaderEntryParseCreate(const char *field_start, const char *field_end)
{
    HttpHeaderEntry *e;
    int id;
    /* note: name_start == field_start */
    const char *name_end = strchr(field_start, ':');
    const int name_len = name_end ? name_end - field_start : 0;
    const char *value_start = field_start + name_len + 1; /* skip ':' */
    /* note: value_end == field_end */

    HeaderEntryParsedCount++;

    /* do we have a valid field name within this field? */
    if (!name_len || name_end > field_end)
	return NULL;
    /* now we know we can parse it */
    e = memAllocate(MEM_HTTP_HDR_ENTRY);
    debug(55, 9) ("creating entry %p: near '%s'\n", e, getStringPrefix(field_start, field_end));
    /* is it a "known" field? */
    id = httpHeaderIdByName(field_start, name_len, Headers, HDR_ENUM_END);
    if (id < 0)
	id = HDR_OTHER;
    assert_eid(id);
    e->id = id;
    /* set field name */
    if (id == HDR_OTHER)
	stringLimitInit(&e->name, field_start, name_len);
    else
	e->name = Headers[id].name;
    /* trim field value */
    while (value_start < field_end && isspace(*value_start))
	value_start++;
    /* set field value */
    stringLimitInit(&e->value, value_start, field_end - value_start);
    Headers[id].stat.seenCount++;
    Headers[id].stat.aliveCount++;
    debug(55, 9) ("created entry %p: '%s: %s'\n", e, strBuf(e->name), strBuf(e->value));
    return e;
}

static HttpHeaderEntry *
httpHeaderEntryClone(const HttpHeaderEntry * e)
{
    return httpHeaderEntryCreate(e->id, strBuf(e->name), strBuf(e->value));
}

void
httpHeaderEntryPackInto(const HttpHeaderEntry * e, Packer * p)
{
    assert(e && p);
    packerAppend(p, strBuf(e->name), strLen(e->name));
    packerAppend(p, ": ", 2);
    packerAppend(p, strBuf(e->value), strLen(e->value));
    packerAppend(p, "\r\n", 2);
}

static void
httpHeaderNoteParsedEntry(http_hdr_type id, String context, int error)
{
    Headers[id].stat.parsCount++;
    if (error) {
	Headers[id].stat.errCount++;
	debug(55,2) ("cannot parse hdr field: '%s: %s'\n",
	    strBuf(Headers[id].name), strBuf(context));
    }
}

/*
 * Reports
 */

static void
httpHeaderFieldStatDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    const int id = (int) val;
    const int valid_id = id >= 0 && id < HDR_ENUM_END;
    const char *name = valid_id ? strBuf(Headers[id].name) : "INVALID";
    if (count || valid_id)
	storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
	    id, name, count, xdiv(count, NonEmptyHeaderDestroyedCount));
}

static void
httpHeaderFldsPerHdrDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    if (count)
	storeAppendPrintf(sentry, "%2d\t %5d\t %5d\t %6.2f\n",
	    idx, (int)val, count,
	    xpercent(count, HeaderDestroyedCount));
}


static void
httpHeaderStatDump(const HttpHeaderStat * hs, StoreEntry * e)
{
    assert(hs && e);

    storeAppendPrintf(e, "\n<h3>Header Stats: %s</h3>\n", hs->label);
    storeAppendPrintf(e, "<h3>Field type distribution</h3>\n");
    storeAppendPrintf(e, "%2s\t %-20s\t %5s\t %6s\n",
	"id", "name", "count", "#/header");
    statHistDump(&hs->fieldTypeDistr, e, httpHeaderFieldStatDumper);
    storeAppendPrintf(e, "<h3>Cache-control directives distribution</h3>\n");
    storeAppendPrintf(e, "%2s\t %-20s\t %5s\t %6s\n",
	"id", "name", "count", "#/cc_field");
    statHistDump(&hs->ccTypeDistr, e, httpHdrCcStatDumper);
    storeAppendPrintf(e, "<h3>Number of fields per header distribution</h3>\n");
    storeAppendPrintf(e, "%2s\t %-5s\t %5s\t %6s\n",
	"id", "#flds", "count", "%total");
    statHistDump(&hs->hdrUCountDistr, e, httpHeaderFldsPerHdrDumper);
}

void
httpHeaderStoreReport(StoreEntry * e)
{
    int i;
    http_hdr_type ht;
    assert(e);

    /* fix this (including summing for totals) for req hdrs @?@ */
    for (i = 0; i < 1 /*HttpHeaderStatCount */ ; i++) {
	httpHeaderStatDump(HttpHeaderStats + i, e);
	storeAppendPrintf(e, "%s\n", "<br>");
    }
    storeAppendPrintf(e, "%s\n", "<hr size=1 noshade>");
    /* field stats */
    storeAppendPrintf(e, "<h3>Http Fields Stats (replies and requests)</h3>\n");
    storeAppendPrintf(e, "%2s\t %-20s\t %5s\t %6s\t %6s\n",
	"id", "name", "#alive", "%err", "%repeat");
    for (ht = 0; ht < HDR_ENUM_END; ht++) {
	HttpHeaderFieldInfo *f = Headers + ht;
	storeAppendPrintf(e, "%2d\t %-20s\t %5d\t %6.3f\t %6.3f\n",
	    f->id, strBuf(f->name), f->stat.aliveCount,
	    xpercent(f->stat.errCount, f->stat.parsCount),
	    xpercent(f->stat.repCount, f->stat.seenCount));
    }
    storeAppendPrintf(e, "Headers Parsed: %d\n", HeaderParsedCount);
    storeAppendPrintf(e, "Hdr Fields Parsed: %d\n", HeaderEntryParsedCount);
}
