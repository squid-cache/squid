
/*
 * $Id: HttpHeader.cc,v 1.23 1998/03/11 22:18:45 rousskov Exp $
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
 * HttpHeader is implemented as a collection of header "entries"
 * An entry is a (field_id, field) pair where
 * - field_id is one of the http_hdr_type ids,
 * - field is a compiled(parsed) image of message-header.
 */


/*
 * local types
 */

/*
 * HttpHeader entry (type of cached value is Headers[id].type)
 */
struct _HttpHeaderEntry {
    String name;
    String value;
    field_store cache;
    short int id;
};


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
    {"Etag", HDR_ETAG, ftStr},	/* for now */
    {"Expires", HDR_EXPIRES, ftDate_1123},
    {"Host", HDR_HOST, ftStr},
    {"If-Modified-Since", HDR_IMS, ftDate_1123},
    {"Last-Modified", HDR_LAST_MODIFIED, ftDate_1123},
    {"Location", HDR_LOCATION, ftStr},
    {"Max-Forwards", HDR_MAX_FORWARDS, ftInt},
    {"Proxy-Authenticate", HDR_PROXY_AUTHENTICATE, ftStr},
    {"Proxy-Connection", HDR_PROXY_KEEPALIVE, ftInt},	/* true/false */
    {"Public", HDR_PUBLIC, ftStr},
    {"Range", HDR_RANGE, ftPRange},
    {"Retry-After", HDR_RETRY_AFTER, ftStr},	/* for now */
    {"Server", HDR_SERVER, ftStr},
    {"Set-Cookie", HDR_SET_COOKIE, ftStr},
    {"Upgrade", HDR_UPGRADE, ftStr},	/* for now */
    {"Warning", HDR_WARNING, ftStr},	/* for now */
    {"WWW-Authenticate", HDR_WWW_AUTHENTICATE, ftStr},
    {"X-Cache", HDR_X_CACHE, ftStr},
    {"Other:", HDR_OTHER, ftPExtField}	/* ':' will not allow matches */
};
static HttpHeaderFieldInfo *Headers = NULL;

/*
 * headers with field values defined as #(values) in HTTP/1.1
 *
 * We have listed all possible list headers according to
 * draft-ietf-http-v11-spec-rev-01.txt. Headers that are currently not
 * recognized, are commented out.
 */
static int ListHeadersMask = 0;	/* set run-time using  ListHeadersArr */
static http_hdr_type ListHeadersArr[] =
{
    HDR_ACCEPT,
    /* HDR_ACCEPT_CHARSET, HDR_ACCEPT_ENCODING, HDR_ACCEPT_LANGUAGE, */
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

/* for these headers duplicates are left; list headers do not belong here */
static int DupHeadersMask = 0;	/* set run-time */
static http_hdr_type DupHeadersArr[] = {
    HDR_SET_COOKIE, HDR_X_CACHE, HDR_OTHER
};

static int ReplyHeadersMask = 0;	/* set run-time using ReplyHeaders */
static http_hdr_type ReplyHeadersArr[] =
{
    HDR_RANGE,

    HDR_ACCEPT, HDR_ACCEPT_RANGES, HDR_AGE, HDR_CACHE_CONTROL, HDR_CONTENT_LENGTH,
    HDR_CONTENT_MD5, HDR_CONTENT_RANGE, HDR_CONTENT_TYPE, HDR_DATE, HDR_ETAG, HDR_EXPIRES,
    HDR_LAST_MODIFIED, HDR_LOCATION, HDR_MAX_FORWARDS, HDR_PUBLIC, HDR_RETRY_AFTER,
    HDR_SERVER, HDR_SET_COOKIE, HDR_UPGRADE, HDR_WARNING, HDR_PROXY_KEEPALIVE, HDR_X_CACHE, HDR_OTHER
};

static int RequestHeadersMask = 0;	/* set run-time using RequestHeaders */
static http_hdr_type RequestHeadersArr[] =
{
    HDR_RANGE, HDR_OTHER
};

/* when first field is added, this is how much entries we allocate */
#define INIT_FIELDS_PER_HEADER 8

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
static void httpHeaderDelAt(HttpHeader * hdr, HttpHeaderPos pos, int auto_sync);
static void httpHeaderDelById(HttpHeader * hdr, http_hdr_type id);
static void httpHeaderAddParsedEntry(HttpHeader * hdr, HttpHeaderEntry * e);
static void httpHeaderAddNewEntry(HttpHeader * hdr, const HttpHeaderEntry * e);
static field_store httpHeaderGetCache(const HttpHeader * hdr, http_hdr_type id);
static void httpHeaderSet(HttpHeader * hdr, HttpHeaderEntry *e);
static void httpHeaderSyncMasks(HttpHeader * hdr, const HttpHeaderEntry * e, int add);
static void httpHeaderGrow(HttpHeader * hdr);

static void httpHeaderEntryInit(HttpHeaderEntry * e, http_hdr_type id, const char *value, field_store cache);
static void httpHeaderEntryExtInit(HttpHeaderEntry * e, const char *name, const char *value);
static void httpHeaderEntryClean(HttpHeaderEntry * e);
static int httpHeaderEntryParseInit(HttpHeaderEntry * e, const char *field_start, const char *field_end, int mask);
static int httpHeaderEntryParse(HttpHeaderEntry * e, const char *field_start, const char *field_end);
static void httpHeaderEntrySyncCache(HttpHeaderEntry * e);
static void httpHeaderEntrySyncCacheByType(HttpHeaderEntry * e);
/*
static int httpHeaderEntryParseExtFieldInit(HttpHeaderEntry * e, int id, const HttpHdrExtField * f);
static int httpHeaderEntryParseByTypeInit(HttpHeaderEntry * e, int id, const HttpHdrExtField * f);
*/
static HttpHeaderEntry httpHeaderEntryClone(const HttpHeaderEntry * e);
/*
static void httpHeaderEntryPackByType(const HttpHeaderEntry * e, Packer * p);
*/
static void httpHeaderEntryJoinWith(HttpHeaderEntry * e, const HttpHeaderEntry * newe);
/*
static const char *httpHeaderEntryName(const HttpHeaderEntry * e);
*/

static void httpHeaderFieldInit(field_store * field);
static field_store httpHeaderFieldDup(field_type type, field_store value);
static field_store httpHeaderFieldBadValue(field_type type);

static void httpHeaderStatInit(HttpHeaderStat * hs, const char *label);
static void httpHeaderStatDump(const HttpHeaderStat * hs, StoreEntry * e);

/* handy to determine the #elements in a static array */
#define countof(arr) (sizeof(arr)/sizeof(*arr))

/*
 * some compilers do not want to convert a type into a union which that type
 * belongs to so we have to do it manualy
 */
static field_store 
intField(int n)
{
    field_store f;
    f.v_int = n;
    return f;
}
static field_store 
timeField(time_t t)
{
    field_store f;
    f.v_time = t;
    return f;
}
static field_store 
strField(String s)
{
    field_store f;
    f.v_str = s;
    return f;
}
static field_store 
ptrField(void *p)
{
    field_store f;
    f.v_pcc = p;
    return f;
}


/*
 * Module initialization routines
 */

void
httpHeaderInitModule()
{
    int i;
    /* paranoid check if smbd put a big object into field_store */
    assert(sizeof(field_store) == sizeof(String));
    Headers = httpHeaderBuildFieldsInfo(HeadersAttrs, HDR_ENUM_END);
    /* create masks */
    ListHeadersMask = httpHeaderCalcMask((const int *) ListHeadersArr, countof(ListHeadersArr));
    DupHeadersMask = httpHeaderCalcMask((const int *) DupHeadersArr, countof(DupHeadersArr));
    /* dup-headers cannot be joined */
    assert(!(ListHeadersMask & DupHeadersMask)); 
    ReplyHeadersMask = httpHeaderCalcMask((const int *) ReplyHeadersArr, countof(ReplyHeadersArr));
    RequestHeadersMask = httpHeaderCalcMask((const int *) RequestHeadersArr, countof(RequestHeadersArr));
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
    memset(hdr, 0, sizeof(*hdr));
}

void
httpHeaderClean(HttpHeader * hdr)
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;

    debug(55, 7) ("cleaning hdr: %p\n", hdr);
    assert(hdr);

    statHistCount(&HttpHeaderStats[0].hdrUCountDistr, hdr->ucount);
    HeaderDestroyedCount++;
    NonEmptyHeaderDestroyedCount += hdr->ucount > 0;
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	/* fix this (for cc too) for req headers @?@ */
	statHistCount(&HttpHeaderStats[0].fieldTypeDistr, e->id);
	if (e->id == HDR_CACHE_CONTROL)
	    httpHdrCcUpdateStats(e->cache.v_pcc, &HttpHeaderStats[0].ccTypeDistr);
	httpHeaderEntryClean(e); /* yes, this leaves us in incosistent state */
    }
    xfree(hdr->entries);
    hdr->emask = 0;
    hdr->entries = NULL;
    hdr->capacity = hdr->ucount = 0;
}

void
httpHeaderCopy(HttpHeader *dest, const HttpHeader *src)
{
    HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;
    assert(dest && src);
    debug(55, 7) ("copying hdr: %p <- %p\n", dest, src);

    while ((e = httpHeaderGetEntry(src, &pos))) {
	HttpHeaderEntry e_clone = httpHeaderEntryClone(e);
	httpHeaderAddNewEntry(dest, &e_clone);
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
    HttpHeaderEntry e;
    int mask = 0;

    assert(hdr);
    assert(header_start && header_end);
    debug(55, 7) ("parsing hdr: (%p) '%s'\n...\n", hdr, getStringPrefix(header_start));
    HeaderParsedCount++;
    /* select appropriate field mask */
    mask = ( /* fix this @?@ @?@ */ 1) ? ReplyHeadersMask : RequestHeadersMask;
    /* commonn format headers are "<name>:[ws]<value>" lines delimited by <CRLF> */
    while (field_start < header_end) {
	const char *field_end = field_start + strcspn(field_start, "\r\n");
	/*tmp_debug(here) ("found end of field: %d\n", (int)*field_end); */
	if (!*field_end || field_end > header_end)
	    return httpHeaderReset(hdr);	/* missing <CRLF> */
	/*
	 * If we fail to parse a field, we ignore it. We also could claim that
	 * the whole header is invalid. The latter is safer, but less robust.
	 * Note that we should be able to parse any commonn format field.
	 */
	if (!httpHeaderEntryParseInit(&e, field_start, field_end, mask))
	    debug(55, 2) ("warning: ignoring unparseable http header field near '%s'\n",
		getStringPrefix(field_start));
	else
	    httpHeaderAddParsedEntry(hdr, &e);
	/*
	 * Note that we init() "e", bit never clean() it which is equivalent to
	 * creating a fresh entry on each loop iteration; thus, it is safe to
	 * add e without dup()-ing it.
	 */
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
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	httpHeaderEntryPackInto(e, p);
    }
}

/* returns next valid entry */
static HttpHeaderEntry *
httpHeaderGetEntry(const HttpHeader * hdr, HttpHeaderPos * pos)
{
    assert(hdr && pos);
    assert(*pos >= HttpHeaderInitPos && *pos < hdr->capacity);
    debug(55, 8) ("searching next e in hdr %p from %d\n", hdr, *pos);
    for ((*pos)++; *pos < hdr->ucount; (*pos)++) {
	HttpHeaderEntry *e = hdr->entries + *pos;
	if (e->id >= 0) {
	    debug(55, 8) ("%p returning entry: %s at %d\n",
		hdr, strBuf(e->name), *pos);
	    return e;
	}
    }
    debug(55, 8) ("no more entries in hdr %p\n", hdr);
    return NULL;
}

/*
 * returns a pointer to a specified entry and updates pos; 
 * note that we search from the very begining so it does not make much sense to
 * ask for headers that maybe repeated.
 */
HttpHeaderEntry *
httpHeaderFindEntry(const HttpHeader * hdr, http_hdr_type id, HttpHeaderPos * pos)
{
    HttpHeaderPos p;
    HttpHeaderEntry *e;
    assert(hdr);
    assert_eid(id);
    assert(!EBIT_TEST(DupHeadersMask, id));

    debug(55, 8) ("finding entry %d in hdr %p\n", id, hdr);
    /* check mask first */
    if (!EBIT_TEST(hdr->emask, id))
	return NULL;
    /* looks like we must have it, do linear search */
    if (!pos)
	pos = &p;
    *pos = HttpHeaderInitPos;
    while ((e = httpHeaderGetEntry(hdr, pos))) {
	if (e->id == id)
	    return e;
    }
    /* hm.. we thought it was there, but it was not found */
    assert(0);
    return NULL; /* not reached */
}

/*
 * deletes all field(s) with a given name if any, returns #fields deleted; 
 * used to process Connection: header and delete fields in "paranoid" setup
 */
int
httpHeaderDelFields(HttpHeader * hdr, const char *name)
{
    int count = 0;
    int mask = 0;
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;

    debug(55, 7) ("deleting '%s' fields in hdr %p\n", name, hdr);
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	if (!strCmp(e->name, name)) {
	    httpHeaderDelAt(hdr, pos, 0);
	    count++;
	} else
	    EBIT_SET(mask, e->id);
    }
    hdr->emask = mask;
    return count;
}

/*
 * deletes an entry at pos and leaves a gap; leaving a gap makes it
 * possible to iterate(search) and delete fields at the same time
 */
static void
httpHeaderDelAt(HttpHeader * hdr, HttpHeaderPos pos, int auto_sync)
{
    HttpHeaderEntry *e;
    assert(hdr);
    assert(pos >= 0 && pos < hdr->ucount);
    e = hdr->entries + pos;
    debug(55, 7) ("%p deling entry at %d: id: %d (%p:%p)\n",
	hdr, pos, e->id, hdr->entries, e);
    /* sync masks */
    if (auto_sync) {
	assert(!EBIT_TEST(DupHeadersMask, e->id));
	httpHeaderSyncMasks(hdr, e, 0);
    }
    httpHeaderEntryClean(e);
}

/*
 * adds parsed entry (joins entries if neeeded); assumes e.value is dup()-ed and
 * clean()s it if needed. Thus, "e" should be treated as uninitialized after
 * this function returns.
 */
static void
httpHeaderAddParsedEntry(HttpHeader * hdr, HttpHeaderEntry * e)
{
    HttpHeaderEntry *olde;
    assert(hdr);
    assert(e);
    assert_eid(e->id);

    debug(55, 7) ("%p adding parsed entry %d\n", hdr, e->id);

    if (EBIT_TEST(hdr->emask, e->id))
	Headers[e->id].stat.repCount++;
    olde = EBIT_TEST(DupHeadersMask, e->id) ? NULL : httpHeaderFindEntry(hdr, e->id, NULL);
    if (olde) {
	if (EBIT_TEST(ListHeadersMask, e->id))
	    httpHeaderEntryJoinWith(olde, e);
	else
	    debug(55, 3) ("ignoring duplicate header: %s\n", strBuf(e->name));
	httpHeaderEntryClean(e);
    } else {
	/* actual add */
	httpHeaderAddNewEntry(hdr, e);
	debug(55, 6) ("%p done adding parsed entry %d (%s)\n", hdr, e->id, strBuf(e->name));
    }
}

/*
 * adds a new entry (low level append, does not check if entry is new) note: we
 * copy e value, thus, e can point to a tmp variable (but e->field is not dupped!)
 */
static void
httpHeaderAddNewEntry(HttpHeader * hdr, const HttpHeaderEntry *e)
{
    assert(hdr && e);
    debug(55, 8) ("%p adding entry: %d at %d, (%p:%p)\n",
	hdr, e->id, hdr->ucount,
	hdr->entries, hdr->entries + hdr->ucount);
    if (hdr->ucount >= hdr->capacity)
	httpHeaderGrow(hdr);
    hdr->entries[hdr->ucount++] = *e;
    /* sync masks */
    if (EBIT_TEST(DupHeadersMask, e->id))
	EBIT_SET(DupHeadersMask, e->id);
    else
	httpHeaderSyncMasks(hdr, e, 1);
}


/* test if a field is present */
int
httpHeaderHas(const HttpHeader * hdr, http_hdr_type id)
{
    assert(hdr);
    assert_eid(id);
    assert(id != HDR_OTHER);
    debug(55, 7) ("%p lookup for %d\n", hdr, id);
    return EBIT_TEST(hdr->emask, id);
}

/* delete a field if any; see httpHeaderFindEntry for restrictions */
static void
httpHeaderDelById(HttpHeader * hdr, http_hdr_type id)
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    debug(55, 8) ("%p del-by-id %d\n", hdr, id);
    if (httpHeaderFindEntry(hdr, id, &pos))
	httpHeaderDelAt(hdr, pos, 1);
}

/*
 * set a field
 * old content, if any, is destroyed.
 */
static void
httpHeaderSet(HttpHeader * hdr, HttpHeaderEntry *e)
{
    assert(hdr);
    assert_eid(e->id);

    debug(55, 7) ("%p sets entry with id: %d\n", hdr, e->id);
    httpHeaderDelById(hdr, e->id);	/* delete old entry if any */
    httpHeaderAddNewEntry(hdr, e);
}

void
httpHeaderSetInt(HttpHeader * hdr, http_hdr_type id, int number)
{
    HttpHeaderEntry e;
    assert_eid(id);
    assert(Headers[id].type == ftInt);	/* must be of an appropriatre type */
    assert(number >= 0);
    httpHeaderEntryInit(&e, id, xitoa(number), intField(number));
    httpHeaderSet(hdr, &e);
}

void
httpHeaderSetTime(HttpHeader * hdr, http_hdr_type id, time_t time)
{
    HttpHeaderEntry e;
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123);	/* must be of an appropriatre type */
    if (time >= 0) {
	httpHeaderEntryInit(&e, id, mkrfc1123(time), timeField(time));
	httpHeaderSet(hdr, &e);
    } else
	httpHeaderDelById(hdr, id);
}

void
httpHeaderSetStr(HttpHeader * hdr, http_hdr_type id, const char *str)
{
    HttpHeaderEntry e;
    assert_eid(id);
    assert(Headers[id].type == ftStr);	/* must be of a string type */
    assert(str);
    httpHeaderEntryInit(&e, id, str, strField(StringNull));
    httpHeaderSet(hdr, &e);
}

void
httpHeaderSetAuth(HttpHeader * hdr, const char *authScheme, const char *realm)
{
    MemBuf mb;
    assert(hdr && authScheme && realm);
    memBufDefInit(&mb);
    memBufPrintf(&mb, "%s realm=\"%s\"", authScheme, realm);
    httpHeaderSetStr(hdr, HDR_WWW_AUTHENTICATE, mb.buf);
    memBufClean(&mb);
}

/* add extension header (these fields are not parsed/analyzed/joined, etc.) */
void
httpHeaderAddExt(HttpHeader * hdr, const char *name, const char *value)
{
    HttpHeaderEntry e;
    assert(name &&  value);
    debug(55, 8) ("%p adds ext entry '%s: %s'\n", hdr, name, value);
    httpHeaderEntryExtInit(&e, name, value);
    httpHeaderAddNewEntry(hdr, &e);
}

/* get a ["right"] cached value of a field, see httpHeaderFindEntry for restrictions */
static field_store
httpHeaderGetCache(const HttpHeader * hdr, http_hdr_type id)
{
    HttpHeaderEntry *e;
    assert_eid(id);
    debug(55, 7) ("%p get for id %d\n", hdr, id);
    if ((e = httpHeaderFindEntry(hdr, id, NULL)))
	return e->cache;
    else
	return httpHeaderFieldBadValue(Headers[id].type);
}

int
httpHeaderGetInt(const HttpHeader * hdr, http_hdr_type id)
{
    assert_eid(id);
    assert(Headers[id].type == ftInt);	/* must be of an appropriate type */
    return httpHeaderGetCache(hdr, id).v_int;
}

time_t
httpHeaderGetTime(const HttpHeader * hdr, http_hdr_type id)
{
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123);	/* must be of an appropriate type */
    return httpHeaderGetCache(hdr, id).v_time;
}

const char *
httpHeaderGetStr(const HttpHeader * hdr, http_hdr_type id)
{
    HttpHeaderEntry *e;
    assert_eid(id);
    assert(Headers[id].type == ftStr);	/* must be of an appropriate type */
    if ((e = httpHeaderFindEntry(hdr, id, NULL)))
	if (strBuf(e->cache.v_str))
	    return strBuf(e->cache.v_str);
	else /* use real value if no cached one */
	    return strBuf(e->value);
    return NULL;
}

HttpHdrCc *
httpHeaderGetCc(const HttpHeader * hdr)
{
    return httpHeaderGetCache(hdr, HDR_CACHE_CONTROL).v_pcc;
}

HttpHdrRange *
httpHeaderGetRange(const HttpHeader * hdr)
{
    return httpHeaderGetCache(hdr, HDR_RANGE).v_prange;
}

HttpHdrContRange *
httpHeaderGetContRange(const HttpHeader * hdr)
{
    return httpHeaderGetCache(hdr, HDR_CONTENT_RANGE).v_pcont_range;
}

/* updates header masks */
static void
httpHeaderSyncMasks(HttpHeader * hdr, const HttpHeaderEntry * e, int add)
{
    const int isSet = EBIT_TEST(hdr->emask, e->id) != 0;
    add = add != 0;
    assert(isSet ^ add);
    add ? EBIT_SET(hdr->emask, e->id) : EBIT_CLR(hdr->emask, e->id);
}

/* doubles the size of the fields index, starts with INIT_FIELDS_PER_HEADER */
static void
httpHeaderGrow(HttpHeader * hdr)
{
    int new_cap;
    int new_size;
    assert(hdr);
    new_cap = (hdr->capacity) ? 2 * hdr->capacity : INIT_FIELDS_PER_HEADER;
    new_size = new_cap * sizeof(HttpHeaderEntry);

    debug(55, 9) ("%p grow (%p) %d->%d\n", hdr, hdr->entries, hdr->capacity, new_cap);
    hdr->entries = hdr->entries ?
	xrealloc(hdr->entries, new_size) :
	xmalloc(new_size);
    memset(hdr->entries + hdr->capacity, 0, (new_cap - hdr->capacity) * sizeof(HttpHeaderEntry));
    hdr->capacity = new_cap;
    debug(55, 9) ("%p grew (%p)\n", hdr, hdr->entries);
}

/*
 * HttpHeaderEntry
 */

static void
httpHeaderEntryDoInit(HttpHeaderEntry * e, http_hdr_type id, const char *name, const char *value, field_store cache)
{
    assert(e);
    assert_eid(id);
    e->id = id;
    if (id != HDR_OTHER)
	e->name = Headers[id].name;
    else
	stringInit(&e->name, name);
    stringInit(&e->value, value);
    e->cache = cache;
    Headers[id].stat.aliveCount++;
}

static void
httpHeaderEntryInit(HttpHeaderEntry * e, http_hdr_type id, const char *value, field_store cache)
{
    httpHeaderEntryDoInit(e, id, NULL, value, cache);
}

static void
httpHeaderEntryExtInit(HttpHeaderEntry * e, const char *name, const char *value)
{
    httpHeaderEntryDoInit(e, HDR_OTHER, name, value, strField(StringNull));
}

static void
httpHeaderEntryClean(HttpHeaderEntry * e)
{
    assert(e);
    assert_eid(e->id);
    /* type-based cleanup */
    switch (Headers[e->id].type) {
    case ftInvalid:
    case ftInt:
    case ftDate_1123:
    case ftPExtField:
	/* no special cleaning is necessary */
	break;
    case ftStr:
	stringClean(&e->cache.v_str);
	break;
    case ftPCc:
	if (e->cache.v_pcc)
	    httpHdrCcDestroy(e->cache.v_pcc);
	break;
    case ftPRange:
	if (e->cache.v_prange)
	    httpHdrRangeDestroy(e->cache.v_prange);
	break;
    case ftPContRange:
	if (e->cache.v_pcont_range)
	    httpHdrContRangeDestroy(e->cache.v_pcont_range);
	break;
    default:
	assert(0);		/* somebody added a new type? */
    }
    /* clean name if needed */
    if (e->id == HDR_OTHER)
	stringClean(&e->name);
    stringClean(&e->value);
    Headers[e->id].stat.aliveCount--;
    /* we have to do that so entry will be _invlaid_ */
    e->id = -1;
    httpHeaderFieldInit(&e->cache);
}

/* parses and inits header entry, returns true on success */
static int
httpHeaderEntryParseInit(HttpHeaderEntry * e, const char *field_start, const char *field_end, int mask)
{
    HeaderEntryParsedCount++;
    /* paranoid reset */
    memset(e, 0, sizeof(*e));
    e->id = -1;
    if (!httpHeaderEntryParse(e, field_start, field_end))
	return 0; /* total parsing failure */
    e->id = httpHeaderIdByName(strBuf(e->name), -1, Headers, HDR_ENUM_END, mask);
    debug(55, 8) ("EntryParseInit: '%s'.id = %d\n", strBuf(e->name), e->id);
    if (e->id < 0)
	e->id = HDR_OTHER;
    Headers[e->id].stat.parsCount++;
    Headers[e->id].stat.aliveCount++;
    if (e->id != HDR_OTHER) {
	/* we got something interesting, parse and cache the value */
	httpHeaderEntrySyncCache(e);
    }
    return 1;
}

static int
httpHeaderEntryParse(HttpHeaderEntry * e, const char *field_start, const char *field_end)
{
    /* note: name_start == field_start */
    const char *name_end = strchr(field_start, ':');
    const char *value_start;
    /* note: value_end == field_end */

    if (!name_end || name_end <= field_start || name_end > field_end)
	return 0;

    value_start = name_end + 1; /* skip ':' */
    /* skip white space */
    while (value_start < field_end && isspace(*value_start))
	value_start++;

    stringLimitInit(&e->name, field_start, name_end - field_start);
    stringLimitInit(&e->value, value_start, field_end - value_start);
    return 1;
}

/* tries to parse field value further and cache the result */
static void
httpHeaderEntrySyncCache(HttpHeaderEntry * e)
{
    assert(e);
    assert_eid(e->id);
    debug(55, 9) ("httpHeaderEntrySyncCache: start with %s: %s\n",
	strBuf(e->name), strBuf(e->value));
    httpHeaderFieldInit(&e->cache);
    /*
     * check for exceptions first (parsing is not determined by value type)
     * then parse using value type if needed
     */
    switch (e->id) {
    case HDR_PROXY_KEEPALIVE:
	/*  we treat Proxy-Connection as "keep alive" only if it says so */
	e->cache = intField(!strcasecmp(strBuf(e->value), "Keep-Alive"));
	break;
    case HDR_CONTENT_TYPE:
	/*  strip content type params */
	stringLimitInit(&e->cache.v_str, strBuf(e->value), 
	    strcspn(strBuf(e->value), ";\t "));
	break;
    default:
	/* if we got here, it is something that can be parsed based on value type */
	httpHeaderEntrySyncCacheByType(e);
    }
    /* post-processing */
    switch (e->id) {
    case HDR_EXPIRES:
	/*
	 * The HTTP/1.0 specs says that robust implementations should
	 * consider bad or malformed Expires header as equivalent to
	 * "expires immediately."
	 */
	if (e->cache.v_time <= 0)
	    e->cache.v_time = squid_curtime;
	/*
	 * real expiration value also depends on max-age too,
	 * HttpReply should handle that
	 */
	break;
    }
}

static void
httpHeaderEntrySyncCacheByType(HttpHeaderEntry * e)
{
    const char *err_entry_descr = NULL;
    const field_type type = Headers[e->id].type;

    debug(55, 8) ("httpHeaderEntrySyncCacheByType: id: %d type: %d\n", e->id, type);
    switch (type) {
    case ftInt:
	if (!httpHeaderParseInt(strBuf(e->value), &e->cache.v_int))
	    err_entry_descr = "integer field";
	break;
    case ftStr:
	/* we do not cache string values to avoid duplicating e->value */
	break;
    case ftDate_1123:
	e->cache.v_time = parse_rfc1123(strBuf(e->value));
	if (e->cache.v_time <= 0)
	    err_entry_descr = "date field";
	break;
    case ftPCc:
	e->cache.v_pcc = httpHdrCcParseCreate(strBuf(e->value));
	if (!e->cache.v_pcc)
	    err_entry_descr = "cache control hdr";
	break;
    case ftPRange:
	e->cache.v_prange = httpHdrRangeParseCreate(strBuf(e->value));
	if (!e->cache.v_prange)
	    err_entry_descr = "range hdr";
	break;
    case ftPContRange:
	e->cache.v_pcont_range = httpHdrContRangeParseCreate(strBuf(e->value));
	if (!e->cache.v_pcont_range)
	    err_entry_descr = "content range hdr";
	break;
    default:
	debug(55, 2) ("something went wrong with hdr field type analysis: id: %d, type: %d, field: '%s: %s'\n",
	    e->id, type, strBuf(e->name), strBuf(e->value));
	assert(0);
    }
    /* notify of failure if any */
    if (err_entry_descr) {
	debug(55, 2) ("failed to parse %s: id: %d, field: '%s: %s'\n",
	    err_entry_descr, e->id, strBuf(e->name), strBuf(e->value));
	Headers[e->id].stat.errCount++;
    }
}

static HttpHeaderEntry
httpHeaderEntryClone(const HttpHeaderEntry * e)
{
    HttpHeaderEntry clone;
    assert(e);
    assert_eid(e->id);
    if (e->id == HDR_OTHER)
	httpHeaderEntryExtInit(&clone, strBuf(e->name), strBuf(e->value));
    else
	httpHeaderEntryInit(&clone, e->id, strBuf(e->value),
	    httpHeaderFieldDup(Headers[e->id].type, e->cache));
    return clone;
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
httpHeaderEntryJoinWith(HttpHeaderEntry * e, const HttpHeaderEntry * newe)
{
    field_type type;
    assert(e && newe);
    assert_eid(e->id);
    assert(e->id == newe->id);

    debug(55, 6) ("joining entry (%p) with (%p)\n", e, newe);
    /* append value */
    stringAppend(&e->value, ",", 1);
    stringAppend(&e->value, strBuf(newe->value), strLen(newe->value));
    /* type-based join */
    type = Headers[e->id].type;
    switch (type) {
    case ftStr:
	assert(!strBuf(e->cache.v_str)); /* currently others should not be join-able */
	break;
    case ftPCc:
	httpHdrCcJoinWith(e->cache.v_pcc, newe->cache.v_pcc);
	break;
    default:
	debug(55, 0) ("join for invalid/unknown type: id: %d, type: %d\n", e->id, type);
	assert(0);
    }
}


#if OLD_CODE
static int
httpHeaderFieldIsValid(field_type type, const HttpHeaderEntry * e)
{
    /* type-based analysis */
    switch (type) {
    case ftInvalid:
	return 0;
    case ftInt:
	return e->cache.v_int >= 0;
    case ftStr:
	return strBuf(e->cache.v_str) != NULL;
    case ftDate_1123:
	return e->cache.v_time >= 0;
    case ftPCc:
	return e->cache.v_pcc != NULL;
    case ftPRange:
	return e->cache.v_prange != NULL;
    case ftPContRange:
	return e->cache.v_pcont_range != NULL;
    default:
	assert(0);		/* query for invalid/unknown type */
    }
    return 0;			/* not reached */
}
#endif

/*
 * HttpHeaderField
 */

static void
httpHeaderFieldInit(field_store * field)
{
    assert(field);
    memset(field, 0, sizeof(field_store));
}

static field_store
httpHeaderFieldDup(field_type type, field_store value)
{
    /* type based duplication */
    switch (type) {
    case ftInt:
    case ftDate_1123:
	return value;
    case ftStr:
	return strField(stringDup(&value.v_str));
    case ftPCc:
	return ptrField(httpHdrCcDup(value.v_pcc));
    case ftPRange:
	return ptrField(httpHdrRangeDup(value.v_prange));
    case ftPContRange:
	return ptrField(httpHdrContRangeDup(value.v_pcont_range));
    default:
	assert(0);		/* dup of invalid/unknown type */
    }
    return ptrField(NULL);	/* not reached */
}

/*
 * bad value table; currently bad values are determined by field type, but this
 * can be changed in the future to reflect dependence on entry id if any
 */
static field_store
httpHeaderFieldBadValue(field_type type)
{
    switch (type) {
    case ftInt:
	return intField(-1);
    case ftDate_1123:
	return timeField(-1);
    case ftStr:
	return strField(StringNull);
    case ftPCc:
    case ftPRange:
    case ftPContRange:
	return ptrField(NULL);
    case ftInvalid:
    default:
	assert(0);		/* query for invalid/unknown type */
    }
    return ptrField(NULL);	/* not reached */
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
    storeAppendPrintf(e, "<h3>Number of fields per header distribution (init size: %d)</h3>\n",
	INIT_FIELDS_PER_HEADER);
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
	    xpercent(f->stat.repCount, f->stat.parsCount));
    }
    storeAppendPrintf(e, "Headers Parsed: %d\n", HeaderParsedCount);
    storeAppendPrintf(e, "Hdr Fields Parsed: %d\n", HeaderEntryParsedCount);
}
