
/*
 * $Id: HttpHeader.cc,v 1.22 1998/03/08 21:26:29 rousskov Exp $
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
 * HttpHeader entry (type of entry.field is Headers[id].type)
 */
struct _HttpHeaderEntry {
    field_store field;
    short int id;
};


/* per header statistics */
typedef struct {
    const char *label;
    StatHist hdrUCountDistr;
    StatHist fieldTypeDistr;
    StatHist ccTypeDistr;
} HttpHeaderStat;


/* use HttpHeaderPos as opaque type, do not interpret */
typedef ssize_t HttpHeaderPos;
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
static field_attrs_t Headers[] =
{
    {"Accept", HDR_ACCEPT, ftStr},
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
    {"Set-Cookie", HDR_SET_COOKIE, ftStr},
    {"Upgrade", HDR_UPGRADE, ftStr},	/* for now */
    {"Warning", HDR_WARNING, ftStr},	/* for now */
    {"WWW-Authenticate", HDR_WWW_AUTHENTICATE, ftStr},
    {"Other:", HDR_OTHER, ftPExtField}	/* ':' will not allow matches */
};

/*
 * headers with field values defined as #(values) in HTTP/1.1
 *
 * We have listed all possible list headers according to
 * draft-ietf-http-v11-spec-rev-01.txt. Headers that are currently not
 * recognized, are commented out.
 */
static int ListHeadersMask = 0;	/* set run-time using  ListHeaders */
static http_hdr_type ListHeaders[] =
{
    HDR_ACCEPT,
    /* HDR_ACCEPT_CHARSET, HDR_ACCEPT_ENCODING, HDR_ACCEPT_LANGUAGE, */
    /* HDR_ACCEPT_RANGES, */
    /* HDR_ALLOW, */
    HDR_CACHE_CONTROL, HDR_CONNECTION,
    HDR_CONTENT_ENCODING,
    /* HDR_CONTENT_LANGUAGE, */
    /*  HDR_IF_MATCH, HDR_IF_NONE_MATCH, HDR_PRAGMA, */
    HDR_RANGE,
    /* HDR_TRANSFER_ENCODING, */
    HDR_UPGRADE,		/* HDR_VARY, */
    /* HDR_VIA, HDR_WARNING, */
    HDR_WWW_AUTHENTICATE,
    /* HDR_EXPECT, HDR_TE, HDR_TRAILER */
};

static int ReplyHeadersMask = 0;	/* set run-time using ReplyHeaders */
static http_hdr_type ReplyHeaders[] =
{
    HDR_ACCEPT, HDR_AGE, HDR_CACHE_CONTROL, HDR_CONTENT_LENGTH,
    HDR_CONTENT_MD5, HDR_CONTENT_TYPE, HDR_DATE, HDR_ETAG, HDR_EXPIRES,
    HDR_LAST_MODIFIED, HDR_LOCATION, HDR_MAX_FORWARDS, HDR_PUBLIC, HDR_RETRY_AFTER,
    HDR_SET_COOKIE, HDR_UPGRADE, HDR_WARNING, HDR_PROXY_KEEPALIVE, HDR_OTHER
};

static int RequestHeadersMask = 0;	/* set run-time using RequestHeaders */
static http_hdr_type RequestHeaders[] =
{
    HDR_CONTENT_RANGE, HDR_OTHER
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
static void httpHeaderDelAt(HttpHeader * hdr, HttpHeaderPos pos);
static void httpHeaderAddParsedEntry(HttpHeader * hdr, HttpHeaderEntry * e);
static void httpHeaderAddNewEntry(HttpHeader * hdr, const HttpHeaderEntry * e);
static field_store httpHeaderGet(const HttpHeader * hdr, http_hdr_type id);
static void httpHeaderSet(HttpHeader * hdr, http_hdr_type id, const field_store value);
static void httpHeaderSyncMasks(HttpHeader * hdr, const HttpHeaderEntry * e, int add);
static void httpHeaderGrow(HttpHeader * hdr);

static void httpHeaderEntryInit(HttpHeaderEntry * e, http_hdr_type id, field_store field);
static void httpHeaderEntryClean(HttpHeaderEntry * e);
static int httpHeaderEntryParseInit(HttpHeaderEntry * e, const char *field_start, const char *field_end, int mask);
static int httpHeaderEntryParseExtFieldInit(HttpHeaderEntry * e, int id, const HttpHdrExtField * f);
static int httpHeaderEntryParseByTypeInit(HttpHeaderEntry * e, int id, const HttpHdrExtField * f);
static HttpHeaderEntry httpHeaderEntryClone(const HttpHeaderEntry * e);
static void httpHeaderEntryPackInto(const HttpHeaderEntry * e, Packer * p);
static void httpHeaderEntryPackByType(const HttpHeaderEntry * e, Packer * p);
static void httpHeaderEntryJoinWith(HttpHeaderEntry * e, const HttpHeaderEntry * newe);
static int httpHeaderEntryIsValid(const HttpHeaderEntry * e);
static const char *httpHeaderEntryName(const HttpHeaderEntry * e);

static void httpHeaderFieldInit(field_store * field);
static field_store httpHeaderFieldDup(field_type type, field_store value);
static field_store httpHeaderFieldBadValue(field_type type);

static void httpHeaderStatInit(HttpHeaderStat * hs, const char *label);
static void httpHeaderStatDump(const HttpHeaderStat * hs, StoreEntry * e);

/* handy to determine the #elements in a static array */
#define countof(arr) (sizeof(arr)/sizeof(*arr))

/*
 * some compilers do not want to convert a type into a union which that type
 * belongs to
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
    f.v_pefield = (HttpHdrExtField *) p;
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
    /* have to force removal of const here */
    httpHeaderInitAttrTable((field_attrs_t *) Headers, countof(Headers));
    /* create masks */
    ListHeadersMask = httpHeaderCalcMask((const int *) ListHeaders, countof(ListHeaders));
    ReplyHeadersMask = httpHeaderCalcMask((const int *) ReplyHeaders, countof(ReplyHeaders));
    RequestHeadersMask = httpHeaderCalcMask((const int *) RequestHeaders, countof(RequestHeaders));
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


HttpHeader *
httpHeaderCreate()
{
    HttpHeader *hdr = xmalloc(sizeof(HttpHeader));
    httpHeaderInit(hdr);
    return hdr;
}


/* "create" for non-alloc objects; also used by real Create */
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
	    httpHdrCcUpdateStats(e->field.v_pcc, &HttpHeaderStats[0].ccTypeDistr);
	httpHeaderDelAt(hdr, pos);
    }
    xfree(hdr->entries);
    hdr->emask = 0;
    hdr->entries = NULL;
    hdr->capacity = hdr->ucount = 0;
}

void
httpHeaderDestroy(HttpHeader * hdr)
{
    httpHeaderClean(hdr);
    xfree(hdr);
}

/* create a copy of self */
HttpHeader *
httpHeaderClone(HttpHeader * hdr)
{
    HttpHeader *clone = httpHeaderCreate();
    HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;

    debug(55, 7) ("cloning hdr: %p -> %p\n", hdr, clone);

    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	HttpHeaderEntry e_clone = httpHeaderEntryClone(e);
	httpHeaderAddNewEntry(clone, &e_clone);
    }

    return clone;
}

/* just handy in parsing: resets and returns false */
static int
httpHeaderReset(HttpHeader * hdr)
{
    httpHeaderClean(hdr);
    httpHeaderInit(hdr);
    return 0;
}

/*
 * Note: currently, in most cases, we discard a field if we cannot parse it.  We
 * also truncate some field values (e.g. content-type).  Thus, we may not
 * forward exactly what was received. However, Squid keeps a copy of "raw"
 * headers anyway, so we are safe until that changes. A possible alternative
 * would be to store any buggy field as HDR_OTHER, but that still leaves a
 * problem with truncated fields. The later one requires a better parser and
 * additional storage, I guess.
 */
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
	if (!*field_end)
	    return httpHeaderReset(hdr);	/* missing <CRLF> */
	/*
	 * If we fail to parse a field, we ignore that field. We also could
	 * claim that the whole header is invalid. The latter is safer, but less
	 * robust. Note that we should be able to parse any commonn format field
	 */
	if (!httpHeaderEntryParseInit(&e, field_start, field_end, mask))
	    debug(55, 2) ("warning: ignoring unparseable http header field near '%s'\n",
		getStringPrefix(field_start));
	else
	    httpHeaderAddParsedEntry(hdr, &e);
	/*
	 * Note that we init() e, bit never clean() it which is equivalent to *
	 * creating a fresh entry on each loop iteration; thus, it is safe to *
	 * add e without dup()-ing it.
	 */
	field_start = field_end;
	/* skip CRLF */
	if (*field_start == '\r')
	    field_start++;
	if (*field_start == '\n')
	    field_start++;
    }
    return 1;			/* even if no fields where found, they could be optional! */
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
	if (httpHeaderEntryIsValid(e)) {
	    debug(55, 8) ("%p returning entry: %s at %d\n",
		hdr, httpHeaderEntryName(e), *pos);
	    return e;
	}
    }
    debug(55, 8) ("no more entries in hdr %p\n", hdr);
    return NULL;
}

/*
 * returns a pointer to a specified entry and updates pos; 
 * note that we search from the very begining so it does not make much sense to
 * ask for HDR_OTHER entries since there could be more than one.
 */
static HttpHeaderEntry *
httpHeaderFindEntry(const HttpHeader * hdr, http_hdr_type id, HttpHeaderPos * pos)
{
    HttpHeaderPos p;
    HttpHeaderEntry *e;
    int is_absent;
    assert(hdr);
    assert_eid(id);
    assert(id != HDR_OTHER);

    debug(55, 8) ("finding entry %d in hdr %p\n", id, hdr);
    /* check mask first @?@ @?@ remove double checking and asserts when done */
    is_absent = (id != HDR_OTHER && !EBIT_TEST(hdr->emask, id));
    if (!pos)
	pos = &p;
    *pos = HttpHeaderInitPos;
    while ((e = httpHeaderGetEntry(hdr, pos))) {
	if (e->id == id) {
	    assert(!is_absent);
	    return e;
	}
    }
    assert(!EBIT_TEST(hdr->emask, id));
    return NULL;
}

/*
 * deletes all field(s) with a given name if any, returns #fields deleted; 
 * used to process Connection: header and delete fields in "paranoid" setup
 */
int
httpHeaderDelFields(HttpHeader * hdr, const char *name)
{
    int count = 0;
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;

    debug(55, 7) ("deleting '%s' fields in hdr %p\n", name, hdr);
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	if (!strcmp(httpHeaderEntryName(e), name)) {
	    httpHeaderDelAt(hdr, pos);
	    count++;
	}
    }
    return count;
}

/*
 * deletes an entry at pos and leaves a gap; leaving a gap makes it
 * possible to iterate(search) and delete fields at the same time
 */
static void
httpHeaderDelAt(HttpHeader * hdr, HttpHeaderPos pos)
{
    HttpHeaderEntry *e;
    assert(hdr);
    assert(pos >= 0 && pos < hdr->ucount);
    e = hdr->entries + pos;
    debug(55, 7) ("%p deling entry at %d: id: %d (%p:%p)\n",
	hdr, pos, e->id, hdr->entries, e);
    /* sync masks */
    httpHeaderSyncMasks(hdr, e, 0);
    httpHeaderEntryClean(e);
    if (pos == hdr->ucount)
	hdr->ucount--;
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

    /* there is no good reason to add invalid entries */
    if (!httpHeaderEntryIsValid(e))
	return;
    olde = (e->id == HDR_OTHER) ? NULL : httpHeaderFindEntry(hdr, e->id, NULL);
    if (olde) {
	if (EBIT_TEST(ListHeadersMask, e->id))
	    httpHeaderEntryJoinWith(olde, e);
	else {
	    debug(55, 2) ("ignoring duplicate header: %s\n", httpHeaderEntryName(e));
	    Headers[e->id].stat.repCount++;
	}
	httpHeaderEntryClean(e);
    } else {
	/* actual add */
	httpHeaderAddNewEntry(hdr, e);
	debug(55, 6) ("%p done adding parsed entry %d (%s)\n", hdr, e->id, httpHeaderEntryName(e));
    }
}

/*
 * adds a new entry (low level append, does not check if entry is new) note: we
 * copy e value, thus, e can point to a tmp variable (but e->field is not dupped!)
 */
static void
httpHeaderAddNewEntry(HttpHeader * hdr, const HttpHeaderEntry * e)
{
    assert(hdr && e);
    debug(55, 8) ("%p adding entry: %d at %d, (%p:%p)\n",
	hdr, e->id, hdr->ucount,
	hdr->entries, hdr->entries + hdr->ucount);
    if (hdr->ucount >= hdr->capacity)
	httpHeaderGrow(hdr);
    hdr->entries[hdr->ucount++] = *e;
    /* sync masks */
    httpHeaderSyncMasks(hdr, e, 1);
}


/*
 * Global (user level) routines
 */

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

/* delete a field if any */
void
httpHeaderDel(HttpHeader * hdr, http_hdr_type id)
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    assert(id != HDR_OTHER);
    debug(55, 8) ("%p del-by-id %d\n", hdr, id);
    if (httpHeaderFindEntry(hdr, id, &pos)) {
	httpHeaderDelAt(hdr, pos);
    }
}

/*
 * set a field
 * setting an invaid value is equivalent to deleting a field
 * (if field is not present, it is added; otherwise, old content is destroyed).
 */
static void
httpHeaderSet(HttpHeader * hdr, http_hdr_type id, const field_store value)
{
    HttpHeaderPos pos;
    HttpHeaderEntry e;
    assert(hdr);
    assert_eid(id);

    debug(55, 7) ("%p sets entry with id: %d\n", hdr, id);
    if (httpHeaderFindEntry(hdr, id, &pos))	/* delete old entry */
	httpHeaderDelAt(hdr, pos);

    httpHeaderEntryInit(&e, id, httpHeaderFieldDup(Headers[id].type, value));
    if (httpHeaderEntryIsValid(&e))
	httpHeaderAddNewEntry(hdr, &e);
    else
	httpHeaderEntryClean(&e);
}

void
httpHeaderSetInt(HttpHeader * hdr, http_hdr_type id, int number)
{
    field_store value;
    assert_eid(id);
    assert(Headers[id].type == ftInt);	/* must be of an appropriatre type */
    value.v_int = number;
    httpHeaderSet(hdr, id, value);
}

void
httpHeaderSetTime(HttpHeader * hdr, http_hdr_type id, time_t time)
{
    field_store value;
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123);	/* must be of an appropriatre type */
    value.v_time = time;
    httpHeaderSet(hdr, id, value);
}

void
httpHeaderSetStr(HttpHeader * hdr, http_hdr_type id, const char *str)
{
    field_store value;
    assert_eid(id);
    assert(Headers[id].type == ftStr);	/* must be of a string type */
    stringInit(&value.v_str, str);
    httpHeaderSet(hdr, id, value);
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
    HttpHdrExtField *ext = httpHdrExtFieldCreate(name, value);
    HttpHeaderEntry e;

    debug(55, 8) ("%p adds ext entry '%s:%s'\n", hdr, name, value);
    httpHeaderEntryInit(&e, HDR_OTHER, ptrField(ext));
    httpHeaderAddNewEntry(hdr, &e);
}

/* get a value of a field (not lvalue though) */
static field_store
httpHeaderGet(const HttpHeader * hdr, http_hdr_type id)
{
    HttpHeaderEntry *e;
    assert_eid(id);
    assert(id != HDR_OTHER);	/* there is no single value for HDR_OTHER */

    debug(55, 7) ("%p get for id %d\n", hdr, id);
    if ((e = httpHeaderFindEntry(hdr, id, NULL)))
	return e->field;
    else
	return httpHeaderFieldBadValue(Headers[id].type);
}

int
httpHeaderGetInt(const HttpHeader * hdr, http_hdr_type id)
{
    assert_eid(id);
    assert(Headers[id].type == ftInt);	/* must be of an apropriate type */
    return httpHeaderGet(hdr, id).v_int;
}

const char *
httpHeaderGetStr(const HttpHeader * hdr, http_hdr_type id)
{
    assert_eid(id);
    assert(Headers[id].type == ftStr);	/* must be of an apropriate type */
    return strBuf(httpHeaderGet(hdr, id).v_str);
}

time_t
httpHeaderGetTime(const HttpHeader * hdr, http_hdr_type id)
{
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123);	/* must be of an apropriate type */
    return httpHeaderGet(hdr, id).v_time;
}

HttpHdrCc *
httpHeaderGetCc(const HttpHeader * hdr)
{
    return httpHeaderGet(hdr, HDR_CACHE_CONTROL).v_pcc;
}

HttpHdrRange *
httpHeaderGetRange(const HttpHeader * hdr)
{
    return httpHeaderGet(hdr, HDR_RANGE).v_prange;
}

HttpHdrContRange *
httpHeaderGetContRange(const HttpHeader * hdr)
{
    return httpHeaderGet(hdr, HDR_CONTENT_RANGE).v_pcont_range;
}

/* updates header masks */
static void
httpHeaderSyncMasks(HttpHeader * hdr, const HttpHeaderEntry * e, int add)
{
    int isSet;
    assert(hdr && e);
    assert_eid(e->id);

    /* we cannot mask HDR_OTHER because it may not be unique */
    if (e->id == HDR_OTHER)
	return;
    isSet = EBIT_TEST(hdr->emask, e->id) != 0;
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
httpHeaderEntryInit(HttpHeaderEntry * e, http_hdr_type id, field_store field)
{
    assert(e);
    assert_eid(id);
    e->id = id;
    e->field = field;
    Headers[id].stat.aliveCount++;
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
	/* no special cleaning is necessary */
	break;
    case ftStr:
	stringClean(&e->field.v_str);
	break;
    case ftPCc:
	if (e->field.v_pcc)
	    httpHdrCcDestroy(e->field.v_pcc);
	break;
    case ftPRange:
	if (e->field.v_prange)
	    httpHdrRangeDestroy(e->field.v_prange);
	break;
    case ftPContRange:
	if (e->field.v_pcont_range)
	    httpHdrContRangeDestroy(e->field.v_pcont_range);
	break;
    case ftPExtField:
	if (e->field.v_pefield)
	    httpHdrExtFieldDestroy(e->field.v_pefield);
	break;
    default:
	assert(0);		/* somebody added a new type? */
    }
    Headers[e->id].stat.aliveCount--;
    /* we have to do that so entry will be _invlaid_ */
    e->id = -1;
    memset(&e->field, 0, sizeof(e->field));
}

/* parses and inits header entry, returns true on success */
static int
httpHeaderEntryParseInit(HttpHeaderEntry * e, const char *field_start, const char *field_end, int mask)
{
    HttpHdrExtField *f;
    int id;
    int result;

    HeaderEntryParsedCount++;
    /* paranoid reset */
    e->id = -1;
    memset(&e->field, 0, sizeof(e->field));
    /* first assume it is just an extension field */
    f = httpHdrExtFieldParseCreate(field_start, field_end);
    if (!f)			/* total parsing failure */
	return 0;
    id = httpHeaderIdByName(strBuf(f->name), -1, Headers, countof(Headers), mask);
    if (id < 0)
	id = HDR_OTHER;
    Headers[id].stat.parsCount++;
    if (id == HDR_OTHER) {
	/* hm.. it is an extension field indeed */
	httpHeaderEntryInit(e, id, ptrField(f));
	return 1;
    }
    /* ok, we got something interesting, parse it further */
    result = httpHeaderEntryParseExtFieldInit(e, id, f);
    /* do not need it anymore */
    httpHdrExtFieldDestroy(f);
    return result;
}

static int
httpHeaderEntryParseExtFieldInit(HttpHeaderEntry * e, int id, const HttpHdrExtField * f)
{
    assert(e && f);
    assert_eid(id);
    e->id = -1;
    /*
     * check for exceptions first (parsing is not determined by value type)
     * then parse using value type if needed
     */
    switch (id) {
    case HDR_PROXY_KEEPALIVE:
	/*  we treat Proxy-Connection as "keep alive" only if it says so */
	httpHeaderEntryInit(e, id, intField(!strcasecmp(strBuf(f->value), "Keep-Alive")));
	break;
    default:
	/* if we got here, it is something that can be parsed based on value type */
	if (!httpHeaderEntryParseByTypeInit(e, id, f))
	    return 0;
    }
    /* parsing was successful, post-processing maybe required */
    switch (id) {
    case HDR_CONTENT_TYPE: {
	    /* cut off "; parameter" from Content-Type @?@ why? */
	    const int l = strcspn(strBuf(e->field.v_str), ";\t ");
	    if (l > 0)
		strCut(e->field.v_str, l);
	    break;
	}
    case HDR_EXPIRES:
	/*
	 * The HTTP/1.0 specs says that robust implementations should
	 * consider bad or malformed Expires header as equivalent to
	 * "expires immediately."
	 */
	if (!httpHeaderEntryIsValid(e))
	    e->field.v_time = squid_curtime;
	/*
	 * real expiration value also depends on max-age too, but it is not
	 * of our business (HttpReply should handle it)
	 */
	break;
    }
    return 1;
}

static int
httpHeaderEntryParseByTypeInit(HttpHeaderEntry * e, int id, const HttpHdrExtField * f)
{
    const char *err_entry_descr = NULL;
    int type;
    field_store field;
    assert(e && f);
    assert_eid(id);
    type = Headers[id].type;

    httpHeaderFieldInit(&field);
    switch (type) {
    case ftInt:
	if (!httpHeaderParseInt(strBuf(f->value), &field.v_int))
	    err_entry_descr = "integer field";
	break;
    case ftStr:
	field.v_str = stringDup(&f->value);
	break;
    case ftDate_1123:
	field.v_time = parse_rfc1123(strBuf(f->value));
	if (field.v_time <= 0)
	    Headers[id].stat.errCount++;
	/*
	 * if parse_rfc1123 fails we fall through anyway so upper levels
	 * will notice invalid date rather than unparsible header
	 */
	break;
    case ftPCc:
	field.v_pcc = httpHdrCcParseCreate(strBuf(f->value));
	if (!field.v_pcc)
	    err_entry_descr = "cache control hdr";
	break;
    case ftPRange:
	field.v_prange = httpHdrRangeParseCreate(strBuf(f->value));
	if (!field.v_prange)
	    err_entry_descr = "range hdr";
	break;
    case ftPContRange:
	field.v_pcont_range = httpHdrContRangeParseCreate(strBuf(f->value));
	if (!field.v_pcont_range)
	    err_entry_descr = "content range hdr";
	break;
    default:
	debug(55, 2) ("something went wrong with hdr field type analysis: id: %d, type: %d, field: '%s: %s'\n",
	    id, type, strBuf(f->name), strBuf(f->value));
	assert(0);
    }
    /* failure ? */
    if (err_entry_descr) {
	debug(55, 2) ("failed to parse %s: id: %d, field: '%s: %s'\n",
	    err_entry_descr, id, strBuf(f->name), strBuf(f->value));
	Headers[id].stat.errCount++;
	return 0;
    }
    /* success, do actual init */
    httpHeaderEntryInit(e, id, field);
    return 1;
}

static HttpHeaderEntry
httpHeaderEntryClone(const HttpHeaderEntry * e)
{
    HttpHeaderEntry clone;
    assert(e);
    assert_eid(e->id);
    httpHeaderEntryInit(&clone, e->id,
	httpHeaderFieldDup(Headers[e->id].type, e->field));
    return clone;
}

static void
httpHeaderEntryPackInto(const HttpHeaderEntry * e, Packer * p)
{
    assert(e && p);

    /* pack the field_name: */
    packerPrintf(p, "%s: ", httpHeaderEntryName(e));
    /*
     * pack the value
     * check for exceptions (packing is not determined by value type)
     * then swap using value type
     */
    switch (e->id) {
    case HDR_PROXY_KEEPALIVE:
	packerPrintf(p, "%s", "Keep-Alive");
	break;
    default:
	/* if we got here, it is something that can be swap based on value type */
	httpHeaderEntryPackByType(e, p);
    }
    /* add CRLF */
    packerPrintf(p, "%s", "\r\n");
}

static void
httpHeaderEntryPackByType(const HttpHeaderEntry * e, Packer * p)
{
    field_type type;
    assert(e && p);
    assert_eid(e->id);
    type = Headers[e->id].type;
    switch (type) {
    case ftInt:
	packerPrintf(p, "%d", e->field.v_int);
	break;
    case ftStr:
	packerPrintf(p, "%s", strBuf(e->field.v_str));
	break;
    case ftDate_1123:
	packerPrintf(p, "%s", mkrfc1123(e->field.v_time));
	break;
    case ftPCc:
	httpHdrCcPackInto(e->field.v_pcc, p);
	break;
    case ftPRange:
	httpHdrRangePackInto(e->field.v_prange, p);
	break;
    case ftPContRange:
	httpHdrContRangePackInto(e->field.v_pcont_range, p);
	break;
    case ftPExtField:
	packerPrintf(p, "%s", strBuf(e->field.v_pefield->value));
	break;
    default:
	assert(0 && type);	/* pack for invalid/unknown type */
    }
}

static void
httpHeaderEntryJoinWith(HttpHeaderEntry * e, const HttpHeaderEntry * newe)
{
    field_type type;
    assert(e && newe);
    assert_eid(e->id);
    assert(e->id == newe->id);

    debug(55, 6) ("joining entry (%p) with (%p)\n", e, newe);
    /* type-based join */
    type = Headers[e->id].type;
    switch (type) {
    case ftStr:
	stringAppend(&e->field.v_str, ",", 1);
	stringAppend(&e->field.v_str, strBuf(newe->field.v_str), strLen(newe->field.v_str));
	break;
    case ftPCc:
	httpHdrCcJoinWith(e->field.v_pcc, newe->field.v_pcc);
	break;
    case ftPRange:
	httpHdrRangeJoinWith(e->field.v_prange, newe->field.v_prange);
	break;
    default:
	debug(55, 0) ("join for invalid/unknown type: id: %d, type: %d\n", e->id, type);
	assert(0);
    }
}


static int
httpHeaderEntryIsValid(const HttpHeaderEntry * e)
{
    assert(e);
    if (e->id == -1)
	return 0;
    assert_eid(e->id);
    /* type-based analysis */
    switch (Headers[e->id].type) {
    case ftInvalid:
	return 0;
    case ftInt:
	return e->field.v_int >= 0;
    case ftStr:
	return strBuf(e->field.v_str) != NULL;
    case ftDate_1123:
	return e->field.v_time >= 0;
    case ftPCc:
	return e->field.v_pcc != NULL;
    case ftPRange:
	return e->field.v_prange != NULL;
    case ftPContRange:
	return e->field.v_pcont_range != NULL;
    case ftPExtField:
	return e->field.v_pefield != NULL;
    default:
	assert(0);		/* query for invalid/unknown type */
    }
    return 0;			/* not reached */
}

static const char *
httpHeaderEntryName(const HttpHeaderEntry * e)
{
    assert(e);
    assert_eid(e->id);

    return (e->id == HDR_OTHER) ?
	strBuf(e->field.v_pefield->name) : Headers[e->id].name;
}

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
    case ftPExtField:
	return ptrField(httpHdrExtFieldDup(value.v_pefield));
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
    case ftPExtField:
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
    const char *name = valid_id ? Headers[id].name : "INVALID";
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
	field_attrs_t *f = Headers + ht;
	storeAppendPrintf(e, "%2d\t %-20s\t %5d\t %6.3f\t %6.3f\n",
	    f->id, f->name, f->stat.aliveCount,
	    xpercent(f->stat.errCount, f->stat.parsCount),
	    xpercent(f->stat.repCount, f->stat.parsCount));
    }
    storeAppendPrintf(e, "Headers Parsed: %d\n", HeaderParsedCount);
    storeAppendPrintf(e, "Hdr Fields Parsed: %d\n", HeaderEntryParsedCount);
}
