/*
 * $Id: HttpHeader.cc,v 1.12 1998/03/03 22:17:50 rousskov Exp $
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

/* HTTP/1.1 extension-header */
struct _HttpHeaderExtField {
    char *name;			/* field-name  from HTTP/1.1 (no column after name!) */
    char *value;		/* field-value from HTTP/1.1 */
};

/* possible types for fields */
typedef enum {
    ftInvalid = HDR_ENUM_END,	/* to catch nasty errors with hdr_id<->fld_type clashes */
    ftInt,
    ftPChar,
    ftDate_1123,
    ftPSCC,
    ftPExtField
} field_type;

/*
 * HttpHeader entry 
 * ( the concrete type of entry.field is Headers[id].type )
 */
struct _HttpHeaderEntry {
    field_store field;
    http_hdr_type id;
};


/* counters and size accumulators for stat objects */
typedef int StatCount;
typedef size_t StatSize;

/* per field statistics */
typedef struct {
    StatCount aliveCount;	/* created but not destroyed (count) */
    StatCount parsCount;	/* #parsing attempts */
    StatCount errCount;		/* #pasring errors */
    StatCount repCount;		/* #repetitons */
} HttpHeaderFieldStat;

/* per header statistics */
typedef struct {
    const char *label;
    StatHist hdrUCountDistr;
    StatHist fieldTypeDistr;
    StatHist ccTypeDistr;
} HttpHeaderStat;


/* constant attributes of fields */
typedef struct {
    const char *name;
    http_hdr_type id;
    field_type type;
    int name_len;
    HttpHeaderFieldStat stat;
} field_attrs_t;

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
    {"Accept", HDR_ACCEPT, ftPChar},
    {"Age", HDR_AGE, ftInt},
    {"Cache-Control", HDR_CACHE_CONTROL, ftPSCC},
    {"Connection", HDR_CONNECTION, ftPChar},	/* for now */
    {"Content-Encoding", HDR_CONTENT_ENCODING, ftPChar},
    {"Content-Length", HDR_CONTENT_LENGTH, ftInt},
    {"Content-MD5", HDR_CONTENT_MD5, ftPChar},	/* for now */
    {"Content-Type", HDR_CONTENT_TYPE, ftPChar},
    {"Date", HDR_DATE, ftDate_1123},
    {"Etag", HDR_ETAG, ftPChar},	/* for now */
    {"Expires", HDR_EXPIRES, ftDate_1123},
    {"Host", HDR_HOST, ftPChar},
    {"If-Modified-Since", HDR_IMS, ftDate_1123},
    {"Last-Modified", HDR_LAST_MODIFIED, ftDate_1123},
    {"Location", HDR_LOCATION, ftPChar},
    {"Max-Forwards", HDR_MAX_FORWARDS, ftInt},
    {"Proxy-Authenticate", HDR_PROXY_AUTHENTICATE, ftPChar},
    {"Public", HDR_PUBLIC, ftPChar},
    {"Retry-After", HDR_RETRY_AFTER, ftPChar},	/* for now */
    /* fix this: make count-but-treat as OTHER mask @?@ @?@ */
    {"Set-Cookie:", HDR_SET_COOKIE, ftPChar},
    {"Upgrade", HDR_UPGRADE, ftPChar},	/* for now */
    {"Warning", HDR_WARNING, ftPChar},	/* for now */
    {"WWW-Authenticate", HDR_WWW_AUTHENTICATE, ftPChar},
    {"Proxy-Connection", HDR_PROXY_KEEPALIVE, ftInt},	/* true/false */
    {"Other:", HDR_OTHER, ftPExtField}	/* ':' will not allow matches */
};

/* this table is used for parsing server cache control header */
static field_attrs_t SccAttrs[] =
{
    {"public", SCC_PUBLIC},
    {"private", SCC_PRIVATE},
    {"no-cache", SCC_NO_CACHE},
    {"no-store", SCC_NO_STORE},
    {"no-transform", SCC_NO_TRANSFORM},
    {"must-revalidate", SCC_MUST_REVALIDATE},
    {"proxy-revalidate", SCC_PROXY_REVALIDATE},
    {"max-age", SCC_MAX_AGE}
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
    /* HDR_CONTENT_LANGUAGE,  HDR_IF_MATCH, HDR_IF_NONE_MATCH,
     * HDR_PRAGMA, HDR_TRANSFER_ENCODING, */
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
    HDR_OTHER
};

/* when first field is added, this is how much entries we allocate */
#define INIT_FIELDS_PER_HEADER 8

/* recycle bin for short strings (32KB total only) */
static const size_t shortStrSize = 32;	/* max size of a recyclable string */
static const size_t shortStrPoolCount = (32 * 1024) / 32;	/* sync this with shortStrSize */
static MemPool *shortStrings = NULL;

/* header accounting */
static HttpHeaderStat HttpHeaderStats[] =
{
    {"reply"},
    {"request"},
    {"all"}
};
static int HttpHeaderStatCount = sizeof(HttpHeaderStats) / sizeof(*HttpHeaderStats);

/* global counters */
static StatCount HeaderParsedCount = 0;
static StatCount CcPasredCount = 0;
static StatCount HeaderEntryParsedCount = 0;

/* long strings accounting */
static StatCount longStrAliveCount = 0;
static StatCount longStrHighWaterCount = 0;
static StatSize longStrAliveSize = 0;
static StatSize longStrHighWaterSize = 0;


/*
 * local routines
 */

#define assert_eid(id) assert((id) >= 0 && (id) < HDR_ENUM_END)

static void httpHeaderInitAttrTable(field_attrs_t * table, int count);
static int httpHeaderCalcMask(const int *enums, int count);
static void httpHeaderStatInit(HttpHeaderStat * hs, const char *label);

static HttpHeaderEntry *httpHeaderGetEntry(const HttpHeader * hdr, HttpHeaderPos * pos);
static void httpHeaderDelAt(HttpHeader * hdr, HttpHeaderPos pos);
static void httpHeaderAddParsedEntry(HttpHeader * hdr, HttpHeaderEntry * e);
static void httpHeaderAddNewEntry(HttpHeader * hdr, const HttpHeaderEntry * e);
static void httpHeaderSet(HttpHeader * hdr, http_hdr_type id, const field_store value);
static void httpHeaderSyncMasks(HttpHeader * hdr, const HttpHeaderEntry * e, int add);
static int httpHeaderIdByName(const char *name, int name_len, const field_attrs_t * attrs, int end, int mask);
static void httpHeaderGrow(HttpHeader * hdr);

static void httpHeaderEntryInit(HttpHeaderEntry * e, http_hdr_type id, field_store field);
static void httpHeaderEntryClean(HttpHeaderEntry * e);
static int httpHeaderEntryParseInit(HttpHeaderEntry * e, const char *field_start, const char *field_end, int mask);
static int httpHeaderEntryParseExtFieldInit(HttpHeaderEntry * e, int id, const HttpHeaderExtField * f);
static int httpHeaderEntryParseByTypeInit(HttpHeaderEntry * e, int id, const HttpHeaderExtField * f);
static HttpHeaderEntry httpHeaderEntryClone(const HttpHeaderEntry * e);
static void httpHeaderEntryPackInto(const HttpHeaderEntry * e, Packer * p);
static void httpHeaderEntryPackByType(const HttpHeaderEntry * e, Packer * p);
static void httpHeaderEntryJoinWith(HttpHeaderEntry * e, const HttpHeaderEntry * newe);
static int httpHeaderEntryIsValid(const HttpHeaderEntry * e);
static const char *httpHeaderEntryName(const HttpHeaderEntry * e);

static void httpHeaderFieldInit(field_store * field);
static field_store httpHeaderFieldDup(field_type type, field_store value);
static field_store httpHeaderFieldBadValue(field_type type);

static HttpScc *httpSccCreate();
static HttpScc *httpSccParseCreate(const char *str);
static void httpSccParseInit(HttpScc * scc, const char *str);
static void httpSccDestroy(HttpScc * scc);
static HttpScc *httpSccDup(HttpScc * scc);
static void httpSccUpdateStats(const HttpScc * scc, StatHist * hist);

static void httpSccPackValueInto(HttpScc * scc, Packer * p);
static void httpSccJoinWith(HttpScc * scc, HttpScc * new_scc);

static HttpHeaderExtField *httpHeaderExtFieldCreate(const char *name, const char *value);
static HttpHeaderExtField *httpHeaderExtFieldParseCreate(const char *field_start, const char *field_end);
static void httpHeaderExtFieldDestroy(HttpHeaderExtField * f);
static HttpHeaderExtField *httpHeaderExtFieldDup(HttpHeaderExtField * f);

static void httpHeaderStatDump(const HttpHeaderStat * hs, StoreEntry * e);
static void shortStringStatDump(StoreEntry * e);

static char *dupShortStr(const char *str);
static char *dupShortBuf(const char *str, size_t len);
static char *appShortStr(char *str, const char *app_str);
static char *allocShortBuf(size_t size);
static void freeShortString(char *str);

static int strListGetItem(const char *str, char del, const char **item, int *ilen, const char **pos);
static const char *getStringPrefix(const char *str);

/* handy to determine the #elements in a static array */
#define countof(arr) (sizeof(arr)/sizeof(*arr))

/*
 * some compilers do not want to convert a type into a union which that type
 * belongs to
 */
field_store intField(int n) { field_store f; f.v_int = n; return f; }
field_store timeField(time_t t) { field_store f; f.v_time = t; return f; }
field_store ptrField(void *p) { field_store f; f.v_pchar = (char*)p; return f; }

/*
 * Module initialization routines
 */

void
httpHeaderInitModule()
{
    int i;
    /* paranoid check if smbd put a big object into field_store */
    assert(sizeof(field_store) == sizeof(char *));
    /* have to force removal of const here */
    httpHeaderInitAttrTable((field_attrs_t *) Headers, countof(Headers));
    httpHeaderInitAttrTable((field_attrs_t *) SccAttrs, countof(SccAttrs));
    /* create masks */
    ListHeadersMask = httpHeaderCalcMask((const int *) ListHeaders, countof(ListHeaders));
    ReplyHeadersMask = httpHeaderCalcMask((const int *) ReplyHeaders, countof(ReplyHeaders));
    RequestHeadersMask = httpHeaderCalcMask((const int *) RequestHeaders, countof(RequestHeaders));
    /* create a pool of short strings @?@ we never destroy it! */
    shortStrings = memPoolCreate("'short http hdr strs'", shortStrSize);
    /* init header stats */
    for (i = 0; i < HttpHeaderStatCount; i++)
	httpHeaderStatInit(HttpHeaderStats + i, HttpHeaderStats[i].label);
    cachemgrRegister("http_headers",
	"HTTP Header Statistics", httpHeaderStoreReport, 0);
}

void
httpHeaderCleanModule()
{
    if (shortStrings) {
	memPoolDestroy(shortStrings);
	shortStrings = NULL;
    }
}

static void
httpHeaderInitAttrTable(field_attrs_t * table, int count)
{
    int i;
    assert(table);
    assert(count > 1);		/* to protect from buggy "countof" implementations */

    /* reorder so that .id becomes an index */
    for (i = 0; i < count;) {
	const int id = table[i].id;
	assert(id >= 0 && id < count);	/* sanity check */
	assert(id >= i);	/* entries prior to i have been indexed already */
	if (id != i) {		/* out of order */
	    const field_attrs_t fa = table[id];
	    assert(fa.id != id);	/* avoid endless loops */
	    table[id] = table[i];	/* swap */
	    table[i] = fa;
	} else
	    i++;		/* make progress */
    }

    /* calculate name lengths and init stats */
    for (i = 0; i < count; ++i) {
	assert(table[i].name);
	table[i].name_len = strlen(table[i].name);
	debug(55, 5) ("hdr table entry[%d]: %s (%d)\n", i, table[i].name, table[i].name_len);
	assert(table[i].name_len);
	/* init stats */
	memset(&table[i].stat, 0, sizeof(table[i].stat));
    }
}

static void
httpHeaderStatInit(HttpHeaderStat * hs, const char *label)
{
    assert(hs);
    assert(label);
    hs->label = label;
    statHistEnumInit(&hs->hdrUCountDistr, 32);	/* not a real enum */
    statHistEnumInit(&hs->fieldTypeDistr, HDR_ENUM_END);
    statHistEnumInit(&hs->ccTypeDistr, SCC_ENUM_END);
}

/* calculates a bit mask of a given array (move this to lib/uitils) @?@ */
static int
httpHeaderCalcMask(const int *enums, int count)
{
    int i;
    int mask = 0;
    assert(enums);
    assert(count < sizeof(int) * 8);	/* check for overflow */

    for (i = 0; i < count; ++i) {
	assert(enums[i] < sizeof(int) * 8);	/* check for overflow again */
	assert(!EBIT_TEST(mask, enums[i]));	/* check for duplicates */
	EBIT_SET(mask, enums[i]);
    }
    return mask;
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
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	/* fix this (for scc too) for req headers @?@ */
	statHistCount(&HttpHeaderStats[0].fieldTypeDistr, e->id);
	if (e->id == HDR_CACHE_CONTROL)
	    httpSccUpdateStats(e->field.v_pscc, &HttpHeaderStats[0].ccTypeDistr);
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
	    debug(55, 1) ("warning: ignoring unparseable http header field near '%s'\n",
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
    debug(55,8) ("searching next e in hdr %p from %d\n", hdr, *pos);
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
    if (!hdr->ucount)
	HeaderParsedCount++;
    if (hdr->ucount >= hdr->capacity)
	httpHeaderGrow(hdr);
    hdr->entries[hdr->ucount++] = *e;
    /* sync masks */
    httpHeaderSyncMasks(hdr, e, 1);
}

#if 0				/* save for parts */
/*
 * Splits list field and appends all entries separately; 
 * Warning: This is internal function, never call this directly, 
 *          only for httpHeaderAddField use.
 */
static void
httpHeaderAddListField(HttpHeader * hdr, HttpHeaderField * fld)
{
    const char *v;
    assert(hdr);
    assert(fld);
    /*
     * Note: assume that somebody already checked that we can split. The danger
     * is in splitting something that is not a list field but contains ','s in
     * its value.
     */
    /* we got a fld.value that is a list of values separated by ',' */
    v = strtok(fld->value, ",");
    httpHeaderAddSingleField(hdr, fld);		/* first strtok() did its job! */
    while ((v = strtok(NULL, ","))) {
	/* ltrim and skip empty fields */
	while (isspace(*v) || *v == ',')
	    v++;
	if (*v)
	    httpHeaderAddSingleField(hdr, httpHeaderFieldCreate(fld->name, v));
    }
}
#endif

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

#ifdef SLOW_BUT_SAFE
    return httpHeaderFindEntry(hdr, id, NULL) != NULL;
#endif
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
    assert(Headers[id].type == ftPChar);	/* must be of a string type */
    value.v_pcchar = str;
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
    HttpHeaderExtField *ext = httpHeaderExtFieldCreate(name, value);
    HttpHeaderEntry e;

    debug(55, 8) ("%p adds ext entry '%s:%s'\n", hdr, name, value);
    httpHeaderEntryInit(&e, HDR_OTHER, ptrField(ext));
    httpHeaderAddNewEntry(hdr, &e);
}

/* get a value of a field (not lvalue though) */
field_store
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

const char *
httpHeaderGetStr(const HttpHeader * hdr, http_hdr_type id)
{
    assert_eid(id);
    assert(Headers[id].type == ftPChar);	/* must be of an apropriate type */
    return httpHeaderGet(hdr, id).v_pchar;
}

time_t
httpHeaderGetTime(const HttpHeader * hdr, http_hdr_type id)
{
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123);	/* must be of an apropriate type */
    return httpHeaderGet(hdr, id).v_time;
}

HttpScc *
httpHeaderGetScc(const HttpHeader * hdr)
{
    return httpHeaderGet(hdr, HDR_CACHE_CONTROL).v_pscc;
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

static int
httpHeaderIdByName(const char *name, int name_len, const field_attrs_t * attrs, int end, int mask)
{
    int i;
    for (i = 0; i < end; ++i) {
	if (mask < 0 || EBIT_TEST(mask, i)) {
	    if (name_len >= 0 && name_len != attrs[i].name_len)
		continue;
	    if (!strncasecmp(name, attrs[i].name,
		    name_len < 0 ? attrs[i].name_len + 1 : name_len))
		return i;
	}
    }
    return -1;
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
    case ftPChar:
	freeShortString(e->field.v_pchar);
	break;
    case ftPSCC:
	if (e->field.v_pscc)
	    httpSccDestroy(e->field.v_pscc);
	break;
    case ftPExtField:
	if (e->field.v_pefield)
	    httpHeaderExtFieldDestroy(e->field.v_pefield);
	break;
    default:
	assert(0);		/* somebody added a new type? */
    }
    Headers[e->id].stat.aliveCount--;
    /* we have to do that so entry will be _invlaid_ */
    e->id = -1;
    e->field.v_pchar = NULL;
}

/* parses and inits header entry, returns true on success */
static int
httpHeaderEntryParseInit(HttpHeaderEntry * e, const char *field_start, const char *field_end, int mask)
{
    HttpHeaderExtField *f;
    int id;
    int result;

    HeaderEntryParsedCount++;
    /* paranoid reset */
    e->id = -1;
    e->field.v_pchar = NULL;
    /* first assume it is just an extension field */
    f = httpHeaderExtFieldParseCreate(field_start, field_end);
    if (!f)			/* total parsing failure */
	return 0;
    id = httpHeaderIdByName(f->name, -1, Headers, countof(Headers), mask);
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
    httpHeaderExtFieldDestroy(f);
    return result;
}

static int
httpHeaderEntryParseExtFieldInit(HttpHeaderEntry * e, int id, const HttpHeaderExtField * f)
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
	httpHeaderEntryInit(e, id, intField(!strcasecmp(f->value, "Keep-Alive")));
	break;
    default:
	/* if we got here, it is something that can be parsed based on value type */
	if (!httpHeaderEntryParseByTypeInit(e, id, f))
	    return 0;
    }
    /* parsing was successful, post-processing maybe required */
    switch (id) {
    case HDR_CONTENT_TYPE:{
	    /* cut off "; parameter" from Content-Type @?@ why? */
	    const int l = strcspn(e->field.v_pchar, ";\t ");
	    if (l > 0)
		e->field.v_pchar[l] = '\0';
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
httpHeaderEntryParseByTypeInit(HttpHeaderEntry * e, int id, const HttpHeaderExtField * f)
{
    int type;
    field_store field;
    assert(e && f);
    assert_eid(id);
    type = Headers[id].type;

    httpHeaderFieldInit(&field);
    switch (type) {
    case ftInt:
	field.v_int = atoi(f->value);
	if (!field.v_int && !isdigit(*f->value)) {
	    debug(55, 1) ("cannot parse an int header field: id: %d, field: '%s: %s'\n",
		id, f->name, f->value);
	    Headers[id].stat.errCount++;
	    return 0;
	}
	break;

    case ftPChar:
	field.v_pchar = dupShortStr(f->value);
	break;

    case ftDate_1123:
	field.v_time = parse_rfc1123(f->value);
	if (field.v_time <= 0)
	    Headers[id].stat.errCount++;
	/*
	 * if parse_rfc1123 fails we fall through anyway so upper levels
	 * will notice invalid date
	 */
	break;

    case ftPSCC:
	field.v_pscc = httpSccParseCreate(f->value);
	if (!field.v_pscc) {
	    debug(55, 0) ("failed to parse scc hdr: id: %d, field: '%s: %s'\n",
		id, f->name, f->value);
	    Headers[id].stat.errCount++;
	    return 0;
	}
	break;

    default:
	debug(55, 0) ("something went wrong with hdr field type analysis: id: %d, type: %d, field: '%s: %s'\n",
	    id, type, f->name, f->value);
	assert(0);
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

    /* swap the field_name: */
    packerPrintf(p, "%s: ", httpHeaderEntryName(e));
    /*
     * swap the value
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
    case ftPChar:
	packerPrintf(p, "%s", e->field.v_pchar);
	break;
    case ftDate_1123:
	packerPrintf(p, "%s", mkrfc1123(e->field.v_time));
	break;
    case ftPSCC:
	httpSccPackValueInto(e->field.v_pscc, p);
	break;
    case ftPExtField:
	packerPrintf(p, "%s", e->field.v_pefield->value);
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
    case ftPChar:
	e->field.v_pchar = appShortStr(e->field.v_pchar, newe->field.v_pchar);
	break;
    case ftPSCC:
	httpSccJoinWith(e->field.v_pscc, newe->field.v_pscc);
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
    case ftPChar:
	return e->field.v_pchar != NULL;
    case ftDate_1123:
	return e->field.v_time >= 0;
    case ftPSCC:
	return e->field.v_pscc != NULL;
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
	e->field.v_pefield->name : Headers[e->id].name;
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
    case ftPChar:
	return ptrField(dupShortStr(value.v_pchar));
    case ftPSCC:
	return ptrField(httpSccDup(value.v_pscc));
    case ftPExtField:
	return ptrField(httpHeaderExtFieldDup(value.v_pefield));
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
    case ftPChar:
    case ftPSCC:
    case ftPExtField:
	return ptrField(NULL);
    case ftInvalid:
    default:
	assert(0);		/* query for invalid/unknown type */
    }
    return ptrField(NULL);	/* not reached */
}

/*
 * HttpScc (server cache control)
 */

static HttpScc *
httpSccCreate()
{
    HttpScc *scc = memAllocate(MEM_HTTP_SCC);
    scc->max_age = -1;
    return scc;
}

/* creates an scc object from a 0-terminating string */
static HttpScc *
httpSccParseCreate(const char *str)
{
    HttpScc *scc = httpSccCreate();
    httpSccParseInit(scc, str);
    return scc;
}

/* parses a 0-terminating string and inits scc */
static void
httpSccParseInit(HttpScc * scc, const char *str)
{
    const char *item;
    const char *p;		/* '=' parameter */
    const char *pos = NULL;
    int type;
    int ilen;
    assert(scc && str);

    CcPasredCount++;
    /* iterate through comma separated list */
    while (strListGetItem(str, ',', &item, &ilen, &pos)) {
	/* strip '=' statements @?@ */
	if ((p = strchr(item, '=')) && (p - item < ilen))
	    ilen = p++ - item;
	/* find type */
	type = httpHeaderIdByName(item, ilen,
	    SccAttrs, SCC_ENUM_END, -1);
	if (type < 0) {
	    debug(55, 0) ("cc: unknown cache-directive: near '%s' in '%s'\n", item, str);
	    continue;
	}
	if (EBIT_TEST(scc->mask, type)) {
	    debug(55, 0) ("cc: ignoring duplicate cache-directive: near '%s' in '%s'\n", item, str);
	    SccAttrs[type].stat.repCount++;
	    continue;
	}
	/* update mask */
	EBIT_SET(scc->mask, type);
	/* post-processing special cases */
	switch (type) {
	case SCC_MAX_AGE:
	    if (p)
		scc->max_age = (time_t) atoi(p);
	    if (scc->max_age < 0) {
		debug(55, 0) ("scc: invalid max-age specs near '%s'\n", item);
		scc->max_age = -1;
		EBIT_CLR(scc->mask, type);
	    }
	    break;
	default:
	    /* note that we ignore most of '=' specs @?@ */
	    break;
	}
    }
    return;
}

static void
httpSccDestroy(HttpScc * scc)
{
    assert(scc);
    memFree(MEM_HTTP_SCC, scc);
}

static HttpScc *
httpSccDup(HttpScc * scc)
{
    HttpScc *dup;
    assert(scc);
    dup = httpSccCreate();
    dup->mask = scc->mask;
    dup->max_age = scc->max_age;
    return dup;
}

static void
httpSccPackValueInto(HttpScc * scc, Packer * p)
{
    http_scc_type flag;
    int pcount = 0;
    assert(scc && p);
    if (scc->max_age >= 0) {
	packerPrintf(p, "max-age=%d", scc->max_age);
	pcount++;
    }
    for (flag = 0; flag < SCC_ENUM_END; flag++) {
	if (EBIT_TEST(scc->mask, flag)) {
	    packerPrintf(p, pcount ? ", %s" : "%s", SccAttrs[flag].name);
	    pcount++;
	}
    }
}

static void
httpSccJoinWith(HttpScc * scc, HttpScc * new_scc)
{
    assert(scc && new_scc);
    if (scc->max_age < 0)
	scc->max_age = new_scc->max_age;
    scc->mask |= new_scc->mask;
}

static void
httpSccUpdateStats(const HttpScc * scc, StatHist * hist)
{
    http_scc_type c;
    assert(scc);
    for (c = 0; c < SCC_ENUM_END; c++)
	if (EBIT_TEST(scc->mask, c))
	    statHistCount(hist, c);
}

/*
 * HttpHeaderExtField
 */

static HttpHeaderExtField *
httpHeaderExtFieldCreate(const char *name, const char *value)
{
    HttpHeaderExtField *f = xcalloc(1, sizeof(HttpHeaderExtField));
    f->name = dupShortStr(name);
    f->value = dupShortStr(value);
    return f;
}

/* parses ext field; returns fresh ext field on success and NULL on failure */
static HttpHeaderExtField *
httpHeaderExtFieldParseCreate(const char *field_start, const char *field_end)
{
    HttpHeaderExtField *f = NULL;
    /* note: name_start == field_start */
    const char *name_end = strchr(field_start, ':');
    const char *value_start;
    /* note: value_end == field_end */

    if (!name_end || name_end <= field_start || name_end > field_end)
	return NULL;

    value_start = name_end + 1;	/* skip ':' */
    /* skip white space */
    while (value_start < field_end && isspace(*value_start))
	value_start++;

    /* cut off "; parameter" from Content-Type @?@ why? */
    if (!strncasecmp(field_start, "Content-Type:", 13)) {
	const int l = strcspn(value_start, ";\t ");
	if (l > 0 && value_start + l < field_end)
	    field_end = value_start + l;
    }
    f = xcalloc(1, sizeof(HttpHeaderExtField));
    f->name = dupShortBuf(field_start, name_end - field_start);
    f->value = dupShortBuf(value_start, field_end - value_start);
    debug(55, 8) ("got field: '%s: %s' (%p)\n", f->name, f->value, f);
    return f;
}

static void
httpHeaderExtFieldDestroy(HttpHeaderExtField * f)
{
    assert(f);
    freeShortString(f->name);
    freeShortString(f->value);
    xfree(f);
}

static HttpHeaderExtField *
httpHeaderExtFieldDup(HttpHeaderExtField * f)
{
    assert(f);
    return httpHeaderExtFieldCreate(f->name, f->value);
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
	    id, name, count, xdiv(count, HeaderParsedCount));
}

static void
httpHeaderCCStatDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    const int id = (int) val;
    const int valid_id = id >= 0 && id < SCC_ENUM_END;
    const char *name = valid_id ? SccAttrs[id].name : "INVALID";
    if (count || valid_id)
	storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
	    id, name, count, xdiv(count, CcPasredCount));
}


static void
httpHeaderFldsPerHdrDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    if (count)
	storeAppendPrintf(sentry, "%2d\t %5d\t %5d\t %6.2f\n",
	    idx, ((int) (val + size)), count, xpercent(count, HeaderEntryParsedCount));
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
    statHistDump(&hs->ccTypeDistr, e, httpHeaderCCStatDumper);
    storeAppendPrintf(e, "<h3>Number of fields per header distribution (init size: %d)</h3>\n",
	INIT_FIELDS_PER_HEADER);
    storeAppendPrintf(e, "%2s\t %-5s\t %5s\t %6s\n",
	"id", "#flds", "count", "%total");
    statHistDump(&hs->hdrUCountDistr, e, httpHeaderFldsPerHdrDumper);
}

static void
shortStringStatDump(StoreEntry * e)
{
    storeAppendPrintf(e, "<h3>Short String Stats</h3>\n<p>");
	memPoolReport(shortStrings, e);
    storeAppendPrintf(e, "\n</p>\n");
    storeAppendPrintf(e, "<br><h3>Long String Stats</h3>\n");
    storeAppendPrintf(e, "alive: %3d (%5.1f KB) high-water:  %3d (%5.1f KB)\n",
	longStrAliveCount, (double) longStrAliveSize / 1024.,
	longStrHighWaterCount, (double) longStrHighWaterSize / 1024.);
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
    storeAppendPrintf(e, "%s\n", "<hr size=1 noshade>");
    /* short strings */
    shortStringStatDump(e);
}


/*
 * "short string" routines below are trying to recycle memory for short strings
 */

static char *
dupShortStr(const char *str)
{
    return dupShortBuf(str, strlen(str));
}

static char *
dupShortBuf(const char *str, size_t len)
{
    char *buf;
    assert(str);
    buf = allocShortBuf(len + 1);
    assert(buf);
    if (len)
	xmemcpy(buf, str, len);	/* may not have terminating 0 */
    buf[len] = '\0';		/* terminate */
    debug(55, 9) ("dupped short buf[%d] (%p): '%s'\n", len + 1, buf, buf);
    return buf;
}

static char *
appShortStr(char *str, const char *app_str)
{
    const size_t size = strlen(str) + strlen(app_str) + 1;
    char *buf = allocShortBuf(size);
    snprintf(buf, size, "%s, %s", str, app_str);
    freeShortString(str);
    return buf;
}

static char *
allocShortBuf(size_t sz)
{
    char *buf = NULL;
    assert(shortStrings);
    if (sz > shortStrSize) {
	buf = xmalloc(sz);
	longStrAliveCount++;
	longStrAliveSize += sz;
	if (longStrHighWaterCount < longStrAliveCount)
	    longStrHighWaterCount = longStrAliveCount;
	if (longStrHighWaterSize < longStrAliveSize)
	    longStrHighWaterSize = longStrAliveSize;
    } else
	buf = memPoolAlloc(shortStrings);
    return buf;
}

static void
freeShortString(char *str)
{
    assert(shortStrings);
    if (str) {
	const size_t sz = strlen(str) + 1;
	debug(55, 9) ("freeing short str of size %d (max: %d) '%s' (%p)\n", sz, shortStrSize, str, str);
	if (sz > shortStrSize) {
	    debug(55, 9) ("LONG short string[%d>%d]: %s\n", sz, shortStrSize, str);
	    assert(longStrAliveCount);
	    xfree(str);
	    longStrAliveCount--;
	    longStrAliveSize -= sz;
	} else
	    memPoolFree(shortStrings, str);
    }
}

/*
 * other routines (move these into lib if you need them somewhere else?)
 */

/*
 * iterates through a 0-terminated string of items separated by 'del's.
 * white space around 'del' is considered to be a part of 'del'
 * like strtok, but preserves the source.
 *
 * returns true if next item is found.
 * init pos with NULL to start iteration.
 */
static int
strListGetItem(const char *str, char del, const char **item, int *ilen, const char **pos)
{
    size_t len;
    assert(str && item && pos);
    if (*pos)
	if (!**pos)		/* end of string */
	    return 0;
	else
	    (*pos)++;
    else
	*pos = str;

    /* skip leading ws (ltrim) */
    *pos += xcountws(*pos);
    *item = *pos;		/* remember item's start */
    /* find next delimiter */
    *pos = strchr(*item, del);
    if (!*pos)			/* last item */
	*pos = *item + strlen(*item);
    len = *pos - *item;		/* *pos points to del or '\0' */
    /* rtrim */
    while (len > 0 && isspace((*item)[len - 1]))
	len--;
    if (ilen)
	*ilen = len;
    return len > 0;
}

/* handy to printf prefixes of potentially very long buffers */
static const char *
getStringPrefix(const char *str)
{
#define SHORT_PREFIX_SIZE 256
    LOCAL_ARRAY(char, buf, SHORT_PREFIX_SIZE);
    xstrncpy(buf, str, SHORT_PREFIX_SIZE);
    return buf;
}
