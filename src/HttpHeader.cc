/*
 * $Id: HttpHeader.cc,v 1.2 1998/02/21 00:56:41 rousskov Exp $
 *
 * DEBUG: section 55    General HTTP Header
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
#include "MemPool.h"
#include "HttpHeader.h"

/*
   On naming conventions:
 
   HTTP/1.1 defines message-header as 

          message-header = field-name ":" [ field-value ] CRLF
          field-name     = token
          field-value    = *( field-content | LWS )

   HTTP/1.1 does not give a name name a group of all message-headers in a message.
   Squid 1.1 seems to refer to that group _plus_ start-line as "headers".

   HttpHeader is an object that represents all message-headers in a message.
   HttpHeader does not manage start-line.

   HttpHeader is implemented as a collection of header "entries"
   An entry is a (field_id, field) pair where
	- field_id is one of the http_hdr_type ids,
	- field is a compiled(parsed) image of message-header.
*/


/*
 * local types
 */

/* HTTP/1.1 extension-header */
struct _HttpHeaderExtField {
    char *name;   /* field-name  from HTTP/1.1 (no column after name!) */
    char *value;  /* field-value from HTTP/1.1 */
};

/* possible types for fields */
typedef enum {
    ftInvalid = HDR_ENUM_END, /* to catch nasty errors with hdr_id<->fld_type clashes */
    ftInt,
    ftPChar,
    ftDate_1123,
    ftPSCC,
    ftPExtField,
} field_type;

/*
 * HttpHeader entry 
 * ( the concrete type of entry.field is Headers[id].type )
 */
struct _HttpHeaderEntry {
    field_store field;
    http_hdr_type id;
};

/* constant attributes of fields */
typedef struct {
    const char *name;
    http_hdr_type id;
    field_type type;
    int name_len;
} field_attrs_t;

/* use HttpHeaderPos as opaque type, do not interpret */
typedef ssize_t HttpHeaderPos;
/* use this and only this to initialize HttpHeaderPos */
#define HttpHeaderInitPos (-1)


#if 0 /* moved to HttpHeader.h */
typedef struct _HttpHeaderEntry HttpHeaderEntry;
struct _HttpHeader {
    /* public, read only */
    int emask;           /* bits set for present entries */

    /* protected, do not use these, use interface functions instead */
    int capacity;        /* max #entries before we have to grow */
    int ucount;          /* #entries used, including holes */
    HttpHeaderEntry *entries;
};
#endif


/*
 * local constants and vars
 */

/*
 * A table with major attributes for every known field. 
 * We calculate name lengths and reorganize this array on start up. 
 * After reorganization, field id can be used as an index to the table.
 */
static field_attrs_t Headers[] = {
    { "Accept",            HDR_ACCEPT,          ftPChar },
    { "Age",               HDR_AGE,             ftInt },
    { "Cache-Control",     HDR_CACHE_CONTROL,   ftPSCC },
    { "Connection",        HDR_CONNECTION,      ftPChar }, /* for now */
    { "Content-Encoding",  HDR_CONTENT_ENCODING,ftPChar },
    { "Content-Length",    HDR_CONTENT_LENGTH,  ftInt },
    { "Content-MD5",       HDR_CONTENT_MD5,     ftPChar }, /* for now */
    { "Content-Type",      HDR_CONTENT_TYPE,    ftPChar },
    { "Date",              HDR_DATE,            ftDate_1123 },
    { "Etag",              HDR_ETAG,            ftPChar }, /* for now */
    { "Expires",           HDR_EXPIRES,         ftDate_1123 },
    { "Host",              HDR_HOST,            ftPChar },
    { "If-Modified-Since", HDR_IMS,             ftDate_1123 },
    { "Last-Modified",     HDR_LAST_MODIFIED,   ftDate_1123 },
    { "Location",          HDR_LOCATION,        ftPChar },
    { "Max-Forwards",      HDR_MAX_FORWARDS,    ftInt },
    { "Proxy-Authenticate",HDR_PROXY_AUTHENTICATE,ftPChar },
    { "Public",            HDR_PUBLIC,          ftPChar },
    { "Retry-After",       HDR_RETRY_AFTER,     ftPChar }, /* for now */
    /* fix this: make count-but-treat as OTHER mask @?@ @?@ */
    { "Set-Cookie:",        HDR_SET_COOKIE,      ftPChar },
    { "Upgrade",           HDR_UPGRADE,         ftPChar }, /* for now */
    { "Warning",           HDR_WARNING,         ftPChar }, /* for now */
    { "WWW-Authenticate",  HDR_WWW_AUTHENTICATE,ftPChar },
    { "Proxy-Connection",  HDR_PROXY_KEEPALIVE, ftInt },   /* true/false */
    { "Other:",            HDR_OTHER,           ftPExtField } /* ':' will not allow matches */
};

/* this table is used for parsing server cache control header */
static field_attrs_t SccAttrs[] = {
    { "public",            SCC_PUBLIC },
    { "private",           SCC_PRIVATE },
    { "no-cache",          SCC_NO_CACHE },
    { "no-store",          SCC_NO_STORE },
    { "no-transform",      SCC_NO_TRANSFORM },
    { "must-revalidate",   SCC_MUST_REVALIDATE },
    { "proxy-revalidate",  SCC_PROXY_REVALIDATE },
    { "max-age",           SCC_MAX_AGE }
};

/*
 * headers with field values defined as #(values) in HTTP/1.1
 *
 * We have listed all possible list headers according to
 * draft-ietf-http-v11-spec-rev-01.txt. Headers that are currently not
 * recognized, are commented out.
 */
static int ListHeadersMask = 0; /* set run-time using  ListHeaders */
static http_hdr_type ListHeaders[] = {
    HDR_ACCEPT, 
    /* HDR_ACCEPT_CHARSET, HDR_ACCEPT_ENCODING, HDR_ACCEPT_LANGUAGE, */
    /* HDR_ACCEPT_RANGES, */
    /* HDR_ALLOW, */
    HDR_CACHE_CONTROL, HDR_CONNECTION,
    HDR_CONTENT_ENCODING, 
    /* HDR_CONTENT_LANGUAGE,  HDR_IF_MATCH, HDR_IF_NONE_MATCH,
       HDR_PRAGMA, HDR_TRANSFER_ENCODING, */
    HDR_UPGRADE, /* HDR_VARY, */
    /* HDR_VIA, HDR_WARNING, */
    HDR_WWW_AUTHENTICATE, 
    /* HDR_EXPECT, HDR_TE, HDR_TRAILER */
};

static int ReplyHeadersMask = 0; /* set run-time using ReplyHeaders */
static http_hdr_type ReplyHeaders[] = {
    HDR_ACCEPT, HDR_AGE, HDR_CACHE_CONTROL, HDR_CONTENT_LENGTH,
    HDR_CONTENT_MD5,  HDR_CONTENT_TYPE, HDR_DATE, HDR_ETAG, HDR_EXPIRES,
    HDR_LAST_MODIFIED, HDR_LOCATION, HDR_MAX_FORWARDS, HDR_PUBLIC, HDR_RETRY_AFTER,
    HDR_SET_COOKIE, HDR_UPGRADE, HDR_WARNING, HDR_PROXY_KEEPALIVE, HDR_OTHER
};

static int RequestHeadersMask = 0; /* set run-time using RequestHeaders */
static http_hdr_type RequestHeaders[] = {
    HDR_OTHER
};

static const char *KnownSplitableFields[] = {
    "Connection", "Range"
};
/* if you must have KnownSplitableFields empty, set KnownSplitableFieldCount to 0 */
static const int KnownSplitableFieldCount = sizeof(KnownSplitableFields)/sizeof(*KnownSplitableFields);

/* headers accounting */
#define INIT_FIELDS_PER_HEADER 8
static u_num32 shortHeadersCount = 0;
static u_num32 longHeadersCount = 0;

typedef struct {
    const char *label;
    int parsed;
    int misc[HDR_ENUM_END];
} HttpHeaderStats;

#if 0 /* not used, add them later @?@ */
static struct {
    int parsed;
    int misc[HDR_MISC_END];
    int cc[SCC_ENUM_END];
} ReplyHeaderStats;

#endif /* if 0 */

/* recycle bin for short strings (32KB only) */
static const size_t shortStrSize = 32; /* max size of a recyclable string */
static const size_t shortStrPoolCount = (32*1024)/32; /* sync this with shortStrSize */
static MemPool *shortStrings = NULL;

/* long strings accounting */
static u_num32 longStrAllocCount = 0;
static u_num32 longStrFreeCount = 0;
static u_num32 longStrHighWaterCount = 0;
static size_t longStrAllocSize = 0;
static size_t longStrFreeSize = 0;
static size_t longStrHighWaterSize = 0;


/* local routines */

#define assert_eid(id) assert((id) >= 0 && (id) < HDR_ENUM_END)

static void httpHeaderInitAttrTable(field_attrs_t *table, int count);
static int httpHeaderCalcMask(const int *enums, int count);
static HttpHeaderEntry *httpHeaderGetEntry(const HttpHeader *hdr, HttpHeaderPos *pos);
static void httpHeaderDelAt(HttpHeader *hdr, HttpHeaderPos pos);
static void httpHeaderAddParsedEntry(HttpHeader *hdr, HttpHeaderEntry *e);
static void httpHeaderAddNewEntry(HttpHeader *hdr, const HttpHeaderEntry *e);
static void httpHeaderSet(HttpHeader *hdr, http_hdr_type id, const field_store value);
static void httpHeaderSyncMasks(HttpHeader *hdr, const HttpHeaderEntry *e, int add);
static void httpHeaderSyncStats(HttpHeader *hdr, const HttpHeaderEntry *e);
static int httpHeaderIdByName(const char *name, int name_len, const field_attrs_t *attrs, int end, int mask);
static void httpHeaderGrow(HttpHeader *hdr);

static void httpHeaderEntryInit(HttpHeaderEntry *e, http_hdr_type id, field_store field);
static void httpHeaderEntryClean(HttpHeaderEntry *e);
static int httpHeaderEntryParseInit(HttpHeaderEntry *e, const char *field_start, const char *field_end, int mask);
static int httpHeaderEntryParseExtFieldInit(HttpHeaderEntry *e, int id, const HttpHeaderExtField *f);
static int httpHeaderEntryParseByTypeInit(HttpHeaderEntry *e, int id, const HttpHeaderExtField *f);
static HttpHeaderEntry httpHeaderEntryClone(const HttpHeaderEntry *e);
static void httpHeaderEntryPackInto(const HttpHeaderEntry *e, Packer *p);
static void httpHeaderEntryPackByType(const HttpHeaderEntry *e, Packer *p);
static void httpHeaderEntryJoinWith(HttpHeaderEntry *e, const HttpHeaderEntry *newe);
static int httpHeaderEntryIsValid(const HttpHeaderEntry *e);
static const char *httpHeaderEntryName(const HttpHeaderEntry *e);

static void httpHeaderFieldInit(field_store *field);
static field_store httpHeaderFieldDup(field_type type, field_store value);
static field_store httpHeaderFieldBadValue(field_type type);

static HttpScc *httpSccCreate();
static HttpScc *httpSccParseCreate(const char *str);
static void httpSccParseInit(HttpScc *scc, const char *str);
static void httpSccDestroy(HttpScc *scc);
static HttpScc *httpSccDup(HttpScc *scc);
static void httpSccPackValueInto(HttpScc *scc, Packer *p);
static void httpSccJoinWith(HttpScc *scc, HttpScc *new_scc);

static HttpHeaderExtField *httpHeaderExtFieldCreate(const char *name, const char *value);
static HttpHeaderExtField *httpHeaderExtFieldParseCreate(const char *field_start, const char *field_end);
static void httpHeaderExtFieldDestroy(HttpHeaderExtField *f);
static HttpHeaderExtField *httpHeaderExtFieldDup(HttpHeaderExtField *f);

static void httpHeaderStoreAReport(StoreEntry *e, void (*reportPacker)(Packer *p));
static void httpHeaderPackReport(Packer *p);
static void httpHeaderPackReqReport(Packer *p);
static void httpHeaderPackRepReport(Packer *p);


#if 0
static void httpHeaderAddField(HttpHeader *hdr, HttpHeaderField *fld);
static void httpHeaderAddSingleField(HttpHeader *hdr, HttpHeaderField *fld);
static void httpHeaderAddListField(HttpHeader *hdr, HttpHeaderField *fld);
static void httpHeaderCountField(HttpHeader *hdr, HttpHeaderField *fld);
static void httpHeaderCountSCCField(HttpHeader *hdr, HttpHeaderField *fld);
static int httpHeaderFindFieldType(HttpHeaderField *fld, const field_attrs_t *attrs, int end, int mask);
static HttpHeaderField *httpHeaderFieldCreate(const char *name, const char *value);
static HttpHeaderField *httpHeaderFieldParseCreate(const char *field_start, const char *field_end);
static void httpHeaderFieldDestroy(HttpHeaderField *f);
static size_t httpHeaderFieldBufSize(const HttpHeaderField *fld);
static int httpHeaderFieldIsList(const HttpHeaderField *fld);
static void httpHeaderStoreAReport(Packer *p, HttpHeaderStats *stats);
#endif

static char *dupShortStr(const char *str);
static char *dupShortBuf(const char *str, size_t len);
static char *appShortStr(char *str, const char *app_str);
static char *allocShortBuf(size_t size);
static void freeShortString(char *str);

static int strListGetItem(const char *str, char del, const char **item, int *ilen, const char **pos);
static const char *getStringPrefix(const char *str);


/* delete this when everybody remembers that ':' is not a part of a name */
#define conversion_period_name_check(name) assert(!strchr((name), ':'))

/* handy to determine the #elements in a static array */
#define countof(arr) (sizeof(arr)/sizeof(*arr))

/*
 * Module initialization routines
 */

void
httpHeaderInitModule()
{
    /* paranoid check if smbd put a big object into field_store */
    assert(sizeof(field_store) == 4);
    /* have to force removal of const here */
    httpHeaderInitAttrTable((field_attrs_t *)Headers, countof(Headers));
    httpHeaderInitAttrTable((field_attrs_t *)SccAttrs, countof(SccAttrs));
    /* create masks */
    ListHeadersMask = httpHeaderCalcMask((const int*)ListHeaders, countof(ListHeaders));
    ReplyHeadersMask = httpHeaderCalcMask((const int*)ReplyHeaders, countof(ReplyHeaders));
    RequestHeadersMask = httpHeaderCalcMask((const int*)RequestHeaders, countof(RequestHeaders));
    /* create a pool of short strings @?@ we never destroy it! */
    shortStrings = memPoolCreate(shortStrPoolCount, shortStrPoolCount/10, shortStrSize, "shortStr");
}

static void
httpHeaderInitAttrTable(field_attrs_t *table, int count)
{
    int i;
    assert(table);
    assert(count > 1); /* to protect from buggy "countof" implementations */

    /* reorder so that .id becomes an index */
    for (i = 0; i < count;) {
	const int id = table[i].id;
	assert(id >= 0 && id < count); /* sanity check */
	assert(id >= i);    /* entries prior to i have been indexed already */
	if (id != i) { /* out of order */
	    const field_attrs_t fa = table[id];
	    assert(fa.id != id);  /* avoid endless loops */
	    table[id] = table[i]; /* swap */
	    table[i] = fa;
	} else
	    i++; /* make progress */
    }

    /* calculate name lengths */
    for (i = 0; i < count; ++i) {
	assert(table[i].name);
	table[i].name_len = strlen(table[i].name);
	tmp_debug(here) ("hdr table entry[%d]: %s (%d)\n", i, table[i].name, table[i].name_len);
	assert(table[i].name_len);
    }
}

/* calculates a bit mask of a given array (move this to lib/uitils) @?@ */
static int
httpHeaderCalcMask(const int *enums, int count)
{
    int i;
    int mask = 0;
    assert(enums);
    assert(count < sizeof(int)*8); /* check for overflow */

    for (i = 0; i < count; ++i) {
	assert(enums[i] < sizeof(int)*8); /* check for overflow again */
	assert(!EBIT_TEST(mask,enums[i])); /* check for duplicates */
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
httpHeaderInit(HttpHeader *hdr)
{
    assert(hdr);
    memset(hdr, 0, sizeof(*hdr));
    tmp_debug(here) ("init hdr: %p\n", hdr);
}

void
httpHeaderClean(HttpHeader *hdr)
{
    HttpHeaderPos pos = HttpHeaderInitPos;

    tmp_debug(here) ("cleaning hdr: %p\n", hdr);
    assert(hdr);

    if (hdr->capacity > INIT_FIELDS_PER_HEADER)
	longHeadersCount++;
    else
	shortHeadersCount++;

    while (httpHeaderGetEntry(hdr, &pos))
	httpHeaderDelAt(hdr, pos);
    xfree(hdr->entries);
    hdr->emask = 0;
    hdr->entries = NULL;
    hdr->capacity = hdr->ucount = 0;
}

void
httpHeaderDestroy(HttpHeader *hdr)
{
    httpHeaderClean(hdr);
    xfree(hdr);
}

/* create a copy of self */
HttpHeader *
httpHeaderClone(HttpHeader *hdr)
{
    HttpHeader *clone = httpHeaderCreate();
    HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;

    tmp_debug(here) ("cloning hdr: %p -> %p\n", hdr, clone);

    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	HttpHeaderEntry e_clone = httpHeaderEntryClone(e);
	httpHeaderAddNewEntry(clone, &e_clone);
    }

    return clone;
}

/* just handy in parsing: resets and returns false */
static int
httpHeaderReset(HttpHeader *hdr) {
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
httpHeaderParse(HttpHeader *hdr, const char *header_start, const char *header_end)
{
    const char *field_start = header_start;
    HttpHeaderEntry e;
    int mask = 0;

    assert(hdr);
    assert(header_start && header_end);
    tmp_debug(here) ("parsing hdr: %p\n", hdr);
    /* select appropriate field mask */
    mask = (/* fix this @?@ @?@ */ 1 ) ? ReplyHeadersMask : RequestHeadersMask;
    /* commonn format headers are "<name>:[ws]<value>" lines delimited by <CRLF> */
    while (field_start < header_end) {
	const char *field_end = field_start + strcspn(field_start, "\r\n");
	/*tmp_debug(here) ("found end of field: %d\n", (int)*field_end);*/
	if (!*field_end) 
	    return httpHeaderReset(hdr); /* missing <CRLF> */
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
	if (*field_start == '\r') field_start++;
	if (*field_start == '\n') field_start++;
    }
    return 1; /* even if no fields where found, they could be optional! */
}

/*
 * packs all the entries into the buffer, 
 * returns number of bytes packed including terminating '\0'
 */
void
httpHeaderPackInto(const HttpHeader *hdr, Packer *p)
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    const HttpHeaderEntry *e;
    assert(hdr && p);
    tmp_debug(here) ("packing hdr: %p\n", hdr);
    /* pack all entries one by one */
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	httpHeaderEntryPackInto(e, p);
    }
}

/* returns next valid entry */
static HttpHeaderEntry *
httpHeaderGetEntry(const HttpHeader *hdr, HttpHeaderPos *pos)
{
    assert(hdr && pos);
    assert(*pos >= HttpHeaderInitPos && *pos < hdr->capacity);
    tmp_debug(here) ("searching next e in hdr %p from %d\n", hdr, *pos);
    for ((*pos)++; *pos < hdr->ucount; (*pos)++) {
	HttpHeaderEntry *e = hdr->entries + *pos;
    	if (httpHeaderEntryIsValid(e)) {
	    tmp_debug(here)("%p returning: %s at %d\n", 
		hdr, httpHeaderEntryName(e), *pos);
    	    return e;
	}
    }
    tmp_debug(here) ("failed to find entry in hdr %p\n", hdr);
    return NULL;
}

/*
 * returns a pointer to a specified entry and updates pos; 
 * note that we search from the very begining so it does not make much sense to
 * ask for HDR_OTHER entries since there could be more than one.
 */
static HttpHeaderEntry *
httpHeaderFindEntry(const HttpHeader *hdr, http_hdr_type id, HttpHeaderPos *pos)
{
    HttpHeaderPos p;
    HttpHeaderEntry *e;
    int is_absent;
    assert(hdr);
    assert_eid(id);
    assert(id != HDR_OTHER);

    tmp_debug(here) ("finding entry %d in hdr %p\n", id, hdr);
    /* check mask first @?@ @?@ remove double checking and asserts when done */
    is_absent = (id != HDR_OTHER && !EBIT_TEST(hdr->emask, id));
    if (!pos) pos = &p;
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
httpHeaderDelFields(HttpHeader *hdr, const char *name)
{
    int count = 0;
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;

    tmp_debug(here) ("deleting '%s' fields in hdr %p\n", name, hdr);
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
httpHeaderDelAt(HttpHeader *hdr, HttpHeaderPos pos)
{
    HttpHeaderEntry *e;
    assert(hdr);
    assert(pos >= 0 && pos < hdr->ucount);
    e = hdr->entries + pos;
    tmp_debug(here) ("%p deling entry at %d: id: %d (%p:%p)\n", 
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
httpHeaderAddParsedEntry(HttpHeader *hdr, HttpHeaderEntry *e)
{
    HttpHeaderEntry *olde;
    assert(hdr);
    assert_eid(e->id);

    tmp_debug(here) ("%p adding parsed entry %d\n", hdr, e->id);

    /* there is no good reason to add invalid entries */
    if (!httpHeaderEntryIsValid(e))
	return;

    olde = (e->id == HDR_OTHER) ? NULL : httpHeaderFindEntry(hdr, e->id, NULL);
    if (olde) {
	if (EBIT_TEST(ListHeadersMask, e->id))
	    httpHeaderEntryJoinWith(olde, e);
	else
	    debug(55, 1) ("ignoring duplicate header: %s\n", httpHeaderEntryName(e));
	httpHeaderEntryClean(e);
    } else {
	/* actual add */
	httpHeaderAddNewEntry(hdr, e);
    }
    tmp_debug(here) ("%p done adding parsed entry %d\n", hdr, e->id);
}

/*
 * adds a new entry (low level append, does not check if entry is new) note: we
 * copy e value, thus, e can point to a tmp variable (but e->field is not dupped!)
 */
static void
httpHeaderAddNewEntry(HttpHeader *hdr, const HttpHeaderEntry *e)
{
    assert(hdr && e);
    if (hdr->ucount >= hdr->capacity)
	httpHeaderGrow(hdr);
    tmp_debug(here) ("%p adding entry: %d at %d, (%p:%p)\n", 
	hdr, e->id, hdr->ucount, 
	hdr->entries, hdr->entries + hdr->ucount);
    hdr->entries[hdr->ucount++] = *e;
    /* sync masks */
    httpHeaderSyncMasks(hdr, e, 1);
    /* sync accounting */
    httpHeaderSyncStats(hdr, e);
}

#if 0 /* save for parts */
/*
 * Splits list field and appends all entries separately; 
 * Warning: This is internal function, never call this directly, 
 *          only for httpHeaderAddField use.
 */
static void
httpHeaderAddListField(HttpHeader *hdr, HttpHeaderField *fld)
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
    httpHeaderAddSingleField(hdr, fld); /* first strtok() did its job! */
    while ((v = strtok(NULL, ","))) {
	/* ltrim and skip empty fields */
	while (isspace(*v) || *v == ',') v++;
	if (*v)
	    httpHeaderAddSingleField(hdr, httpHeaderFieldCreate(fld->name, v));
    }
}
#endif

/*
 * Global (user level) routines
 */

/* test if a field is present */
int httpHeaderHas(const HttpHeader *hdr, http_hdr_type id)
{
    assert(hdr);
    assert_eid(id);
    assert(id != HDR_OTHER);
    tmp_debug(here) ("%p lookup for %d\n", hdr, id);
    return EBIT_TEST(hdr->emask, id);

#ifdef SLOW_BUT_SAFE
    return httpHeaderFindEntry(hdr, id, NULL) != NULL;
#endif
}

/* delete a field if any */
void httpHeaderDel(HttpHeader *hdr, http_hdr_type id)
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    assert(id != HDR_OTHER);
    tmp_debug(here) ("%p del-by-id %d\n", hdr, id);
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
httpHeaderSet(HttpHeader *hdr, http_hdr_type id, const field_store value)
{
    HttpHeaderPos pos;
    HttpHeaderEntry e;
    assert(hdr);
    assert_eid(id);
    
    tmp_debug(here) ("%p sets with id: %d\n", hdr, id);
    if (httpHeaderFindEntry(hdr, id, &pos)) /* delete old entry */
	httpHeaderDelAt(hdr, pos);

    httpHeaderEntryInit(&e, id, httpHeaderFieldDup(Headers[id].type, value));
    if (httpHeaderEntryIsValid(&e))
	httpHeaderAddNewEntry(hdr, &e);
    else
	httpHeaderEntryClean(&e);
}

void
httpHeaderSetInt(HttpHeader *hdr, http_hdr_type id, int number)
{
    field_store value;
    assert_eid(id);
    assert(Headers[id].type == ftInt); /* must be of an appropriatre type */
    value.v_int = number;
    httpHeaderSet(hdr, id, value);
}

void
httpHeaderSetTime(HttpHeader *hdr, http_hdr_type id, time_t time)
{
    field_store value;
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123); /* must be of an appropriatre type */
    value.v_time = time;
    httpHeaderSet(hdr, id, value);
}
void
httpHeaderSetStr(HttpHeader *hdr, http_hdr_type id, const char *str)
{
    field_store value;
    assert_eid(id);
    assert(Headers[id].type == ftPChar); /* must be of a string type */
    value.v_pcchar = str;
    httpHeaderSet(hdr, id, value);
}

/* add extension header (these fields are not parsed/analyzed/joined, etc.) */
void
httpHeaderAddExt(HttpHeader *hdr, const char *name, const char* value)
{
    HttpHeaderExtField *ext = httpHeaderExtFieldCreate(name, value);
    HttpHeaderEntry e;

    tmp_debug(here) ("%p ads exte '%s:%s'\n", hdr, name, value);
    httpHeaderEntryInit(&e, HDR_OTHER, ext);
    httpHeaderAddNewEntry(hdr, &e);
}

/* get a value of a field (not lvalue though) */
field_store
httpHeaderGet(const HttpHeader *hdr, http_hdr_type id)
{
    HttpHeaderEntry *e;
    assert_eid(id);
    assert(id != HDR_OTHER); /* there is no single value for HDR_OTHER */

    tmp_debug(here) ("%p get for id %d\n", hdr, id);
    if ((e = httpHeaderFindEntry(hdr, id, NULL)))
	return e->field;
    else
	return httpHeaderFieldBadValue(Headers[id].type);
}

const char *
httpHeaderGetStr(const HttpHeader *hdr, http_hdr_type id)
{
    assert_eid(id);
    assert(Headers[id].type == ftPChar); /* must be of an apropriate type */
    return httpHeaderGet(hdr, id).v_pchar;
}

time_t
httpHeaderGetTime(const HttpHeader *hdr, http_hdr_type id)
{
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123); /* must be of an apropriate type */
    return httpHeaderGet(hdr, id).v_time;
}

HttpScc *
httpHeaderGetScc(const HttpHeader *hdr)
{
    return httpHeaderGet(hdr, HDR_CACHE_CONTROL).v_pscc;
}

/* updates header masks */
static void
httpHeaderSyncMasks(HttpHeader *hdr, const HttpHeaderEntry *e, int add)
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

/* updates header stats */
static void
httpHeaderSyncStats(HttpHeader *hdr, const HttpHeaderEntry *e)
{
#if 0 /* implement it @?@ */
    assert(0); /* implement it */
    /* add Req/Pep detection here @?@ */
    int type = httpHeaderFindFieldType(fld,
	HdrFieldAttrs, HDR_ENUM_END,
	(1) ? ReplyHeadersMask : RequestHeadersMask);
    /* exception */
    if (type == HDR_PROXY_KEEPALIVE && strcasecmp("Keep-Alive", fld->value))
	type = -1;
    if (type < 0)
	type = HDR_OTHER;
    /* @?@ update stats for req/resp:type @?@ */
    /* process scc @?@ check if we need to do that for requests or not */
    if (1 && type == HDR_CACHE_CONTROL)
	httpHeaderCountSCCField(hdr, fld);
#endif
}

#if 0 /* move it */
/* updates scc mask and stats for an scc field */
static void
httpHeaderCountSCCField(HttpHeader *hdr, HttpHeaderField *fld)
{
    int type = httpHeaderFindFieldType(fld,
	SccFieldAttrs, SCC_ENUM_END, -1);
    if (type < 0)
	type = SCC_OTHER;
    /* update mask */
    EBIT_SET(hdr->scc_mask, type);
    /* @?@ update stats for scc @?@ */
    SccFieldAttrs[type].dummy.test1++;
}
#endif

static int
httpHeaderIdByName(const char *name, int name_len, const field_attrs_t *attrs, int end, int mask)
{
    int i;
    for (i = 0; i < end; ++i) {
	if (mask < 0 || EBIT_TEST(mask, i)) {
	    if (name_len >= 0 && name_len != attrs[i].name_len)
		continue;
	    if (!strncasecmp(name, attrs[i].name, 
		name_len < 0 ? attrs[i].name_len+1 : name_len))
		return i;
	}
    }
    return -1;
}

/* doubles the size of the fields index, starts with INIT_FIELDS_PER_HEADER */
static void
httpHeaderGrow(HttpHeader *hdr)
{
    int new_cap;
    int new_size;
    assert(hdr);
    new_cap = (hdr->capacity) ? 2*hdr->capacity : INIT_FIELDS_PER_HEADER;
    new_size = new_cap*sizeof(HttpHeaderEntry);

    tmp_debug(here) ("%p grow (%p) %d->%d\n", hdr, hdr->entries, hdr->capacity, new_cap);
    hdr->entries = hdr->entries ?
	xrealloc(hdr->entries, new_size) :
	xmalloc(new_size);
    memset(hdr->entries+hdr->capacity, 0, (new_cap-hdr->capacity)*sizeof(HttpHeaderEntry));
    hdr->capacity = new_cap;
    tmp_debug(here) ("%p grew (%p)\n", hdr, hdr->entries);
}

/*
 * HttpHeaderEntry
 */

static void
httpHeaderEntryInit(HttpHeaderEntry *e, http_hdr_type id, field_store field)
{
    assert(e);
    assert_eid(id);
    e->id = id;
    e->field = field;
}

static void
httpHeaderEntryClean(HttpHeaderEntry *e) {
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
	    assert(0); /* somebody added a new type? */
    }
    /* we have to do that so entry will be _invlaid_ */
    e->id = -1;
    e->field.v_pchar = NULL;
}

/* parses and inits header entry, returns true on success */
static int
httpHeaderEntryParseInit(HttpHeaderEntry *e, const char *field_start, const char *field_end, int mask)
{
    HttpHeaderExtField *f;
    int id;
    int result;

    /* first assume it is just an extension field */
    f = httpHeaderExtFieldParseCreate(field_start, field_end);
    if (!f) /* parsing failure */
	return 0;
    id = httpHeaderIdByName(f->name, -1, Headers, countof(Headers), mask);
    if (id < 0)
	id = HDR_OTHER;
    if (id == HDR_OTHER) {
	/* hm.. it is an extension field indeed */
	httpHeaderEntryInit(e, id, f);
	return 1;
    }
    /* ok, we got something interesting, parse it further */
    result = httpHeaderEntryParseExtFieldInit(e, id, f);
    /* do not need it anymore */
    httpHeaderExtFieldDestroy(f);
    return result;
}

static int
httpHeaderEntryParseExtFieldInit(HttpHeaderEntry *e, int id, const HttpHeaderExtField *f)
{
    /*
     * check for exceptions first (parsing is not determined by value type)
     * then parse using value type if needed
     */
    switch (id) {
	case HDR_PROXY_KEEPALIVE:
	    /*  we treat Proxy-Connection as "keep alive" only if it says so */
            e->field.v_int = !strcasecmp(f->value, "Keep-Alive");
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
httpHeaderEntryParseByTypeInit(HttpHeaderEntry *e, int id, const HttpHeaderExtField *f)
{
    int type;
    field_store field;
    assert(e && f);
    assert_eid(id);
    type = Headers[id].type;

    httpHeaderFieldInit(&field);
    switch(type) {
	case ftInt:
	    field.v_int = atoi(f->value);
	    if (!field.v_int && !isdigit(*f->value)) {
		debug(55, 1) ("cannot parse an int header field: id: %d, field: '%s: %s'\n",
		    id, f->name, f->value);
		return 0;
	    }
	    break;

	case ftPChar:
	    field.v_pchar = dupShortStr(f->value);
	    break;

	case ftDate_1123:
	    field.v_time = parse_rfc1123(f->value);
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
		return 0;
	    }
	    break;

	default:
	    debug(55, 0) ("something went wrong with hdr field type analysis: id: %d, type: %d, field: '%s: %s'\n", 
		id, type, f->name, f->value);
	    return 0;
    }
    /* success, do actual init */
    httpHeaderEntryInit(e, id, field);
    return 1;
}


static HttpHeaderEntry
httpHeaderEntryClone(const HttpHeaderEntry *e)
{
    HttpHeaderEntry clone;
    assert(e);
    assert_eid(e->id);
    httpHeaderEntryInit(&clone, e->id,
	httpHeaderFieldDup(Headers[e->id].type, e->field));
    return clone;
}

static void
httpHeaderEntryPackInto(const HttpHeaderEntry *e, Packer *p)
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
httpHeaderEntryPackByType(const HttpHeaderEntry *e, Packer *p)
{
    field_type type;
    assert(e && p);
    assert_eid(e->id);
    type = Headers[e->id].type;    
    switch(type) {
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
	    assert(0 && type); /* pack for invalid/unknown type */
    }
}

static void
httpHeaderEntryJoinWith(HttpHeaderEntry *e, const HttpHeaderEntry *newe)
{
    field_type type;
    assert(e && newe);
    assert_eid(e->id);
    assert(e->id == newe->id);

    /* type-based join */
    type = Headers[e->id].type;
    switch(type) {
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
httpHeaderEntryIsValid(const HttpHeaderEntry *e)
{
    assert(e);
    if (e->id == -1)
	return 0;
    assert_eid(e->id);
    /* type-based analysis */
    switch(Headers[e->id].type) {
	case ftInvalid:
	    return 0;
	case ftInt:
	    return e->field.v_int >= 0;
	case ftPChar:
	    return e->field.v_pchar != NULL;
	    break;
	case ftDate_1123:
	    return e->field.v_time >= 0;
	    break;
	case ftPSCC:
	    return e->field.v_pscc != NULL;
	    break;
	case ftPExtField:
	    return e->field.v_pefield != NULL;
	    break;
	default:
	    assert(0); /* query for invalid/unknown type */
    }
    return 0; /* not reached */
}

static const char *
httpHeaderEntryName(const HttpHeaderEntry *e)
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
httpHeaderFieldInit(field_store *field)
{
    assert(field);
    memset(field, 0, sizeof(field_store));
}

static field_store
httpHeaderFieldDup(field_type type, field_store value)
{
    /* type based duplication */
    switch(type) {
	case ftInt:
	    return value.v_int;
	case ftPChar:
	    return dupShortStr(value.v_pchar);
	    break;
	case ftDate_1123:
	    return value.v_time;
	    break;
	case ftPSCC:
	    return httpSccDup(value.v_pscc);
	    break;
	case ftPExtField:
	    return httpHeaderExtFieldDup(value.v_pefield);
	    break;
	default:
	    assert(0); /* dup of invalid/unknown type */
    }
    return NULL; /* not reached */
}

/*
 * bad value table; currently bad values are determined by field type, but this
 * can be changed in the future to reflect dependence on entry id if any
 */
static field_store
httpHeaderFieldBadValue(field_type type)
{
    switch(type) {
	case ftInt:
	case ftDate_1123:
	    return -1;
	case ftPChar:
	case ftPSCC:
	case ftPExtField:
	    return NULL;
	case ftInvalid:
	default:
	    assert(0); /* query for invalid/unknown type */
    }
    return NULL; /* not reached */
}

/*
 * HttpScc (server cache control)
 */

static HttpScc *
httpSccCreate()
{
    HttpScc *scc = memAllocate(MEM_HTTP_SCC, 1);
    scc->max_age = -1;
    return scc;
}

/* creates an scc object from a 0-terminating string*/
static HttpScc *
httpSccParseCreate(const char *str)
{
    HttpScc *scc = httpSccCreate();
    httpSccParseInit(scc, str);
    return scc;
}

/* parses a 0-terminating string and inits scc */
static void
httpSccParseInit(HttpScc *scc, const char *str)
{
    const char *item;
    const char *p; /* '=' parameter */
    const char *pos = NULL;
    int type;
    int ilen;
    assert(scc && str);

    /* iterate through comma separated list */
    while(strListGetItem(str, ',', &item, &ilen, &pos)) {
	/* strip '=' statements @?@ */
	if ((p = strchr(item, '=')) && (p-item < ilen))
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
httpSccDestroy(HttpScc *scc)
{
    assert(scc);
    memFree(MEM_HTTP_SCC, scc);
}

static HttpScc *
httpSccDup(HttpScc *scc)
{
    HttpScc *dup;
    assert(scc);
    dup = httpSccCreate();
    dup->mask = scc->mask;
    dup->max_age = scc->max_age;
    return dup;
}

static void
httpSccPackValueInto(HttpScc *scc, Packer *p)
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
httpSccJoinWith(HttpScc *scc, HttpScc *new_scc)
{
    assert(scc && new_scc);
    if (scc->max_age < 0)
	scc->max_age = new_scc->max_age;
    scc->mask |= new_scc->mask;
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

    tmp_debug(here) ("got field len: %d\n", field_end-field_start);

    value_start = name_end + 1; /* skip ':' */
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
    f->name = dupShortBuf(field_start, name_end-field_start);
    f->value = dupShortBuf(value_start, field_end-value_start);
    tmp_debug(here) ("%p got field: '%s: %s'\n", f, f->name, f->value);
    return f;
}

static void
httpHeaderExtFieldDestroy(HttpHeaderExtField *f)
{
    assert(f);
    freeShortString(f->name);
    freeShortString(f->value);
    xfree(f);
}

static HttpHeaderExtField *
httpHeaderExtFieldDup(HttpHeaderExtField *f)
{
    assert(f);
    return httpHeaderExtFieldCreate(f->name, f->value);
}

#if 0 /* save for parts */

/*
 * returns the space requred to put a field (and terminating <CRLF>!) into a
 * buffer
 */
static size_t
httpHeaderFieldBufSize(const HttpHeaderExtField *fld)
{
    return strlen(fld->name)+2+strlen(fld->value)+2;
}

/*
 * returns true if fld.name is a "known" splitable field; 
 * always call this function to check because the detection algortihm may change
 */
static int
httpHeaderFieldIsList(const HttpHeaderExtField *fld) {
    int i;
    assert(fld);
    /* "onten" should not match "Content"! */
    for (i = 0; i < KnownSplitableFieldCount; ++i)
	if (strcasecmp(KnownSplitableFields[i], fld->name))
	    return 1;
    return 0;
}

#endif

static void
httpHeaderStoreAReport(StoreEntry *e, void (*reportPacker)(Packer *p))
{
    Packer p;
    assert(e);
    packerToStoreInit(&p, e);
    (*reportPacker)(&p);
    packerClean(&p);
}

void
httpHeaderStoreReport(StoreEntry *e)
{
    httpHeaderStoreAReport(e, &httpHeaderPackReport); 
}

void
httpHeaderStoreReqReport(StoreEntry *e)
{
    httpHeaderStoreAReport(e, &httpHeaderPackReqReport); 
}

void
httpHeaderStoreRepReport(StoreEntry *e)
{
    httpHeaderStoreAReport(e, &httpHeaderPackRepReport); 
}


static void
httpHeaderPackReport(Packer *p)
{
    assert(p);

    httpHeaderPackRepReport(p);
    httpHeaderPackReqReport(p);

    /* low level totals; reformat this? @?@ */
    packerPrintf(p,
	"hdrs totals: %uld+%uld %s lstr: +%uld-%uld<(%uld=%uld)\n",
	shortHeadersCount,
	longHeadersCount,
	memPoolReport(shortStrings),
	longStrAllocCount,
	longStrFreeCount,
	longStrHighWaterCount,
	longStrHighWaterSize);
}

static void
httpHeaderPackRepReport(Packer *p)
{
    assert(p);
#if 0 /* implement this */
    httpHeaderPackAReport(p, &ReplyHeaderStats);
    for (i = SCC_PUBLIC; i < SCC_ENUM_END; i++)
	storeAppendPrintf(entry, "Cache-Control %s: %d\n",
	    HttpServerCCStr[i],
	    ReplyHeaderStats.cc[i]);
#endif
}

static void
httpHeaderPackReqReport(Packer *p)
{
    assert(p);
#if 0 /* implement this */
    httpHeaderPackAReport(p, &RequestHeaderStats);
#endif
}

#if 0 /* implement this */
static void
httpHeaderPackAReport(Packer *p, HttpHeaderStats *stats)
{
    assert(p);
    assert(stats);
    assert(0);
    http_server_cc_t i;
    http_hdr_misc_t j;
    storeAppendPrintf(entry, "HTTP Reply Headers:\n");
    storeAppendPrintf(entry, "       Headers parsed: %d\n",
	ReplyHeaderStats.parsed);
    for (j = HDR_AGE; j < HDR_MISC_END; j++)
	storeAppendPrintf(entry, "%21.21s: %d\n",
	    HttpHdrMiscStr[j],
	    ReplyHeaderStats.misc[j]);
}
#endif

/* "short string" routines below are trying to recycle memory for short strings */
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
    assert(len >= 0);
    buf = allocShortBuf(len + 1);
    assert(buf);
    if (len)
	xmemcpy(buf, str, len); /* may not have terminating 0 */
    buf[len] = '\0'; /* terminate */
    tmp_debug(here) ("dupped short buf[%d]: '%s'\n", len, buf);
    return buf;
}

static char *
appShortStr(char *str, const char *app_str)
{
    const size_t size = strlen(str)+strlen(app_str)+1;
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
    /* tmp_debug(here) ("allocating short buffer of size %d (max: %d)\n", sz, shortStrings->obj_size); @?@ */
    if (sz > shortStrings->obj_size) {
	buf = xmalloc(sz);
	longStrAllocCount++;
	longStrAllocSize += sz;
	if (longStrHighWaterCount < longStrAllocCount - longStrFreeCount)
	    longStrHighWaterCount = longStrAllocCount - longStrFreeCount;
	if (longStrHighWaterSize < longStrAllocSize - longStrFreeSize)
	    longStrHighWaterSize = longStrAllocSize - longStrFreeSize;
    } else
	buf = memPoolGetObj(shortStrings);
    return buf;
}

static void
freeShortString(char *str)
{
    assert(shortStrings);
    if (str) {
	const size_t sz = strlen(str)+1;
        /* tmp_debug(here) ("freeing short str of size %d (max: %d)'%s'\n", sz, shortStrings->obj_size, str); @?@ */
	if (sz > shortStrings->obj_size) {
	    tmp_debug(here) ("LONG short string[%d>%d]: %s\n", sz, shortStrings->obj_size, str);
	    xfree(str);
	    longStrFreeCount++;
	    longStrFreeSize += sz;
	} else
	    memPoolPutObj(shortStrings, str);
    }
}

/*
 * other routines (move these into lib if you need them somewhere else?)
 */

/*
 * iterates through a 0-terminated string of items separated by 'del'
 * white space around 'del' is considered to be a part of 'del'
 * like strtok, but preserves the source
 *
 * returns true if next item is found
 * init pos with NULL to start iteration
 */
static int
strListGetItem(const char *str, char del, const char **item, int *ilen, const char **pos)
{
    size_t len;
    assert(str && item && pos);
    if (*pos)
	if (!**pos)   /* end of string */
	    return 0;
	else
	    (*pos)++;
    else
	*pos = str;

    /* skip leading ws (ltrim) */
    *pos += xcountws(*pos);
    *item = *pos; /* remember item's start */
    /* find next delimiter */
    *pos = strchr(*item, del);
    if (!*pos) /* last item */
	*pos = *item + strlen(*item);
    len = *pos - *item; /* *pos points to del or '\0' */
    /* rtrim */
    while (len > 0 && isspace((*item)[len-1])) len--;
    if (ilen)
	*ilen = len;
    return len > 0;
}

/* handy to printf prefixes of potentially very long buffers */
static const char *
getStringPrefix(const char *str) {
#define SHORT_PREFIX_SIZE 256
    LOCAL_ARRAY(char, buf, SHORT_PREFIX_SIZE);
    xstrncpy(buf, str, SHORT_PREFIX_SIZE);
    return buf;
}
