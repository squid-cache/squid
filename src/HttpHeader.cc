
/*
 * $Id: HttpHeader.cc,v 1.73 2001/10/17 21:37:28 hno Exp $
 *
 * DEBUG: section 55    HTTP Header
 * AUTHOR: Alex Rousskov
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
    {"Allow", HDR_ALLOW, ftStr},
    {"Authorization", HDR_AUTHORIZATION, ftStr},	/* for now */
    {"Cache-Control", HDR_CACHE_CONTROL, ftPCc},
    {"Connection", HDR_CONNECTION, ftStr},
    {"Content-Base", HDR_CONTENT_BASE, ftStr},
    {"Content-Encoding", HDR_CONTENT_ENCODING, ftStr},
    {"Content-Language", HDR_CONTENT_LANGUAGE, ftStr},
    {"Content-Length", HDR_CONTENT_LENGTH, ftInt},
    {"Content-Location", HDR_CONTENT_LOCATION, ftStr},
    {"Content-MD5", HDR_CONTENT_MD5, ftStr},	/* for now */
    {"Content-Range", HDR_CONTENT_RANGE, ftPContRange},
    {"Content-Type", HDR_CONTENT_TYPE, ftStr},
    {"Cookie", HDR_COOKIE, ftStr},
    {"Date", HDR_DATE, ftDate_1123},
    {"ETag", HDR_ETAG, ftETag},
    {"Expires", HDR_EXPIRES, ftDate_1123},
    {"From", HDR_FROM, ftStr},
    {"Host", HDR_HOST, ftStr},
    {"If-Match", HDR_IF_MATCH, ftStr},	/* for now */
    {"If-Modified-Since", HDR_IF_MODIFIED_SINCE, ftDate_1123},
    {"If-None-Match", HDR_IF_NONE_MATCH, ftStr},	/* for now */
    {"If-Range", HDR_IF_RANGE, ftDate_1123_or_ETag},
    {"Last-Modified", HDR_LAST_MODIFIED, ftDate_1123},
    {"Link", HDR_LINK, ftStr},
    {"Location", HDR_LOCATION, ftStr},
    {"Max-Forwards", HDR_MAX_FORWARDS, ftInt},
    {"Mime-Version", HDR_MIME_VERSION, ftStr},	/* for now */
    {"Pragma", HDR_PRAGMA, ftStr},
    {"Proxy-Authenticate", HDR_PROXY_AUTHENTICATE, ftStr},
    {"Proxy-Authentication-Info", HDR_PROXY_AUTHENTICATION_INFO, ftStr},
    {"Proxy-Authorization", HDR_PROXY_AUTHORIZATION, ftStr},
    {"Proxy-Connection", HDR_PROXY_CONNECTION, ftStr},
    {"Public", HDR_PUBLIC, ftStr},
    {"Range", HDR_RANGE, ftPRange},
    {"Referer", HDR_REFERER, ftStr},
    {"Request-Range", HDR_REQUEST_RANGE, ftPRange},	/* usually matches HDR_RANGE */
    {"Retry-After", HDR_RETRY_AFTER, ftStr},	/* for now (ftDate_1123 or ftInt!) */
    {"Server", HDR_SERVER, ftStr},
    {"Set-Cookie", HDR_SET_COOKIE, ftStr},
    {"Title", HDR_TITLE, ftStr},
    {"Upgrade", HDR_UPGRADE, ftStr},	/* for now */
    {"User-Agent", HDR_USER_AGENT, ftStr},
    {"Vary", HDR_VARY, ftStr},	/* for now */
    {"Via", HDR_VIA, ftStr},	/* for now */
    {"Warning", HDR_WARNING, ftStr},	/* for now */
    {"WWW-Authenticate", HDR_WWW_AUTHENTICATE, ftStr},
    {"Authentication-Info", HDR_AUTHENTICATION_INFO, ftStr},
    {"X-Cache", HDR_X_CACHE, ftStr},
    {"X-Cache-Lookup", HDR_X_CACHE_LOOKUP, ftStr},
    {"X-Forwarded-For", HDR_X_FORWARDED_FOR, ftStr},
    {"X-Request-URI", HDR_X_REQUEST_URI, ftStr},
    {"X-Squid-Error", HDR_X_SQUID_ERROR, ftStr},
    {"Negotiate", HDR_NEGOTIATE, ftStr},
#if X_ACCELERATOR_VARY
    {"X-Accelerator-Vary", HDR_X_ACCELERATOR_VARY, ftStr},
#endif
    {"Other:", HDR_OTHER, ftStr}	/* ':' will not allow matches */
};
static HttpHeaderFieldInfo *Headers = NULL;

/*
 * headers with field values defined as #(values) in HTTP/1.1
 * Headers that are currently not recognized, are commented out.
 */
static HttpHeaderMask ListHeadersMask;	/* set run-time using  ListHeadersArr */
static http_hdr_type ListHeadersArr[] =
{
    HDR_ACCEPT,
    HDR_ACCEPT_CHARSET, HDR_ACCEPT_ENCODING, HDR_ACCEPT_LANGUAGE,
    HDR_ACCEPT_RANGES, HDR_ALLOW,
    HDR_CACHE_CONTROL,
    HDR_CONTENT_ENCODING,
    HDR_CONTENT_LANGUAGE,
    HDR_CONNECTION,
    HDR_IF_MATCH, HDR_IF_NONE_MATCH,
    HDR_LINK, HDR_PRAGMA,
    HDR_PROXY_CONNECTION,
    /* HDR_TRANSFER_ENCODING, */
    HDR_UPGRADE,
    HDR_VARY,
    HDR_VIA,
    /* HDR_WARNING, */
    HDR_WWW_AUTHENTICATE,
    HDR_AUTHENTICATION_INFO,
    HDR_PROXY_AUTHENTICATION_INFO,
    /* HDR_EXPECT, HDR_TE, HDR_TRAILER */
#if X_ACCELERATOR_VARY
    HDR_X_ACCELERATOR_VARY,
#endif
    HDR_X_FORWARDED_FOR
};

/* general-headers */
static http_hdr_type GeneralHeadersArr[] =
{
    HDR_CACHE_CONTROL, HDR_CONNECTION, HDR_DATE, HDR_PRAGMA,
    /* HDR_TRANSFER_ENCODING, */
    HDR_UPGRADE,
    /* HDR_TRAILER, */
    HDR_VIA
};

/* entity-headers */
static http_hdr_type EntityHeadersArr[] =
{
    HDR_ALLOW, HDR_CONTENT_BASE, HDR_CONTENT_ENCODING, HDR_CONTENT_LANGUAGE,
    HDR_CONTENT_LENGTH, HDR_CONTENT_LOCATION, HDR_CONTENT_MD5,
    HDR_CONTENT_RANGE, HDR_CONTENT_TYPE, HDR_ETAG, HDR_EXPIRES, HDR_LAST_MODIFIED, HDR_LINK,
    HDR_OTHER
};

static HttpHeaderMask ReplyHeadersMask;		/* set run-time using ReplyHeaders */
static http_hdr_type ReplyHeadersArr[] =
{
    HDR_ACCEPT, HDR_ACCEPT_CHARSET, HDR_ACCEPT_ENCODING, HDR_ACCEPT_LANGUAGE,
    HDR_ACCEPT_RANGES, HDR_AGE,
    HDR_LOCATION, HDR_MAX_FORWARDS,
    HDR_MIME_VERSION, HDR_PUBLIC, HDR_RETRY_AFTER, HDR_SERVER, HDR_SET_COOKIE,
    HDR_VARY,
    HDR_WARNING, HDR_PROXY_CONNECTION, HDR_X_CACHE,
    HDR_X_CACHE_LOOKUP,
    HDR_X_REQUEST_URI,
#if X_ACCELERATOR_VARY
    HDR_X_ACCELERATOR_VARY,
#endif
    HDR_X_SQUID_ERROR
};

static HttpHeaderMask RequestHeadersMask;	/* set run-time using RequestHeaders */
static http_hdr_type RequestHeadersArr[] =
{
    HDR_AUTHORIZATION, HDR_FROM, HDR_HOST,
    HDR_IF_MATCH, HDR_IF_MODIFIED_SINCE, HDR_IF_NONE_MATCH,
    HDR_IF_RANGE, HDR_MAX_FORWARDS, HDR_PROXY_CONNECTION,
    HDR_PROXY_AUTHORIZATION, HDR_RANGE, HDR_REFERER, HDR_REQUEST_RANGE,
    HDR_USER_AGENT, HDR_X_FORWARDED_FOR
};

/* header accounting */
static HttpHeaderStat HttpHeaderStats[] =
{
    {"all"},
#if USE_HTCP
    {"HTCP reply"},
#endif
    {"request"},
    {"reply"}
};
static int HttpHeaderStatCount = countof(HttpHeaderStats);

static int HeaderEntryParsedCount = 0;

/*
 * local routines
 */

#define assert_eid(id) assert((id) >= 0 && (id) < HDR_ENUM_END)

static HttpHeaderEntry *httpHeaderEntryCreate(http_hdr_type id, const char *name, const char *value);
static void httpHeaderEntryDestroy(HttpHeaderEntry * e);
static HttpHeaderEntry *httpHeaderEntryParseCreate(const char *field_start, const char *field_end);
static void httpHeaderNoteParsedEntry(http_hdr_type id, String value, int error);

static void httpHeaderStatInit(HttpHeaderStat * hs, const char *label);
static void httpHeaderStatDump(const HttpHeaderStat * hs, StoreEntry * e);

/*
 * Module initialization routines
 */

void
httpHeaderInitModule(void)
{
    int i;
    /* check that we have enough space for masks */
    assert(8 * sizeof(HttpHeaderMask) >= HDR_ENUM_END);
    /* all headers must be described */
    assert(countof(HeadersAttrs) == HDR_ENUM_END);
    if (!Headers)
	Headers = httpHeaderBuildFieldsInfo(HeadersAttrs, HDR_ENUM_END);
    /* create masks */
    httpHeaderMaskInit(&ListHeadersMask, 0);
    httpHeaderCalcMask(&ListHeadersMask, (const int *) ListHeadersArr, countof(ListHeadersArr));
    httpHeaderMaskInit(&ReplyHeadersMask, 0);
    httpHeaderCalcMask(&ReplyHeadersMask, (const int *) ReplyHeadersArr, countof(ReplyHeadersArr));
    httpHeaderCalcMask(&ReplyHeadersMask, (const int *) GeneralHeadersArr, countof(GeneralHeadersArr));
    httpHeaderCalcMask(&ReplyHeadersMask, (const int *) EntityHeadersArr, countof(EntityHeadersArr));
    httpHeaderMaskInit(&RequestHeadersMask, 0);
    httpHeaderCalcMask(&RequestHeadersMask, (const int *) RequestHeadersArr, countof(RequestHeadersArr));
    httpHeaderCalcMask(&RequestHeadersMask, (const int *) GeneralHeadersArr, countof(GeneralHeadersArr));
    httpHeaderCalcMask(&RequestHeadersMask, (const int *) EntityHeadersArr, countof(EntityHeadersArr));
    /* init header stats */
    assert(HttpHeaderStatCount == hoReply + 1);
    for (i = 0; i < HttpHeaderStatCount; i++)
	httpHeaderStatInit(HttpHeaderStats + i, HttpHeaderStats[i].label);
    HttpHeaderStats[hoRequest].owner_mask = &RequestHeadersMask;
    HttpHeaderStats[hoReply].owner_mask = &ReplyHeadersMask;
#if USE_HTCP
    HttpHeaderStats[hoHtcpReply].owner_mask = &ReplyHeadersMask;
#endif
    /* init dependent modules */
    httpHdrCcInitModule();
    /* register with cache manager */
    cachemgrRegister("http_headers",
	"HTTP Header Statistics", httpHeaderStoreReport, 0, 1);
}

void
httpHeaderCleanModule(void)
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
    memset(hs, 0, sizeof(HttpHeaderStat));
    hs->label = label;
    statHistEnumInit(&hs->hdrUCountDistr, 32);	/* not a real enum */
    statHistEnumInit(&hs->fieldTypeDistr, HDR_ENUM_END);
    statHistEnumInit(&hs->ccTypeDistr, CC_ENUM_END);
}

/*
 * HttpHeader Implementation
 */

void
httpHeaderInit(HttpHeader * hdr, http_hdr_owner_type owner)
{
    assert(hdr);
    assert(owner > hoNone && owner <= hoReply);
    debug(55, 7) ("init-ing hdr: %p owner: %d\n", hdr, owner);
    memset(hdr, 0, sizeof(*hdr));
    hdr->owner = owner;
    arrayInit(&hdr->entries);
}

void
httpHeaderClean(HttpHeader * hdr)
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;

    assert(hdr);
    assert(hdr->owner > hoNone && hdr->owner <= hoReply);
    debug(55, 7) ("cleaning hdr: %p owner: %d\n", hdr, hdr->owner);

    statHistCount(&HttpHeaderStats[hdr->owner].hdrUCountDistr, hdr->entries.count);
    HttpHeaderStats[hdr->owner].destroyedCount++;
    HttpHeaderStats[hdr->owner].busyDestroyedCount += hdr->entries.count > 0;
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	/* tmp hack to try to avoid coredumps */
	if (e->id < 0 || e->id >= HDR_ENUM_END) {
	    debug(55, 0) ("httpHeaderClean BUG: entry[%d] is invalid (%d). Ignored.\n",
		pos, e->id);
	} else {
	    statHistCount(&HttpHeaderStats[hdr->owner].fieldTypeDistr, e->id);
	    /* yes, this destroy() leaves us in an incosistent state */
	    httpHeaderEntryDestroy(e);
	}
    }
    arrayClean(&hdr->entries);
}

/* append entries (also see httpHeaderUpdate) */
void
httpHeaderAppend(HttpHeader * dest, const HttpHeader * src)
{
    const HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;
    assert(src && dest);
    assert(src != dest);
    debug(55, 7) ("appending hdr: %p += %p\n", dest, src);

    while ((e = httpHeaderGetEntry(src, &pos))) {
	httpHeaderAddEntry(dest, httpHeaderEntryClone(e));
    }
}

/* use fresh entries to replace old ones */
void
httpHeaderUpdate(HttpHeader * old, const HttpHeader * fresh, const HttpHeaderMask * denied_mask)
{
    const HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;
    assert(old && fresh);
    assert(old != fresh);
    debug(55, 7) ("updating hdr: %p <- %p\n", old, fresh);

    while ((e = httpHeaderGetEntry(fresh, &pos))) {
	/* deny bad guys (ok to check for HDR_OTHER) here */
	if (denied_mask && CBIT_TEST(*denied_mask, e->id))
	    continue;
	httpHeaderDelByName(old, strBuf(e->name));
	httpHeaderAddEntry(old, httpHeaderEntryClone(e));
    }
}

/* just handy in parsing: resets and returns false */
int
httpHeaderReset(HttpHeader * hdr)
{
    http_hdr_owner_type ho = hdr->owner;
    assert(hdr);
    ho = hdr->owner;
    httpHeaderClean(hdr);
    httpHeaderInit(hdr, ho);
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
    HttpHeaderStats[hdr->owner].parsedCount++;
    /* commonn format headers are "<name>:[ws]<value>" lines delimited by <CRLF> */
    while (field_start < header_end) {
	const char *field_end;
	const char *field_ptr = field_start;
	do {
	    field_end = field_ptr = field_ptr + strcspn(field_ptr, "\r\n");
	    /* skip CRLF */
	    if (*field_ptr == '\r')
		field_ptr++;
	    if (*field_ptr == '\n')
		field_ptr++;
	}
	while (*field_ptr == ' ' || *field_ptr == '\t');
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
    return 1;			/* even if no fields where found, it is a valid header */
}

/* packs all the entries using supplied packer */
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
HttpHeaderEntry *
httpHeaderGetEntry(const HttpHeader * hdr, HttpHeaderPos * pos)
{
    assert(hdr && pos);
    assert(*pos >= HttpHeaderInitPos && *pos < hdr->entries.count);
    for ((*pos)++; *pos < hdr->entries.count; (*pos)++) {
	if (hdr->entries.items[*pos])
	    return hdr->entries.items[*pos];
    }
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
    return NULL;		/* not reached */
}

/*
 * same as httpHeaderFindEntry
 */
static HttpHeaderEntry *
httpHeaderFindLastEntry(const HttpHeader * hdr, http_hdr_type id)
{
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    HttpHeaderEntry *result = NULL;
    assert(hdr);
    assert_eid(id);
    assert(!CBIT_TEST(ListHeadersMask, id));

    /* check mask first */
    if (!CBIT_TEST(hdr->mask, id))
	return NULL;
    /* looks like we must have it, do linear search */
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	if (e->id == id)
	    result = e;
    }
    assert(result);		/* must be there! */
    return result;
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
    httpHeaderMaskInit(&hdr->mask, 0);	/* temporal inconsistency */
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

/* deletes all entries with a given id, returns the #entries deleted */
int
httpHeaderDelById(HttpHeader * hdr, http_hdr_type id)
{
    int count = 0;
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    debug(55, 8) ("%p del-by-id %d\n", hdr, id);
    assert(hdr);
    assert_eid(id);
    assert_eid(id != HDR_OTHER);	/* does not make sense */
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

/*
 * deletes an entry at pos and leaves a gap; leaving a gap makes it
 * possible to iterate(search) and delete fields at the same time
 */
void
httpHeaderDelAt(HttpHeader * hdr, HttpHeaderPos pos)
{
    HttpHeaderEntry *e;
    assert(pos >= HttpHeaderInitPos && pos < hdr->entries.count);
    e = hdr->entries.items[pos];
    hdr->entries.items[pos] = NULL;
    /* decrement header length, allow for ": " and crlf */
    hdr->len -= strLen(e->name) + 2 + strLen(e->value) + 2;
    assert(hdr->len >= 0);
    httpHeaderEntryDestroy(e);
}


/* appends an entry; 
 * does not call httpHeaderEntryClone() so one should not reuse "*e"
 */
void
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
    /* increment header length, allow for ": " and crlf */
    hdr->len += strLen(e->name) + 2 + strLen(e->value) + 2;
}

/* return a list of entries with the same id separated by ',' and ws */
String
httpHeaderGetList(const HttpHeader * hdr, http_hdr_type id)
{
    String s = StringNull;
    HttpHeaderEntry *e;
    HttpHeaderPos pos = HttpHeaderInitPos;
    debug(55, 6) ("%p: joining for id %d\n", hdr, id);
    /* only fields from ListHeaders array can be "listed" */
    assert(CBIT_TEST(ListHeadersMask, id));
    if (!CBIT_TEST(hdr->mask, id))
	return s;
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	if (e->id == id)
	    strListAdd(&s, strBuf(e->value), ',');
    }
    /*
     * note: we might get an empty (len==0) string if there was an "empty"
     * header; we must not get a NULL string though.
     */
    assert(strBuf(s));
    /* temporary warning: remove it! @?@ @?@ @?@ */
    if (!strLen(s))
	debug(55, 3) ("empty list header: %s (%d)\n", strBuf(Headers[id].name), id);
    debug(55, 6) ("%p: joined for id %d: %s\n", hdr, id, strBuf(s));
    return s;
}

/* return a string or list of entries with the same id separated by ',' and ws */
String
httpHeaderGetStrOrList(const HttpHeader * hdr, http_hdr_type id)
{
    const char *str;
    String s;

    if (CBIT_TEST(ListHeadersMask, id))
	s = httpHeaderGetList(hdr, id);
    else {
	str = httpHeaderGetStr(hdr, id);
	stringInit(&s, str);
    }
    return s;
}

/*
 * returns a pointer to a specified entry if any 
 * note that we return one entry so it does not make much sense to ask for
 * "list" headers
 */
String
httpHeaderGetByName(const HttpHeader * hdr, const char *name)
{
    http_hdr_type id;
    HttpHeaderPos pos = HttpHeaderInitPos;
    HttpHeaderEntry *e;
    String result = StringNull;

    assert(hdr);
    assert(name);

    /* First try the quick path */
    id = httpHeaderIdByNameDef(name, strlen(name));
    if (id != -1)
	return httpHeaderGetStrOrList(hdr, id);

    /* Sorry, an unknown header name. Do linear search */
    while ((e = httpHeaderGetEntry(hdr, &pos))) {
	if (e->id == HDR_OTHER && strCaseCmp(e->name, name) == 0) {
	    strListAdd(&result, strBuf(e->value), ',');
	}
    }
    return result;
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
    assert(Headers[id].type == ftInt);	/* must be of an appropriate type */
    assert(number >= 0);
    httpHeaderAddEntry(hdr, httpHeaderEntryCreate(id, NULL, xitoa(number)));
}

void
httpHeaderPutTime(HttpHeader * hdr, http_hdr_type id, time_t htime)
{
    assert_eid(id);
    assert(Headers[id].type == ftDate_1123);	/* must be of an appropriate type */
    assert(htime >= 0);
    httpHeaderAddEntry(hdr, httpHeaderEntryCreate(id, NULL, mkrfc1123(htime)));
}

void
httpHeaderPutStr(HttpHeader * hdr, http_hdr_type id, const char *str)
{
    assert_eid(id);
    assert(Headers[id].type == ftStr);	/* must be of an appropriate type */
    assert(str);
    httpHeaderAddEntry(hdr, httpHeaderEntryCreate(id, NULL, str));
}

void
httpHeaderPutAuth(HttpHeader * hdr, const char *auth_scheme, const char *realm)
{
    assert(hdr && auth_scheme && realm);
    httpHeaderPutStrf(hdr, HDR_WWW_AUTHENTICATE, "%s realm=\"%s\"", auth_scheme, realm);
}

void
httpHeaderPutCc(HttpHeader * hdr, const HttpHdrCc * cc)
{
    MemBuf mb;
    Packer p;
    assert(hdr && cc);
    /* remove old directives if any */
    httpHeaderDelById(hdr, HDR_CACHE_CONTROL);
    /* pack into mb */
    memBufDefInit(&mb);
    packerToMemInit(&p, &mb);
    httpHdrCcPackInto(cc, &p);
    /* put */
    httpHeaderAddEntry(hdr, httpHeaderEntryCreate(HDR_CACHE_CONTROL, NULL, mb.buf));
    /* cleanup */
    packerClean(&p);
    memBufClean(&mb);
}

void
httpHeaderPutContRange(HttpHeader * hdr, const HttpHdrContRange * cr)
{
    MemBuf mb;
    Packer p;
    assert(hdr && cr);
    /* remove old directives if any */
    httpHeaderDelById(hdr, HDR_CONTENT_RANGE);
    /* pack into mb */
    memBufDefInit(&mb);
    packerToMemInit(&p, &mb);
    httpHdrContRangePackInto(cr, &p);
    /* put */
    httpHeaderAddEntry(hdr, httpHeaderEntryCreate(HDR_CONTENT_RANGE, NULL, mb.buf));
    /* cleanup */
    packerClean(&p);
    memBufClean(&mb);
}

void
httpHeaderPutRange(HttpHeader * hdr, const HttpHdrRange * range)
{
    MemBuf mb;
    Packer p;
    assert(hdr && range);
    /* remove old directives if any */
    httpHeaderDelById(hdr, HDR_RANGE);
    /* pack into mb */
    memBufDefInit(&mb);
    packerToMemInit(&p, &mb);
    httpHdrRangePackInto(range, &p);
    /* put */
    httpHeaderAddEntry(hdr, httpHeaderEntryCreate(HDR_RANGE, NULL, mb.buf));
    /* cleanup */
    packerClean(&p);
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

/* sync with httpHeaderGetLastStr */
const char *
httpHeaderGetStr(const HttpHeader * hdr, http_hdr_type id)
{
    HttpHeaderEntry *e;
    assert_eid(id);
    assert(Headers[id].type == ftStr);	/* must be of an appropriate type */
    if ((e = httpHeaderFindEntry(hdr, id))) {
	httpHeaderNoteParsedEntry(e->id, e->value, 0);	/* no errors are possible */
	return strBuf(e->value);
    }
    return NULL;
}

/* unusual */
const char *
httpHeaderGetLastStr(const HttpHeader * hdr, http_hdr_type id)
{
    HttpHeaderEntry *e;
    assert_eid(id);
    assert(Headers[id].type == ftStr);	/* must be of an appropriate type */
    if ((e = httpHeaderFindLastEntry(hdr, id))) {
	httpHeaderNoteParsedEntry(e->id, e->value, 0);	/* no errors are possible */
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
    s = httpHeaderGetList(hdr, HDR_CACHE_CONTROL);
    cc = httpHdrCcParseCreate(&s);
    HttpHeaderStats[hdr->owner].ccParsedCount++;
    if (cc)
	httpHdrCcUpdateStats(cc, &HttpHeaderStats[hdr->owner].ccTypeDistr);
    httpHeaderNoteParsedEntry(HDR_CACHE_CONTROL, s, !cc);
    stringClean(&s);
    return cc;
}

HttpHdrRange *
httpHeaderGetRange(const HttpHeader * hdr)
{
    HttpHdrRange *r = NULL;
    HttpHeaderEntry *e;
    /* some clients will send "Request-Range" _and_ *matching* "Range"
     * who knows, some clients might send Request-Range only;
     * this "if" should work correctly in both cases;
     * hopefully no clients send mismatched headers! */
    if ((e = httpHeaderFindEntry(hdr, HDR_RANGE)) ||
	(e = httpHeaderFindEntry(hdr, HDR_REQUEST_RANGE))) {
	r = httpHdrRangeParseCreate(&e->value);
	httpHeaderNoteParsedEntry(e->id, e->value, !r);
    }
    return r;
}

HttpHdrContRange *
httpHeaderGetContRange(const HttpHeader * hdr)
{
    HttpHdrContRange *cr = NULL;
    HttpHeaderEntry *e;
    if ((e = httpHeaderFindEntry(hdr, HDR_CONTENT_RANGE))) {
	cr = httpHdrContRangeParseCreate(strBuf(e->value));
	httpHeaderNoteParsedEntry(e->id, e->value, !cr);
    }
    return cr;
}

const char *
httpHeaderGetAuth(const HttpHeader * hdr, http_hdr_type id, const char *auth_scheme)
{
    const char *field;
    int l;
    assert(hdr && auth_scheme);
    field = httpHeaderGetStr(hdr, id);
    if (!field)			/* no authorization field */
	return NULL;
    l = strlen(auth_scheme);
    if (!l || strncasecmp(field, auth_scheme, l))	/* wrong scheme */
	return NULL;
    field += l;
    if (!xisspace(*field))	/* wrong scheme */
	return NULL;
    /* skip white space */
    field += xcountws(field);
    if (!*field)		/* no authorization cookie */
	return NULL;
    return base64_decode(field);
}

ETag
httpHeaderGetETag(const HttpHeader * hdr, http_hdr_type id)
{
    ETag etag =
    {NULL, -1};
    HttpHeaderEntry *e;
    assert(Headers[id].type == ftETag);		/* must be of an appropriate type */
    if ((e = httpHeaderFindEntry(hdr, id)))
	etagParseInit(&etag, strBuf(e->value));
    return etag;
}

TimeOrTag
httpHeaderGetTimeOrTag(const HttpHeader * hdr, http_hdr_type id)
{
    TimeOrTag tot;
    HttpHeaderEntry *e;
    assert(Headers[id].type == ftDate_1123_or_ETag);	/* must be of an appropriate type */
    memset(&tot, 0, sizeof(tot));
    if ((e = httpHeaderFindEntry(hdr, id))) {
	const char *str = strBuf(e->value);
	/* try as an ETag */
	if (etagParseInit(&tot.tag, str)) {
	    tot.valid = tot.tag.str != NULL;
	    tot.time = -1;
	} else {
	    /* or maybe it is time? */
	    tot.time = parse_rfc1123(str);
	    tot.valid = tot.time >= 0;
	    tot.tag.str = NULL;
	}
    }
    assert(tot.time < 0 || !tot.tag.str);	/* paranoid */
    return tot;
}

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
    memFree(e, MEM_HTTP_HDR_ENTRY);
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
    const char *value_start = field_start + name_len + 1;	/* skip ':' */
    /* note: value_end == field_end */

    HeaderEntryParsedCount++;

    /* do we have a valid field name within this field? */
    if (!name_len || name_end > field_end)
	return NULL;
    if (name_len > 65536) {
	/* String has a 64K limit */
	debug(55, 1) ("WARNING: ignoring header name of %d bytes\n", name_len);
	return NULL;
    }
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
    while (value_start < field_end && xisspace(*value_start))
	value_start++;
    if (field_end - value_start > 65536) {
	/* String has a 64K limit */
	debug(55, 1) ("WARNING: ignoring '%s' header of %d bytes\n",
	    strBuf(e->name), field_end - value_start);
	if (e->id == HDR_OTHER)
	    stringClean(&e->name);
	memFree(e, MEM_HTTP_HDR_ENTRY);
	return NULL;
    }
    /* set field value */
    stringLimitInit(&e->value, value_start, field_end - value_start);
    Headers[id].stat.seenCount++;
    Headers[id].stat.aliveCount++;
    debug(55, 9) ("created entry %p: '%s: %s'\n", e, strBuf(e->name), strBuf(e->value));
    return e;
}

HttpHeaderEntry *
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
	debug(55, 2) ("cannot parse hdr field: '%s: %s'\n",
	    strBuf(Headers[id].name), strBuf(context));
    }
}

/*
 * Reports
 */

/* tmp variable used to pass stat info to dumpers */
extern const HttpHeaderStat *dump_stat;		/* argh! */
const HttpHeaderStat *dump_stat = NULL;

static void
httpHeaderFieldStatDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    const int id = (int) val;
    const int valid_id = id >= 0 && id < HDR_ENUM_END;
    const char *name = valid_id ? strBuf(Headers[id].name) : "INVALID";
    int visible = count > 0;
    /* for entries with zero count, list only those that belong to current type of message */
    if (!visible && valid_id && dump_stat->owner_mask)
	visible = CBIT_TEST(*dump_stat->owner_mask, id);
    if (visible)
	storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
	    id, name, count, xdiv(count, dump_stat->busyDestroyedCount));
}

static void
httpHeaderFldsPerHdrDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    if (count)
	storeAppendPrintf(sentry, "%2d\t %5d\t %5d\t %6.2f\n",
	    idx, (int) val, count,
	    xpercent(count, dump_stat->destroyedCount));
}


static void
httpHeaderStatDump(const HttpHeaderStat * hs, StoreEntry * e)
{
    assert(hs && e);

    dump_stat = hs;
    storeAppendPrintf(e, "\nHeader Stats: %s\n", hs->label);
    storeAppendPrintf(e, "\nField type distribution\n");
    storeAppendPrintf(e, "%2s\t %-20s\t %5s\t %6s\n",
	"id", "name", "count", "#/header");
    statHistDump(&hs->fieldTypeDistr, e, httpHeaderFieldStatDumper);
    storeAppendPrintf(e, "\nCache-control directives distribution\n");
    storeAppendPrintf(e, "%2s\t %-20s\t %5s\t %6s\n",
	"id", "name", "count", "#/cc_field");
    statHistDump(&hs->ccTypeDistr, e, httpHdrCcStatDumper);
    storeAppendPrintf(e, "\nNumber of fields per header distribution\n");
    storeAppendPrintf(e, "%2s\t %-5s\t %5s\t %6s\n",
	"id", "#flds", "count", "%total");
    statHistDump(&hs->hdrUCountDistr, e, httpHeaderFldsPerHdrDumper);
    dump_stat = NULL;
}

void
httpHeaderStoreReport(StoreEntry * e)
{
    int i;
    http_hdr_type ht;
    assert(e);

    HttpHeaderStats[0].parsedCount =
	HttpHeaderStats[hoRequest].parsedCount + HttpHeaderStats[hoReply].parsedCount;
    HttpHeaderStats[0].ccParsedCount =
	HttpHeaderStats[hoRequest].ccParsedCount + HttpHeaderStats[hoReply].ccParsedCount;
    HttpHeaderStats[0].destroyedCount =
	HttpHeaderStats[hoRequest].destroyedCount + HttpHeaderStats[hoReply].destroyedCount;
    HttpHeaderStats[0].busyDestroyedCount =
	HttpHeaderStats[hoRequest].busyDestroyedCount + HttpHeaderStats[hoReply].busyDestroyedCount;

    for (i = 1; i < HttpHeaderStatCount; i++) {
	httpHeaderStatDump(HttpHeaderStats + i, e);
	storeAppendPrintf(e, "%s\n", "<br>");
    }
    /* field stats for all messages */
    storeAppendPrintf(e, "\nHttp Fields Stats (replies and requests)\n");
    storeAppendPrintf(e, "%2s\t %-20s\t %5s\t %6s\t %6s\n",
	"id", "name", "#alive", "%err", "%repeat");
    for (ht = 0; ht < HDR_ENUM_END; ht++) {
	HttpHeaderFieldInfo *f = Headers + ht;
	storeAppendPrintf(e, "%2d\t %-20s\t %5d\t %6.3f\t %6.3f\n",
	    f->id, strBuf(f->name), f->stat.aliveCount,
	    xpercent(f->stat.errCount, f->stat.parsCount),
	    xpercent(f->stat.repCount, f->stat.seenCount));
    }
    storeAppendPrintf(e, "Headers Parsed: %d + %d = %d\n",
	HttpHeaderStats[hoRequest].parsedCount,
	HttpHeaderStats[hoReply].parsedCount,
	HttpHeaderStats[0].parsedCount);
    storeAppendPrintf(e, "Hdr Fields Parsed: %d\n", HeaderEntryParsedCount);
}

int
httpHeaderIdByName(const char *name, int name_len, const HttpHeaderFieldInfo * info, int end)
{
    int i;
    for (i = 0; i < end; ++i) {
	if (name_len >= 0 && name_len != strLen(info[i].name))
	    continue;
	if (!strncasecmp(name, strBuf(info[i].name),
		name_len < 0 ? strLen(info[i].name) + 1 : name_len))
	    return i;
    }
    return -1;
}

int
httpHeaderIdByNameDef(const char *name, int name_len)
{
    if (!Headers)
	Headers = httpHeaderBuildFieldsInfo(HeadersAttrs, HDR_ENUM_END);
    return httpHeaderIdByName(name, name_len, Headers, HDR_ENUM_END);
}

const char *
httpHeaderNameById(int id)
{
    if (!Headers)
	Headers = httpHeaderBuildFieldsInfo(HeadersAttrs, HDR_ENUM_END);
    assert(id >= 0 && id < HDR_ENUM_END);
    return HeadersAttrs[id].name;
}
