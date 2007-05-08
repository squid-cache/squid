
/*
 * $Id: HttpHeaderTools.cc,v 1.59 2007/05/07 18:12:28 wessels Exp $
 *
 * DEBUG: section 66    HTTP Header Tools
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
#include "HttpHeader.h"
#include "HttpHdrContRange.h"
#include "ACLChecklist.h"
#include "MemBuf.h"

static void httpHeaderPutStrvf(HttpHeader * hdr, http_hdr_type id, const char *fmt, va_list vargs);


HttpHeaderFieldInfo *
httpHeaderBuildFieldsInfo(const HttpHeaderFieldAttrs * attrs, int count)
{
    int i;
    HttpHeaderFieldInfo *table = NULL;
    assert(attrs && count);

    /* allocate space */
    table = new HttpHeaderFieldInfo[count];

    for (i = 0; i < count; ++i) {
        const http_hdr_type id = attrs[i].id;
        HttpHeaderFieldInfo *info = table + id;
        /* sanity checks */
        assert(id >= 0 && id < count);
        assert(attrs[i].name);
        assert(info->id == HDR_ACCEPT && info->type == ftInvalid);	/* was not set before */
        /* copy and init fields */
        info->id = id;
        info->type = attrs[i].type;
        info->name = attrs[i].name;
        assert(info->name.size());
    }

    return table;
}

void
httpHeaderDestroyFieldsInfo(HttpHeaderFieldInfo * table, int count)
{
    int i;

    for (i = 0; i < count; ++i)
        table[i].name.clean();

    delete [] table;
}

void
httpHeaderMaskInit(HttpHeaderMask * mask, int value)
{
    memset(mask, value, sizeof(*mask));
}

/* calculates a bit mask of a given array; does not reset mask! */
void
httpHeaderCalcMask(HttpHeaderMask * mask, http_hdr_type http_hdr_type_enums[], size_t count)
{
    size_t i;
    const int * enums = (const int *) http_hdr_type_enums;
    assert(mask && enums);
    assert(count < sizeof(*mask) * 8);	/* check for overflow */

    for (i = 0; i < count; ++i) {
        assert(!CBIT_TEST(*mask, enums[i]));	/* check for duplicates */
        CBIT_SET(*mask, enums[i]);
    }
}

/* same as httpHeaderPutStr, but formats the string using snprintf first */
void
#if STDC_HEADERS
httpHeaderPutStrf(HttpHeader * hdr, http_hdr_type id, const char *fmt,...)
#else
httpHeaderPutStrf(va_alist)
va_dcl
#endif
{
#if STDC_HEADERS
    va_list args;
    va_start(args, fmt);
#else

    va_list args;
    HttpHeader *hdr = NULL;
    http_hdr_type id = HDR_ENUM_END;
    const char *fmt = NULL;
    va_start(args);
    hdr = va_arg(args, HttpHeader *);
    id = va_arg(args, http_hdr_type);
    fmt = va_arg(args, char *);
#endif

    httpHeaderPutStrvf(hdr, id, fmt, args);
    va_end(args);
}

/* used by httpHeaderPutStrf */
static void
httpHeaderPutStrvf(HttpHeader * hdr, http_hdr_type id, const char *fmt, va_list vargs)
{
    MemBuf mb;
    mb.init();
    mb.vPrintf(fmt, vargs);
    hdr->putStr(id, mb.buf);
    mb.clean();
}


/* wrapper arrounf PutContRange */
void
httpHeaderAddContRange(HttpHeader * hdr, HttpHdrRangeSpec spec, ssize_t ent_len)
{
    HttpHdrContRange *cr = httpHdrContRangeCreate();
    assert(hdr && ent_len >= 0);
    httpHdrContRangeSet(cr, spec, ent_len);
    hdr->putContRange(cr);
    httpHdrContRangeDestroy(cr);
}


/*
 * return true if a given directive is found in at least one of
 * the "connection" header-fields note: if HDR_PROXY_CONNECTION is
 * present we ignore HDR_CONNECTION.
 */
int
httpHeaderHasConnDir(const HttpHeader * hdr, const char *directive)
{
    String list;
    http_hdr_type ht;
    int res;
    /* what type of header do we have? */

    if (hdr->has(HDR_PROXY_CONNECTION))
        ht = HDR_PROXY_CONNECTION;
    else if (hdr->has(HDR_CONNECTION))
        ht = HDR_CONNECTION;
    else
        return 0;

    list = hdr->getList(ht);

    res = strListIsMember(&list, directive, ',');

    list.clean();

    return res;
}

/* returns true iff "m" is a member of the list */
int
strListIsMember(const String * list, const char *m, char del)
{
    const char *pos = NULL;
    const char *item;
    int ilen = 0;
    int mlen;
    assert(list && m);
    mlen = strlen(m);

    while (strListGetItem(list, del, &item, &ilen, &pos)) {
        if (mlen == ilen && !strncasecmp(item, m, ilen))
            return 1;
    }

    return 0;
}

/* returns true iff "s" is a substring of a member of the list */
int
strListIsSubstr(const String * list, const char *s, char del)
{
    assert(list && del);
    return list->pos(s) != 0;

    /*
     * Note: the original code with a loop is broken because it uses strstr()
     * instead of strnstr(). If 's' contains a 'del', strListIsSubstr() may
     * return true when it should not. If 's' does not contain a 'del', the
     * implementaion is equavalent to strstr()! Thus, we replace the loop with
     * strstr() above until strnstr() is available.
     */
}

/* appends an item to the list */
void
strListAdd(String * str, const char *item, char del)
{
    assert(str && item);

    if (str->size()) {
        char buf[3];
        buf[0] = del;
        buf[1] = ' ';
        buf[2] = '\0';
        str->append(buf, 2);
    }

    str->append(item, strlen(item));
}

/*
 * iterates through a 0-terminated string of items separated by 'del's.
 * white space around 'del' is considered to be a part of 'del'
 * like strtok, but preserves the source, and can iterate several strings at once
 *
 * returns true if next item is found.
 * init pos with NULL to start iteration.
 */
int
strListGetItem(const String * str, char del, const char **item, int *ilen, const char **pos)
{
    size_t len;
    static char delim[2][3] = {
                                  { '"', '?', 0},
                                  { '"', '\\', 0}};
    int quoted = 0;
    assert(str && item && pos);

    delim[0][1] = del;

    if (*pos) {
        if (!**pos)		/* end of string */
            return 0;
        else
            (*pos)++;
    } else {
        *pos = str->buf();

        if (!*pos)
            return 0;
    }

    /* skip leading ws (ltrim) */
    *pos += xcountws(*pos);

    *item = *pos;		/* remember item's start */

    /* find next delimiter */
    do {
        *pos += strcspn(*pos, delim[quoted]);

        if (**pos == del)
            break;

        if (**pos == '"') {
            quoted = !quoted;
            *pos += 1;
        }

        if (quoted && **pos == '\\') {
            *pos += 1;

            if (**pos)
                *pos += 1;
        }
    } while (**pos);

    len = *pos - *item;		/* *pos points to del or '\0' */

    /* rtrim */
    while (len > 0 && xisspace((*item)[len - 1]))
        len--;

    if (ilen)
        *ilen = len;

    return len > 0;
}

/* handy to printf prefixes of potentially very long buffers */
const char *
getStringPrefix(const char *str, const char *end)
{
#define SHORT_PREFIX_SIZE 512
    LOCAL_ARRAY(char, buf, SHORT_PREFIX_SIZE);
    const int sz = 1 + (end ? end - str : strlen(str));
    xstrncpy(buf, str, (sz > SHORT_PREFIX_SIZE) ? SHORT_PREFIX_SIZE : sz);
    return buf;
}

/*
 * parses an int field, complains if soemthing went wrong, returns true on
 * success
 */
int
httpHeaderParseInt(const char *start, int *value)
{
    assert(value);
    *value = atoi(start);

    if (!*value && !xisdigit(*start)) {
        debugs(66, 2, "failed to parse an int header field near '" << start << "'");
        return 0;
    }

    return 1;
}

int
httpHeaderParseSize(const char *start, ssize_t * value)
{
    int v;
    const int res = httpHeaderParseInt(start, &v);
    assert(value);
    *value = res ? v : 0;
    return res;
}


/* Parses a quoted-string field (RFC 2616 section 2.2), complains if
 * something went wrong, returns non-zero on success.
 * start should point at the first ".
 * RC TODO: This is too looose. We should honour the BNF and exclude CTL's
 */
int
httpHeaderParseQuotedString (const char *start, String *val)
{
    const char *end, *pos;
    val->clean();
    assert (*start == '"');
    pos = start + 1;

    while (1) {
        if (!(end = index (pos,'"'))) {
            debugs(66, 2, "failed to parse a quoted-string header field near '" << start << "'");
            return 0;
        }

        /* check for quoted-chars */
        if (*(end - 1) != '\\') {
            /* done */
            val->append(start + 1, end-start-1);
            return 1;
        }

        /* try for the end again */
        pos = end + 1;
    }
}

/*
 * httpHdrMangle checks the anonymizer (header_access) configuration.
 * Returns 1 if the header is allowed.
 */
static int
httpHdrMangle(HttpHeaderEntry * e, HttpRequest * request, int req_or_rep)
{
    int retval;

    /* check with anonymizer tables */
    header_mangler *hm;
    ACLChecklist *checklist;
    assert(e);

    if (ROR_REQUEST == req_or_rep) {
        hm = &Config.request_header_access[e->id];
    } else if (ROR_REPLY == req_or_rep) {
        hm = &Config.reply_header_access[e->id];
    } else {
        /* error. But let's call it "request". */
        hm = &Config.request_header_access[e->id];
    }

    checklist = aclChecklistCreate(hm->access_list, request, NULL);

    if (1 == checklist->fastCheck()) {
        /* aclCheckFast returns 1 for allow. */
        retval = 1;
    } else if (NULL == hm->replacement) {
        /* It was denied, and we don't have any replacement */
        retval = 0;
    } else {
        /* It was denied, but we have a replacement. Replace the
         * header on the fly, and return that the new header
         * is allowed.
         */
        e->value = hm->replacement;
        retval = 1;
    }

    delete checklist;
    return retval;
}

/* Mangles headers for a list of headers. */
void
httpHdrMangleList(HttpHeader * l, HttpRequest * request, int req_or_rep)
{
    HttpHeaderEntry *e;
    HttpHeaderPos p = HttpHeaderInitPos;

    int headers_deleted = 0;
    while ((e = l->getEntry(&p)))
        if (0 == httpHdrMangle(e, request, req_or_rep))
            l->delAt(p, headers_deleted);

    if (headers_deleted)
        l->refreshMask();
}

/*
 * return 1 if manglers are configured.  Used to set a flag
 * for optimization during request forwarding.
 */
int
httpReqHdrManglersConfigured()
{
    for (int i = 0; i < HDR_ENUM_END; i++) {
        if (NULL != Config.request_header_access[i].access_list)
            return 1;
    }

    return 0;
}
