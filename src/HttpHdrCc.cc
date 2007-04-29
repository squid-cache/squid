
/*
 * $Id: HttpHdrCc.cc,v 1.29 2007/04/28 22:26:37 hno Exp $
 *
 * DEBUG: section 65    HTTP Cache Control Header
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
#include "Store.h"
#include "HttpHeader.h"

/* this table is used for parsing cache control header */
static const HttpHeaderFieldAttrs CcAttrs[CC_ENUM_END] =
    {
        {"public", (http_hdr_type)CC_PUBLIC},

        {"private", (http_hdr_type)CC_PRIVATE},
        {"no-cache", (http_hdr_type)CC_NO_CACHE},
        {"no-store", (http_hdr_type)CC_NO_STORE},
        {"no-transform", (http_hdr_type)CC_NO_TRANSFORM},
        {"must-revalidate", (http_hdr_type)CC_MUST_REVALIDATE},
        {"proxy-revalidate", (http_hdr_type)CC_PROXY_REVALIDATE},
        {"only-if-cached", (http_hdr_type)CC_ONLY_IF_CACHED},
        {"max-age", (http_hdr_type)CC_MAX_AGE},
        {"s-maxage", (http_hdr_type)CC_S_MAXAGE},
        {"max-stale", (http_hdr_type)CC_MAX_STALE},
        {"Other,", (http_hdr_type)CC_OTHER}	/* ',' will protect from matches */
    };

HttpHeaderFieldInfo *CcFieldsInfo = NULL;

http_hdr_cc_type &operator++ (http_hdr_cc_type &aHeader)
{
    int tmp = (int)aHeader;
    aHeader = (http_hdr_cc_type)(++tmp);
    return aHeader;
}


/* local prototypes */
static int httpHdrCcParseInit(HttpHdrCc * cc, const String * str);


/* module initialization */

void
httpHdrCcInitModule(void)
{
    CcFieldsInfo = httpHeaderBuildFieldsInfo(CcAttrs, CC_ENUM_END);
}

void
httpHdrCcCleanModule(void)
{
    httpHeaderDestroyFieldsInfo(CcFieldsInfo, CC_ENUM_END);
    CcFieldsInfo = NULL;
}

/* implementation */

HttpHdrCc *
httpHdrCcCreate(void)
{
    HttpHdrCc *cc = (HttpHdrCc *)memAllocate(MEM_HTTP_HDR_CC);
    cc->max_age = cc->s_maxage = cc->max_stale = -1;
    return cc;
}

/* creates an cc object from a 0-terminating string */
HttpHdrCc *
httpHdrCcParseCreate(const String * str)
{
    HttpHdrCc *cc = httpHdrCcCreate();

    if (!httpHdrCcParseInit(cc, str)) {
        httpHdrCcDestroy(cc);
        cc = NULL;
    }

    return cc;
}

/* parses a 0-terminating string and inits cc */
static int
httpHdrCcParseInit(HttpHdrCc * cc, const String * str)
{
    const char *item;
    const char *p;		/* '=' parameter */
    const char *pos = NULL;
    http_hdr_cc_type type;
    int ilen;
    int nlen;
    assert(cc && str);

    /* iterate through comma separated list */

    while (strListGetItem(str, ',', &item, &ilen, &pos)) {
        /* isolate directive name */

        if ((p = (const char *)memchr(item, '=', ilen)) && (p - item < ilen))
            nlen = p++ - item;
        else
            nlen = ilen;

        /* find type */
        type = (http_hdr_cc_type ) httpHeaderIdByName(item, nlen,
                CcFieldsInfo, CC_ENUM_END);

        if (type < 0) {
            debugs(65, 2, "hdr cc: unknown cache-directive: near '" << item << "' in '" << str->buf() << "'");
            type = CC_OTHER;
        }

        if (EBIT_TEST(cc->mask, type)) {
            if (type != CC_OTHER)
                debugs(65, 2, "hdr cc: ignoring duplicate cache-directive: near '" << item << "' in '" << str->buf() << "'");

            CcFieldsInfo[type].stat.repCount++;

            continue;
        }

        /* update mask */
        EBIT_SET(cc->mask, type);

        /* post-processing special cases */
        switch (type) {

        case CC_MAX_AGE:

            if (!p || !httpHeaderParseInt(p, &cc->max_age)) {
                debugs(65, 2, "cc: invalid max-age specs near '" << item << "'");
                cc->max_age = -1;
                EBIT_CLR(cc->mask, type);
            }

            break;

        case CC_S_MAXAGE:

            if (!p || !httpHeaderParseInt(p, &cc->s_maxage)) {
                debugs(65, 2, "cc: invalid s-maxage specs near '" << item << "'");
                cc->s_maxage = -1;
                EBIT_CLR(cc->mask, type);
            }

            break;

        case CC_MAX_STALE:

            if (!p || !httpHeaderParseInt(p, &cc->max_stale)) {
                debugs(65, 2, "cc: max-stale directive is valid without value");
                cc->max_stale = -1;
            }

            break;

        case CC_OTHER:

            if (cc->other.size())
                cc->other.append(", ");

            cc->other.append(item, ilen);

            break;

        default:
            /* note that we ignore most of '=' specs (RFCVIOLATION) */
            break;
        }
    }

    return cc->mask != 0;
}

void
httpHdrCcDestroy(HttpHdrCc * cc)
{
    assert(cc);

    if (cc->other.buf())
        cc->other.clean();

    memFree(cc, MEM_HTTP_HDR_CC);
}

HttpHdrCc *
httpHdrCcDup(const HttpHdrCc * cc)
{
    HttpHdrCc *dup;
    assert(cc);
    dup = httpHdrCcCreate();
    dup->mask = cc->mask;
    dup->max_age = cc->max_age;
    dup->s_maxage = cc->s_maxage;
    dup->max_stale = cc->max_stale;
    return dup;
}

void
httpHdrCcPackInto(const HttpHdrCc * cc, Packer * p)
{
    http_hdr_cc_type flag;
    int pcount = 0;
    assert(cc && p);

    for (flag = CC_PUBLIC; flag < CC_ENUM_END; ++flag) {
        if (EBIT_TEST(cc->mask, flag) && flag != CC_OTHER) {

            /* print option name */
            packerPrintf(p, (pcount ? ", %s" : "%s"), CcFieldsInfo[flag].name.buf());

            /* handle options with values */

            if (flag == CC_MAX_AGE)
                packerPrintf(p, "=%d", (int) cc->max_age);

            if (flag == CC_S_MAXAGE)
                packerPrintf(p, "=%d", (int) cc->s_maxage);

            if (flag == CC_MAX_STALE)
                packerPrintf(p, "=%d", (int) cc->max_stale);

            pcount++;
        }
    }

    if (cc->other.size())
        packerPrintf(p, (pcount ? ", %s" : "%s"), cc->other.buf());
}

/* negative max_age will clean old max_Age setting */
void
httpHdrCcSetMaxAge(HttpHdrCc * cc, int max_age)
{
    assert(cc);
    cc->max_age = max_age;

    if (max_age >= 0)
        EBIT_SET(cc->mask, CC_MAX_AGE);
    else
        EBIT_CLR(cc->mask, CC_MAX_AGE);
}

/* negative s_maxage will clean old s-maxage setting */
void
httpHdrCcSetSMaxAge(HttpHdrCc * cc, int s_maxage)
{
    assert(cc);
    cc->s_maxage = s_maxage;

    if (s_maxage >= 0)
        EBIT_SET(cc->mask, CC_S_MAXAGE);
    else
        EBIT_CLR(cc->mask, CC_S_MAXAGE);
}

void
httpHdrCcUpdateStats(const HttpHdrCc * cc, StatHist * hist)
{
    http_hdr_cc_type c;
    assert(cc);

    for (c = CC_PUBLIC; c < CC_ENUM_END; ++c)
        if (EBIT_TEST(cc->mask, c))
            statHistCount(hist, c);
}

void
httpHdrCcStatDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    extern const HttpHeaderStat *dump_stat;	/* argh! */
    const int id = (int) val;
    const int valid_id = id >= 0 && id < CC_ENUM_END;
    const char *name = valid_id ? CcFieldsInfo[id].name.buf() : "INVALID";

    if (count || valid_id)
        storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
                          id, name, count, xdiv(count, dump_stat->ccParsedCount));
}
