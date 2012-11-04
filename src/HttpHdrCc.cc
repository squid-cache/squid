/*
 *
 * DEBUG: section 65    HTTP Cache Control Header
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
#include "base/StringArea.h"
#include "HttpHeader.h"
#include "HttpHeaderFieldStat.h"
#include "HttpHeaderStat.h"
#include "HttpHeaderTools.h"
#include "HttpHdrCc.h"
#include "StatHist.h"
#include "Store.h"
#include "StrList.h"

#if HAVE_MAP
#include <map>
#endif

/* a row in the table used for parsing cache control header and statistics */
typedef struct {
    const char *name;
    http_hdr_cc_type id;
    HttpHeaderFieldStat stat;
} HttpHeaderCcFields;

/* order must match that of enum http_hdr_cc_type. The constraint is verified at initialization time */
static HttpHeaderCcFields CcAttrs[CC_ENUM_END] = {
    {"public", CC_PUBLIC},
    {"private", CC_PRIVATE},
    {"no-cache", CC_NO_CACHE},
    {"no-store", CC_NO_STORE},
    {"no-transform", CC_NO_TRANSFORM},
    {"must-revalidate", CC_MUST_REVALIDATE},
    {"proxy-revalidate", CC_PROXY_REVALIDATE},
    {"max-age", CC_MAX_AGE},
    {"s-maxage", CC_S_MAXAGE},
    {"max-stale", CC_MAX_STALE},
    {"min-fresh", CC_MIN_FRESH},
    {"only-if-cached", CC_ONLY_IF_CACHED},
    {"stale-if-error", CC_STALE_IF_ERROR},
    {"Other,", CC_OTHER} /* ',' will protect from matches */
};

/// Map an header name to its type, to expedite parsing
typedef std::map<const StringArea,http_hdr_cc_type> CcNameToIdMap_t;
static CcNameToIdMap_t CcNameToIdMap;

/// used to walk a table of http_header_cc_type structs
http_hdr_cc_type &operator++ (http_hdr_cc_type &aHeader)
{
    int tmp = (int)aHeader;
    aHeader = (http_hdr_cc_type)(++tmp);
    return aHeader;
}

/// Module initialization hook
void
httpHdrCcInitModule(void)
{
    /* build lookup and accounting structures */
    for (int32_t i = 0; i < CC_ENUM_END; ++i) {
        const HttpHeaderCcFields &f=CcAttrs[i];
        assert(i == f.id); /* verify assumption: the id is the key into the array */
        const StringArea k(f.name,strlen(f.name));
        CcNameToIdMap[k]=f.id;
    }
}

/// Module cleanup hook.
void
httpHdrCcCleanModule(void)
{
    // HdrCcNameToIdMap is self-cleaning
}

void
HttpHdrCc::clear()
{
    *this=HttpHdrCc();
}

bool
HttpHdrCc::parse(const String & str)
{
    const char *item;
    const char *p;		/* '=' parameter */
    const char *pos = NULL;
    http_hdr_cc_type type;
    int ilen;
    int nlen;

    /* iterate through comma separated list */

    while (strListGetItem(&str, ',', &item, &ilen, &pos)) {
        /* isolate directive name */

        if ((p = (const char *)memchr(item, '=', ilen)) && (p - item < ilen)) {
            nlen = p - item;
            ++p;
        } else {
            nlen = ilen;
        }

        /* find type */
        const CcNameToIdMap_t::const_iterator i=CcNameToIdMap.find(StringArea(item,nlen));
        if (i==CcNameToIdMap.end())
            type=CC_OTHER;
        else
            type=i->second;

        // ignore known duplicate directives
        if (isSet(type)) {
            if (type != CC_OTHER) {
                debugs(65, 2, "hdr cc: ignoring duplicate cache-directive: near '" << item << "' in '" << str << "'");
                ++CcAttrs[type].stat.repCount;
                continue;
            }
        }

        /* special-case-parsing and attribute-setting */
        switch (type) {

        case CC_MAX_AGE:
            if (!p || !httpHeaderParseInt(p, &max_age) || max_age < 0) {
                debugs(65, 2, "cc: invalid max-age specs near '" << item << "'");
                clearMaxAge();
            } else {
                setMask(type,true);
            }
            break;

        case CC_S_MAXAGE:
            if (!p || !httpHeaderParseInt(p, &s_maxage) || s_maxage < 0) {
                debugs(65, 2, "cc: invalid s-maxage specs near '" << item << "'");
                clearSMaxAge();
            } else {
                setMask(type,true);
            }
            break;

        case CC_MAX_STALE:
            if (!p || !httpHeaderParseInt(p, &max_stale) || max_stale < 0) {
                debugs(65, 2, "cc: max-stale directive is valid without value");
                maxStale(MAX_STALE_ANY);
            } else {
                setMask(type,true);
            }
            break;

        case CC_MIN_FRESH:
            if (!p || !httpHeaderParseInt(p, &min_fresh) || min_fresh < 0) {
                debugs(65, 2, "cc: invalid min-fresh specs near '" << item << "'");
                clearMinFresh();
            } else {
                setMask(type,true);
            }
            break;

        case CC_STALE_IF_ERROR:
            if (!p || !httpHeaderParseInt(p, &stale_if_error) || stale_if_error < 0) {
                debugs(65, 2, "cc: invalid stale-if-error specs near '" << item << "'");
                clearStaleIfError();
            } else {
                setMask(type,true);
            }
            break;

        case CC_PUBLIC:
            Public(true);
            break;
        case CC_PRIVATE:
            Private(true);
            break;
        case CC_NO_CACHE:
            noCache(true);
            break;
        case CC_NO_STORE:
            noStore(true);
            break;
        case CC_NO_TRANSFORM:
            noTransform(true);
            break;
        case CC_MUST_REVALIDATE:
            mustRevalidate(true);
            break;
        case CC_PROXY_REVALIDATE:
            proxyRevalidate(true);
            break;
        case CC_ONLY_IF_CACHED:
            onlyIfCached(true);
            break;

        case CC_OTHER:
            if (other.size())
                other.append(", ");

            other.append(item, ilen);
            break;

        default:
            /* note that we ignore most of '=' specs (RFCVIOLATION) */
            break;
        }
    }

    return (mask != 0);
}

void
HttpHdrCc::packInto(Packer * p) const
{
    // optimization: if the mask is empty do nothing
    if (mask==0)
        return;

    http_hdr_cc_type flag;
    int pcount = 0;
    assert(p);

    for (flag = CC_PUBLIC; flag < CC_ENUM_END; ++flag) {
        if (isSet(flag) && flag != CC_OTHER) {

            /* print option name for all options */
            packerPrintf(p, (pcount ? ", %s": "%s") , CcAttrs[flag].name);

            /* for all options having values, "=value" after the name */
            switch (flag) {
            case CC_MAX_AGE:
                packerPrintf(p, "=%d", (int) maxAge());
                break;
            case CC_S_MAXAGE:
                packerPrintf(p, "=%d", (int) sMaxAge());
                break;
            case CC_MAX_STALE:
                /* max-stale's value is optional.
                  If we didn't receive it, don't send it */
                if (maxStale()!=MAX_STALE_ANY)
                    packerPrintf(p, "=%d", (int) maxStale());
                break;
            case CC_MIN_FRESH:
                packerPrintf(p, "=%d", (int) minFresh());
                break;
            default:
                /* do nothing, directive was already printed */
                break;
            }

            ++pcount;
        }
    }

    if (other.size() != 0)
        packerPrintf(p, (pcount ? ", " SQUIDSTRINGPH : SQUIDSTRINGPH),
                     SQUIDSTRINGPRINT(other));
}

void
httpHdrCcUpdateStats(const HttpHdrCc * cc, StatHist * hist)
{
    http_hdr_cc_type c;
    assert(cc);

    for (c = CC_PUBLIC; c < CC_ENUM_END; ++c)
        if (cc->isSet(c))
            hist->count(c);
}

void
httpHdrCcStatDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    extern const HttpHeaderStat *dump_stat;	/* argh! */
    const int id = (int) val;
    const int valid_id = id >= 0 && id < CC_ENUM_END;
    const char *name = valid_id ? CcAttrs[id].name : "INVALID";

    if (count || valid_id)
        storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
                          id, name, count, xdiv(count, dump_stat->ccParsedCount));
}

#if !_USE_INLINE_
#include "HttpHdrCc.cci"
#endif
