/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 65    HTTP Cache Control Header */

#include "squid.h"
#include "base/LookupTable.h"
#include "HttpHdrCc.h"
#include "HttpHeader.h"
#include "HttpHeaderFieldStat.h"
#include "HttpHeaderStat.h"
#include "HttpHeaderTools.h"
#include "sbuf/SBuf.h"
#include "StatHist.h"
#include "Store.h"
#include "StrList.h"
#include "util.h"

#include <map>
#include <vector>
#include <ostream>

// invariant: row[j].id == j
static LookupTable<HttpHdrCcType>::Record CcAttrs[] = {
    {"public", HttpHdrCcType::CC_PUBLIC},
    {"private", HttpHdrCcType::CC_PRIVATE},
    {"no-cache", HttpHdrCcType::CC_NO_CACHE},
    {"no-store", HttpHdrCcType::CC_NO_STORE},
    {"no-transform", HttpHdrCcType::CC_NO_TRANSFORM},
    {"must-revalidate", HttpHdrCcType::CC_MUST_REVALIDATE},
    {"proxy-revalidate", HttpHdrCcType::CC_PROXY_REVALIDATE},
    {"max-age", HttpHdrCcType::CC_MAX_AGE},
    {"s-maxage", HttpHdrCcType::CC_S_MAXAGE},
    {"max-stale", HttpHdrCcType::CC_MAX_STALE},
    {"min-fresh", HttpHdrCcType::CC_MIN_FRESH},
    {"only-if-cached", HttpHdrCcType::CC_ONLY_IF_CACHED},
    {"stale-if-error", HttpHdrCcType::CC_STALE_IF_ERROR},
    {"immutable", HttpHdrCcType::CC_IMMUTABLE},
    {"Other,", HttpHdrCcType::CC_OTHER}, /* ',' will protect from matches */
    {nullptr, HttpHdrCcType::CC_ENUM_END}
};
LookupTable<HttpHdrCcType> ccLookupTable(HttpHdrCcType::CC_OTHER,CcAttrs);
std::vector<HttpHeaderFieldStat> ccHeaderStats(HttpHdrCcType::CC_ENUM_END);

/// used to walk a table of http_header_cc_type structs
HttpHdrCcType &operator++ (HttpHdrCcType &aHeader)
{
    int tmp = (int)aHeader;
    aHeader = (HttpHdrCcType)(++tmp);
    return aHeader;
}

/// Module initialization hook
void
httpHdrCcInitModule(void)
{
    // check invariant on initialization table
    for (unsigned int j = 0; CcAttrs[j].name != nullptr; ++j) {
        assert (static_cast<int>(CcAttrs[j].id) == j);
    }
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
    const char *p;      /* '=' parameter */
    const char *pos = NULL;
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
        const HttpHdrCcType type = ccLookupTable.lookup(SBuf(item,nlen));

        // ignore known duplicate directives
        if (isSet(type)) {
            if (type != HttpHdrCcType::CC_OTHER) {
                debugs(65, 2, "hdr cc: ignoring duplicate cache-directive: near '" << item << "' in '" << str << "'");
                ++ ccHeaderStats[type].repCount;
                continue;
            }
        }

        /* special-case-parsing and attribute-setting */
        switch (type) {

        case HttpHdrCcType::CC_MAX_AGE:
            if (!p || !httpHeaderParseInt(p, &max_age) || max_age < 0) {
                debugs(65, 2, "cc: invalid max-age specs near '" << item << "'");
                clearMaxAge();
            } else {
                setMask(type,true);
            }
            break;

        case HttpHdrCcType::CC_S_MAXAGE:
            if (!p || !httpHeaderParseInt(p, &s_maxage) || s_maxage < 0) {
                debugs(65, 2, "cc: invalid s-maxage specs near '" << item << "'");
                clearSMaxAge();
            } else {
                setMask(type,true);
            }
            break;

        case HttpHdrCcType::CC_MAX_STALE:
            if (!p || !httpHeaderParseInt(p, &max_stale) || max_stale < 0) {
                debugs(65, 2, "cc: max-stale directive is valid without value");
                maxStale(MAX_STALE_ANY);
            } else {
                setMask(type,true);
            }
            break;

        case HttpHdrCcType::CC_MIN_FRESH:
            if (!p || !httpHeaderParseInt(p, &min_fresh) || min_fresh < 0) {
                debugs(65, 2, "cc: invalid min-fresh specs near '" << item << "'");
                clearMinFresh();
            } else {
                setMask(type,true);
            }
            break;

        case HttpHdrCcType::CC_STALE_IF_ERROR:
            if (!p || !httpHeaderParseInt(p, &stale_if_error) || stale_if_error < 0) {
                debugs(65, 2, "cc: invalid stale-if-error specs near '" << item << "'");
                clearStaleIfError();
            } else {
                setMask(type,true);
            }
            break;

        case HttpHdrCcType::CC_PRIVATE: {
            String temp;
            if (!p)  {
                // Value parameter is optional.
                private_.clean();
            }            else if (/* p &&*/ httpHeaderParseQuotedString(p, (ilen-nlen-1), &temp)) {
                private_.append(temp);
            }            else {
                debugs(65, 2, "cc: invalid private= specs near '" << item << "'");
            }
            // to be safe we ignore broken parameters, but always remember the 'private' part.
            setMask(type,true);
        }
        break;

        case HttpHdrCcType::CC_NO_CACHE: {
            String temp;
            if (!p) {
                // On Requests, missing value parameter is expected syntax.
                // On Responses, value parameter is optional.
                setMask(type,true);
                no_cache.clean();
            } else if (/* p &&*/ httpHeaderParseQuotedString(p, (ilen-nlen-1), &temp)) {
                // On Requests, a value parameter is invalid syntax.
                // XXX: identify when parsing request header and dump err message here.
                setMask(type,true);
                no_cache.append(temp);
            } else {
                debugs(65, 2, "cc: invalid no-cache= specs near '" << item << "'");
            }
        }
        break;

        case HttpHdrCcType::CC_PUBLIC:
            Public(true);
            break;
        case HttpHdrCcType::CC_NO_STORE:
            noStore(true);
            break;
        case HttpHdrCcType::CC_NO_TRANSFORM:
            noTransform(true);
            break;
        case HttpHdrCcType::CC_MUST_REVALIDATE:
            mustRevalidate(true);
            break;
        case HttpHdrCcType::CC_PROXY_REVALIDATE:
            proxyRevalidate(true);
            break;
        case HttpHdrCcType::CC_ONLY_IF_CACHED:
            onlyIfCached(true);
            break;
        case HttpHdrCcType::CC_IMMUTABLE:
            Immutable(true);
            break;

        case HttpHdrCcType::CC_OTHER:
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
HttpHdrCc::packInto(Packable * p) const
{
    // optimization: if the mask is empty do nothing
    if (mask==0)
        return;

    HttpHdrCcType flag;
    int pcount = 0;
    assert(p);

    for (flag = HttpHdrCcType::CC_PUBLIC; flag < HttpHdrCcType::CC_ENUM_END; ++flag) {
        if (isSet(flag) && flag != HttpHdrCcType::CC_OTHER) {

            /* print option name for all options */
            p->appendf((pcount ? ", %s": "%s") , CcAttrs[flag].name);

            /* for all options having values, "=value" after the name */
            switch (flag) {
            case HttpHdrCcType::CC_PUBLIC:
                break;
            case HttpHdrCcType::CC_PRIVATE:
                if (Private().size())
                    p->appendf("=\"" SQUIDSTRINGPH "\"", SQUIDSTRINGPRINT(Private()));
                break;

            case HttpHdrCcType::CC_NO_CACHE:
                if (noCache().size())
                    p->appendf("=\"" SQUIDSTRINGPH "\"", SQUIDSTRINGPRINT(noCache()));
                break;
            case HttpHdrCcType::CC_NO_STORE:
                break;
            case HttpHdrCcType::CC_NO_TRANSFORM:
                break;
            case HttpHdrCcType::CC_MUST_REVALIDATE:
                break;
            case HttpHdrCcType::CC_PROXY_REVALIDATE:
                break;
            case HttpHdrCcType::CC_MAX_AGE:
                p->appendf("=%d", maxAge());
                break;
            case HttpHdrCcType::CC_S_MAXAGE:
                p->appendf("=%d", sMaxAge());
                break;
            case HttpHdrCcType::CC_MAX_STALE:
                /* max-stale's value is optional.
                  If we didn't receive it, don't send it */
                if (maxStale()!=MAX_STALE_ANY)
                    p->appendf("=%d", maxStale());
                break;
            case HttpHdrCcType::CC_MIN_FRESH:
                p->appendf("=%d", minFresh());
                break;
            case HttpHdrCcType::CC_ONLY_IF_CACHED:
                break;
            case HttpHdrCcType::CC_STALE_IF_ERROR:
                p->appendf("=%d", staleIfError());
                break;
            case HttpHdrCcType::CC_IMMUTABLE:
                break;
            case HttpHdrCcType::CC_OTHER:
            case HttpHdrCcType::CC_ENUM_END:
                // done below after the loop
                break;
            }

            ++pcount;
        }
    }

    if (other.size() != 0)
        p->appendf((pcount ? ", " SQUIDSTRINGPH : SQUIDSTRINGPH), SQUIDSTRINGPRINT(other));
}

void
httpHdrCcUpdateStats(const HttpHdrCc * cc, StatHist * hist)
{
    assert(cc);

    for (HttpHdrCcType c = HttpHdrCcType::CC_PUBLIC; c < HttpHdrCcType::CC_ENUM_END; ++c)
        if (cc->isSet(c))
            hist->count(c);
}

void
httpHdrCcStatDumper(StoreEntry * sentry, int, double val, double, int count)
{
    extern const HttpHeaderStat *dump_stat; /* argh! */
    const int id = static_cast<int>(val);
    const bool valid_id = id >= 0 && id < static_cast<int>(HttpHdrCcType::CC_ENUM_END);
    const char *name = valid_id ? CcAttrs[id].name : "INVALID";

    if (count || valid_id)
        storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
                          id, name, count, xdiv(count, dump_stat->ccParsedCount));
}

std::ostream &
operator<< (std::ostream &s, HttpHdrCcType c)
{
    const unsigned char ic = static_cast<int>(c);
    if (c < HttpHdrCcType::CC_ENUM_END)
        s << CcAttrs[ic].name << '[' << ic << ']' ;
    else
        s << "*invalid hdrcc* [" << ic << ']';
    return s;
}

#if !_USE_INLINE_
#include "HttpHdrCc.cci"
#endif

