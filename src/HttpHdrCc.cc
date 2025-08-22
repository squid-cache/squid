/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 65    HTTP Cache Control Header */

#include "squid.h"
#include "base/EnumIterator.h"
#include "base/LookupTable.h"
#include "http/HeaderTools.h"
#include "HttpHdrCc.h"
#include "HttpHeader.h"
#include "HttpHeaderStat.h"
#include "sbuf/SBuf.h"
#include "SquidMath.h"
#include "StatHist.h"
#include "Store.h"
#include "StrList.h"
#include "util.h"

#include <map>
#include <vector>
#include <optional>
#include <ostream>

constexpr LookupTable<HttpHdrCcType>::Record attrsList[] = {
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

constexpr const auto &
CcAttrs() {
    // TODO: Move these compile-time checks into LookupTable
    ConstexprForEnum<HttpHdrCcType::CC_PUBLIC, HttpHdrCcType::CC_ENUM_END>([](const auto ev) {
        const auto idx = static_cast<std::underlying_type<HttpHdrCcType>::type>(ev);
        // invariant: each row has a name except the last one
        static_assert(!attrsList[idx].name == (ev == HttpHdrCcType::CC_ENUM_END));
        // invariant: row[idx].id == idx
        static_assert(attrsList[idx].id == ev);
    });
    return attrsList;
}

static auto
ccTypeByName(const SBuf &name) {
    const static auto table = new LookupTable<HttpHdrCcType>(HttpHdrCcType::CC_OTHER, CcAttrs());
    return table->lookup(name);
}

/// Safely converts an integer into a Cache-Control directive name.
/// \returns std::nullopt if the given integer is not a valid index of a named attrsList entry
template <typename RawId>
static std::optional<const char *>
ccNameByType(const RawId rawId)
{
    // TODO: Store a by-ID index in (and move this functionality into) LookupTable.
    if (!Less(rawId, 0) && Less(rawId, int(HttpHdrCcType::CC_ENUM_END))) {
        const auto idx = static_cast<std::underlying_type<HttpHdrCcType>::type>(rawId);
        return CcAttrs()[idx].name;
    }
    return std::nullopt;
}

/// used to walk a table of http_header_cc_type structs
static HttpHdrCcType &
operator++ (HttpHdrCcType &aHeader)
{
    int tmp = (int)aHeader;
    aHeader = (HttpHdrCcType)(++tmp);
    return aHeader;
}

void
HttpHdrCc::clear()
{
    *this=HttpHdrCc();
}

/// set a data member to a new value, and set the corresponding mask-bit.
/// if setting is false, then the mask-bit is cleared.
void
HttpHdrCc::setValue(int32_t &value, int32_t new_value, HttpHdrCcType hdr, bool setting)
{
    if (setting) {
        if (new_value < 0) {
            debugs(65, 3, "rejecting negative-value Cache-Control directive " << hdr
                   << " value " << new_value);
            return;
        }
    } else {
        new_value = -1; //rely on the convention that "unknown" is -1
    }

    value = new_value;
    setMask(hdr,setting);
}

bool
HttpHdrCc::parse(const String & str)
{
    const char *item;
    const char *p;      /* '=' parameter */
    const char *pos = nullptr;
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
        const auto type = ccTypeByName(SBuf(item, nlen));

        // ignore known duplicate directives
        if (isSet(type)) {
            if (type != HttpHdrCcType::CC_OTHER) {
                debugs(65, 2, "hdr cc: ignoring duplicate cache-directive: near '" << item << "' in '" << str << "'");
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
            p->appendf((pcount ? ", %s": "%s"), *ccNameByType(flag));

            /* for all options having values, "=value" after the name */
            switch (flag) {
            case HttpHdrCcType::CC_PUBLIC:
                break;
            case HttpHdrCcType::CC_PRIVATE:
                if (private_.size())
                    p->appendf("=\"" SQUIDSTRINGPH "\"", SQUIDSTRINGPRINT(private_));
                break;

            case HttpHdrCcType::CC_NO_CACHE:
                if (no_cache.size())
                    p->appendf("=\"" SQUIDSTRINGPH "\"", SQUIDSTRINGPRINT(no_cache));
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
                p->appendf("=%d", max_age);
                break;
            case HttpHdrCcType::CC_S_MAXAGE:
                p->appendf("=%d", s_maxage);
                break;
            case HttpHdrCcType::CC_MAX_STALE:
                /* max-stale's value is optional.
                  If we didn't receive it, don't send it */
                if (max_stale != MAX_STALE_ANY)
                    p->appendf("=%d", max_stale);
                break;
            case HttpHdrCcType::CC_MIN_FRESH:
                p->appendf("=%d", min_fresh);
                break;
            case HttpHdrCcType::CC_ONLY_IF_CACHED:
                break;
            case HttpHdrCcType::CC_STALE_IF_ERROR:
                p->appendf("=%d", stale_if_error);
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
    const auto name = ccNameByType(id);
    if (count || name)
        storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
                          id, name.value_or("INVALID"), count, xdiv(count, dump_stat->ccParsedCount));
}

std::ostream &
operator<< (std::ostream &s, HttpHdrCcType c)
{
    s << ccNameByType(c).value_or("INVALID") << '[' << static_cast<int>(c) << ']';
    return s;
}

