
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
#include "Store.h"
#include "HttpHeader.h"
#include "HttpHdrCc.h"

#if HAVE_MAP
#include <map>
#endif

/** dumb char* /length combo for quick lookups.
 *
 * Data is not copied.
 * Validity of the pointed-to storage is responsibility of the caller.
 * */
class strblob {
    public:
    strblob(const char * ptr, size_t len): thePtr(ptr), theLen(len) {}
    bool operator==(strblob &s) const { return theLen==s.theLen && 0==strncmp(thePtr,s.thePtr,theLen); }
    bool operator< ( const strblob &s2) const { return strncmp(thePtr,s2.thePtr,theLen) < 0; }

    private:
    const char *thePtr;
    size_t theLen;
};

/* this table is used for parsing cache control header and statistics */
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
typedef std::map<const strblob,http_hdr_cc_type> CcNameToIdMap_t;
static CcNameToIdMap_t CcNameToIdMap;

/// iterate over a table of http_header_cc_type structs
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
    for (int32_t i = 0;i < CC_ENUM_END; ++i) {
        const HttpHeaderCcFields *f=&CcAttrs[i];
        assert(i == f->id); /* verify assumption: the id is the key into the array */
        const strblob k(f->name,strlen(f->name));
        CcNameToIdMap[k]=f->id;
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
    HttpHdrCc *cc=this; //TODO: remove after review

    /* iterate through comma separated list */

    while (strListGetItem(&str, ',', &item, &ilen, &pos)) {
        /* isolate directive name */

        if ((p = (const char *)memchr(item, '=', ilen)) && (p - item < ilen))
            nlen = p++ - item;
        else
            nlen = ilen;

        /* find type */
        const strblob tmpstr(item,nlen);
        const CcNameToIdMap_t::iterator i=CcNameToIdMap.find(tmpstr);
        if (i==CcNameToIdMap.end())
            type=CC_OTHER;
        else
            type=i->second;

        // ignore known duplicate directives
        if (EBIT_TEST(cc->mask, type)) {
            if (type != CC_OTHER) {
                debugs(65, 2, "hdr cc: ignoring duplicate cache-directive: near '" << item << "' in '" << str << "'");
                ++CcAttrs[type].stat.repCount;
                continue;
            }
        } else {
            EBIT_SET(cc->mask, type);
        }

        /* post-processing special cases */
        switch (type) {

        case CC_MAX_AGE:
            int32_t ma;
            if (!p || !httpHeaderParseInt(p, &ma)) {
                debugs(65, 2, "cc: invalid max-age specs near '" << item << "'");
                cc->setMaxAge(MAX_AGE_UNSET);
            } else {
                cc->setMaxAge(ma);
            }

            break;

        case CC_S_MAXAGE:

            if (!p || !httpHeaderParseInt(p, &cc->s_maxage)) {
                debugs(65, 2, "cc: invalid s-maxage specs near '" << item << "'");
                cc->setSMaxAge(S_MAXAGE_UNSET);
            }

            break;

        case CC_MAX_STALE:

            if (!p || !httpHeaderParseInt(p, &cc->max_stale)) {
                debugs(65, 2, "cc: max-stale directive is valid without value");
                cc->setMaxStale(MAX_STALE_ALWAYS);
            }

            break;

        case CC_MIN_FRESH:

            if (!p || !httpHeaderParseInt(p, &cc->min_fresh)) {
                debugs(65, 2, "cc: invalid min-fresh specs near '" << item << "'");
                cc->min_fresh = -1;
                EBIT_CLR(cc->mask, type);
            }

            break;

        case CC_STALE_IF_ERROR:
            if (!p || !httpHeaderParseInt(p, &cc->stale_if_error)) {
                debugs(65, 2, "cc: invalid stale-if-error specs near '" << item << "'");
                cc->stale_if_error = -1;
                EBIT_CLR(cc->mask, type);
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

    return (cc->mask != 0);
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
            packerPrintf(p, (pcount ? ", %s": "%s") , CcAttrs[flag].name);

            /* handle options with values */

            if (flag == CC_MAX_AGE)
                packerPrintf(p, "=%d", (int) cc->getMaxAge());

            if (flag == CC_S_MAXAGE)
                packerPrintf(p, "=%d", (int) cc->getSMaxAge());

            if (flag == CC_MAX_STALE && cc->getMaxStale() >= 0)
                packerPrintf(p, "=%d", (int) cc->getMaxStale());

            if (flag == CC_MIN_FRESH)
                packerPrintf(p, "=%d", (int) cc->min_fresh);

            ++pcount;
        }
    }

    if (cc->other.size() != 0)
        packerPrintf(p, (pcount ? ", " SQUIDSTRINGPH : SQUIDSTRINGPH),
                     SQUIDSTRINGPRINT(cc->other));
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
    const char *name = valid_id ? CcAttrs[id].name : "INVALID";

    if (count || valid_id)
        storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
                          id, name, count, xdiv(count, dump_stat->ccParsedCount));
}

void
HttpHdrCc::setMaxAge(int max_age_)
{

    if (max_age_ >= 0) {
        EBIT_SET(mask, CC_MAX_AGE);
        max_age = max_age_;
    } else {
        EBIT_CLR(mask, CC_MAX_AGE);
        max_age=MAX_AGE_UNSET;
    }
}

int32_t HttpHdrCc::getMaxAge() const
{
    return max_age;
}

void HttpHdrCc::setSMaxAge(int32_t s_maxage)
{
	if (s_maxage >= 0) {
		EBIT_SET(mask, CC_S_MAXAGE);
		this->s_maxage=s_maxage;
	} else {
		EBIT_CLR(mask, CC_S_MAXAGE);
		this->s_maxage=S_MAXAGE_UNSET;
	}
}

int32_t HttpHdrCc::getSMaxAge() const
{
	return s_maxage;
}

void HttpHdrCc::setMaxStale(int32_t max_stale)
{
	if (max_stale>=0 || max_stale==MAX_STALE_ALWAYS) {
		EBIT_SET(mask,CC_MAX_STALE);
		this->max_stale=max_stale;
	} else {
		EBIT_CLR(mask, CC_MAX_STALE);
		this->max_stale=MAX_STALE_UNSET;
	}
}
int32_t HttpHdrCc::getMaxStale() const
{
	return max_stale;
}
