
/*
 * $Id: HttpHdrCc.cc,v 1.10 1998/05/11 18:44:25 rousskov Exp $
 *
 * DEBUG: section 65    HTTP Cache Control Header
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

/* this table is used for parsing cache control header */
static const HttpHeaderFieldAttrs CcAttrs[CC_ENUM_END] =
{
    {"public", CC_PUBLIC},
    {"private", CC_PRIVATE},
    {"no-cache", CC_NO_CACHE},
    {"no-store", CC_NO_STORE},
    {"no-transform", CC_NO_TRANSFORM},
    {"must-revalidate", CC_MUST_REVALIDATE},
    {"proxy-revalidate", CC_PROXY_REVALIDATE},
    {"only-if-cached", CC_ONLY_IF_CACHED},
    {"max-age", CC_MAX_AGE},
    {"Other,", CC_OTHER}	/* ',' will protect from matches */
};
HttpHeaderFieldInfo *CcFieldsInfo = NULL;

/* counters */
static int CcParsedCount = 0;

/* local prototypes */
static int httpHdrCcParseInit(HttpHdrCc * cc, const String *str);


/* module initialization */

void
httpHdrCcInitModule()
{
    CcFieldsInfo = httpHeaderBuildFieldsInfo(CcAttrs, CC_ENUM_END);
}

void
httpHdrCcCleanModule()
{
    httpHeaderDestroyFieldsInfo(CcFieldsInfo, CC_ENUM_END);
    CcFieldsInfo = NULL;
}

/* implementation */

HttpHdrCc *
httpHdrCcCreate()
{
    HttpHdrCc *cc = memAllocate(MEM_HTTP_HDR_CC);
    cc->max_age = -1;
    return cc;
}

/* creates an cc object from a 0-terminating string */
HttpHdrCc *
httpHdrCcParseCreate(const String *str)
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
httpHdrCcParseInit(HttpHdrCc * cc, const String *str)
{
    const char *item;
    const char *p;		/* '=' parameter */
    const char *pos = NULL;
    int type;
    int ilen;
    assert(cc && str);

    CcParsedCount++;
    /* iterate through comma separated list */
    while (strListGetItem(str, ',', &item, &ilen, &pos)) {
	/* strip '=' statements @?@ */
	if ((p = strchr(item, '=')) && (p - item < ilen))
	    ilen = p++ - item;
	/* find type */
	type = httpHeaderIdByName(item, ilen,
	    CcFieldsInfo, CC_ENUM_END);
	if (type < 0) {
	    debug(65, 2) ("hdr cc: unknown cache-directive: near '%s' in '%s'\n", item, strBuf(*str));
	    type = CC_OTHER;
	}
	if (EBIT_TEST(cc->mask, type)) {
	    if (type != CC_OTHER)
		debug(65, 2) ("hdr cc: ignoring duplicate cache-directive: near '%s' in '%s'\n", item, strBuf(*str));
	    CcFieldsInfo[type].stat.repCount++;
	    continue;
	}
	/* update mask */
	EBIT_SET(cc->mask, type);
	/* post-processing special cases */
	switch (type) {
	case CC_MAX_AGE:
	    if (!p || !httpHeaderParseInt(p, &cc->max_age)) {
		debug(65, 2) ("cc: invalid max-age specs near '%s'\n", item);
		cc->max_age = -1;
		EBIT_CLR(cc->mask, type);
	    }
	    break;
	default:
	    /* note that we ignore most of '=' specs */
	    break;
	}
    }
    return cc->mask != 0;
}

void
httpHdrCcDestroy(HttpHdrCc * cc)
{
    assert(cc);
    memFree(MEM_HTTP_HDR_CC, cc);
}

HttpHdrCc *
httpHdrCcDup(const HttpHdrCc * cc)
{
    HttpHdrCc *dup;
    assert(cc);
    dup = httpHdrCcCreate();
    dup->mask = cc->mask;
    dup->max_age = cc->max_age;
    return dup;
}

void
httpHdrCcPackInto(const HttpHdrCc * cc, Packer * p)
{
    http_hdr_cc_type flag;
    int pcount = 0;
    assert(cc && p);
    for (flag = 0; flag < CC_ENUM_END; flag++) {
	if (flag == CC_MAX_AGE && cc->max_age >= 0) {
	    packerPrintf(p, "max-age=%d", (int) cc->max_age);
	    pcount++;
	} else
	if (EBIT_TEST(cc->mask, flag) && flag != CC_OTHER) {
	    packerPrintf(p, (pcount ? ", %s" : "%s"), strBuf(CcFieldsInfo[flag].name));
	    pcount++;
	}
    }
}

void
httpHdrCcJoinWith(HttpHdrCc * cc, const HttpHdrCc * new_cc)
{
    assert(cc && new_cc);
    if (cc->max_age < 0)
	cc->max_age = new_cc->max_age;
    cc->mask |= new_cc->mask;
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

void
httpHdrCcUpdateStats(const HttpHdrCc * cc, StatHist * hist)
{
    http_hdr_cc_type c;
    assert(cc);
    for (c = 0; c < CC_ENUM_END; c++)
	if (EBIT_TEST(cc->mask, c))
	    statHistCount(hist, c);
}

void
httpHdrCcStatDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    const int id = (int) val;
    const int valid_id = id >= 0 && id < CC_ENUM_END;
    const char *name = valid_id ? strBuf(CcFieldsInfo[id].name) : "INVALID";
    if (count || valid_id)
	storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
	    id, name, count, xdiv(count, CcParsedCount));
}
