
/*
 * $Id: HttpHdrCc.cc,v 1.1 1998/03/05 00:01:07 rousskov Exp $
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

/* this table is used for parsing server cache control header */
static field_attrs_t CcAttrs[CC_ENUM_END] =
{
    {"public", CC_PUBLIC},
    {"private", CC_PRIVATE},
    {"no-cache", CC_NO_CACHE},
    {"no-store", CC_NO_STORE},
    {"no-transform", CC_NO_TRANSFORM},
    {"must-revalidate", CC_MUST_REVALIDATE},
    {"proxy-revalidate", CC_PROXY_REVALIDATE},
    {"max-age", CC_MAX_AGE}
};


/* counters */
static int CcPasredCount = 0;


/* module initialization */

void
httpHdrCcInitModule()
{
    httpHeaderInitAttrTable((field_attrs_t *) CcAttrs, CC_ENUM_END);
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
httpHdrCcParseCreate(const char *str)
{
    HttpHdrCc *cc = httpHdrCcCreate();
    httpHdrCcParseInit(cc, str);
    return cc;
}

/* parses a 0-terminating string and inits cc */
void
httpHdrCcParseInit(HttpHdrCc * cc, const char *str)
{
    const char *item;
    const char *p;		/* '=' parameter */
    const char *pos = NULL;
    int type;
    int ilen;
    assert(cc && str);

    CcPasredCount++;
    /* iterate through comma separated list */
    while (strListGetItem(str, ',', &item, &ilen, &pos)) {
	/* strip '=' statements @?@ */
	if ((p = strchr(item, '=')) && (p - item < ilen))
	    ilen = p++ - item;
	/* find type */
	type = httpHeaderIdByName(item, ilen,
	    CcAttrs, CC_ENUM_END, -1);
	if (type < 0) {
	    debug(55, 0) ("hdr cc: unknown cache-directive: near '%s' in '%s'\n", item, str);
	    continue;
	}
	if (EBIT_TEST(cc->mask, type)) {
	    debug(55, 0) ("hdr cc: ignoring duplicate cache-directive: near '%s' in '%s'\n", item, str);
	    CcAttrs[type].stat.repCount++;
	    continue;
	}
	/* update mask */
	EBIT_SET(cc->mask, type);
	/* post-processing special cases */
	switch (type) {
	case CC_MAX_AGE:
	    if (p)
		cc->max_age = (time_t) atoi(p);
	    if (cc->max_age < 0) {
		debug(55, 0) ("cc: invalid max-age specs near '%s'\n", item);
		cc->max_age = -1;
		EBIT_CLR(cc->mask, type);
	    }
	    break;
	default:
	    /* note that we ignore most of '=' specs @?@ */
	    break;
	}
    }
    return;
}

void
httpHdrCcDestroy(HttpHdrCc * cc)
{
    assert(cc);
    memFree(MEM_HTTP_HDR_CC, cc);
}

HttpHdrCc *
httpHdrCcDup(HttpHdrCc * cc)
{
    HttpHdrCc *dup;
    assert(cc);
    dup = httpHdrCcCreate();
    dup->mask = cc->mask;
    dup->max_age = cc->max_age;
    return dup;
}

void
httpHdrCcPackValueInto(HttpHdrCc * cc, Packer * p)
{
    http_hdr_cc_type flag;
    int pcount = 0;
    assert(cc && p);
    if (cc->max_age >= 0) {
	packerPrintf(p, "max-age=%d", cc->max_age);
	pcount++;
    }
    for (flag = 0; flag < CC_ENUM_END; flag++) {
	if (EBIT_TEST(cc->mask, flag)) {
	    packerPrintf(p, pcount ? ", %s" : "%s", CcAttrs[flag].name);
	    pcount++;
	}
    }
}

void
httpHdrCcJoinWith(HttpHdrCc * cc, HttpHdrCc * new_cc)
{
    assert(cc && new_cc);
    if (cc->max_age < 0)
	cc->max_age = new_cc->max_age;
    cc->mask |= new_cc->mask;
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
    const char *name = valid_id ? CcAttrs[id].name : "INVALID";
    if (count || valid_id)
	storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
	    id, name, count, xdiv(count, CcPasredCount));
}
