/*
 * $Id: HttpHeaderTools.cc,v 1.3 1998/03/11 22:18:45 rousskov Exp $
 *
 * DEBUG: section 66    HTTP Header Tools
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

static int httpHeaderStrCmp(const char *h1, const char *h2, int len);


HttpHeaderFieldInfo *
httpHeaderBuildFieldsInfo(const HttpHeaderFieldAttrs *attrs, int count)
{
    int i;
    HttpHeaderFieldInfo *table = NULL;
    assert(attrs && count);

    /* allocate space */
    table = xcalloc(count, sizeof(HttpHeaderFieldInfo));

    for (i = 0; i < count; ++i) {
	const int id = attrs[i].id;
	HttpHeaderFieldInfo *info = table + id;
	/* sanity checks */
	assert(id >= 0 && id < count);
	assert(attrs[i].name);
	assert(info->id == 0 && info->type == 0); /* was not set before */
	/* copy and init fields */
	info->id = id;
	info->type = attrs[i].type;
	stringInit(&info->name, attrs[i].name);
	assert(strLen(info->name));
	/* init stats */
	memset(&info->stat, 0, sizeof(info->stat));
    }
    return table;
}

void
httpHeaderDestroyFieldsInfo(HttpHeaderFieldInfo *table, int count)
{
    int i;
    for (i = 0; i < count; ++i)
	stringClean(&table[i].name);
    xfree(table);
}

/* calculates a bit mask of a given array */
int
httpHeaderCalcMask(const int *enums, int count)
{
    int i;
    int mask = 0;
    assert(enums);
    assert(count < sizeof(int) * 8);	/* check for overflow */

    for (i = 0; i < count; ++i) {
	assert(enums[i] < sizeof(int) * 8);	/* check for overflow again */
	assert(!EBIT_TEST(mask, enums[i]));	/* check for duplicates */
	EBIT_SET(mask, enums[i]);
    }
    return mask;
}


int
httpHeaderIdByName(const char *name, int name_len, const HttpHeaderFieldInfo *info, int end, int mask)
{
    int i;
    for (i = 0; i < end; ++i) {
	if (mask < 0 || EBIT_TEST(mask, i)) {
	    if (name_len >= 0 && name_len != strLen(info[i].name))
		continue;
	    if (!strncasecmp(name, strBuf(info[i].name),
		    name_len < 0 ? strLen(info[i].name) + 1 : name_len))
		return i;
	}
    }
    return -1;
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
strListGetItem(const char *str, char del, const char **item, int *ilen, const char **pos)
{
    size_t len;
    assert(str && item && pos);
    if (*pos)
	if (!**pos)		/* end of string */
	    return 0;
	else
	    (*pos)++;
    else
	*pos = str;

    /* skip leading ws (ltrim) */
    *pos += xcountws(*pos);
    *item = *pos;		/* remember item's start */
    /* find next delimiter */
    *pos = strchr(*item, del);
    if (!*pos)			/* last item */
	*pos = *item + strlen(*item);
    len = *pos - *item;		/* *pos points to del or '\0' */
    /* rtrim */
    while (len > 0 && isspace((*item)[len - 1]))
	len--;
    if (ilen)
	*ilen = len;
    return len > 0;
}

/* handy to printf prefixes of potentially very long buffers */
const char *
getStringPrefix(const char *str)
{
#define SHORT_PREFIX_SIZE 256
    LOCAL_ARRAY(char, buf, SHORT_PREFIX_SIZE);
    xstrncpy(buf, str, SHORT_PREFIX_SIZE);
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
    if (!*value && !isdigit(*start)) {
	debug(66, 2) ("failed to parse an int header field near '%s'\n", start);
            return 0;
    }
    return 1;
}

int
httpHeaderParseSize(const char *start, size_t *value)
{
    int v;
    const int res = httpHeaderParseInt(start, &v);
    assert(value);
    *value = res ? v : 0;
    return res;
}


/*
 * parses a given string then packs compiled headers and compares the result
 * with the original, reports discrepancies
 */
void httpHeaderTestParser(const char *hstr)
{
    static int bug_count = 0;
    int hstr_len;
    int parse_success;
    HttpHeader hdr;
    int pos;
    Packer p;
    MemBuf mb;
    assert(hstr);
    /* do not print too much, kludge */
    if (bug_count > 100 && (lrand48() % bug_count) > 50L)
	return;
    /* skip start line if any */
    if (!strncasecmp(hstr, "HTTP/", 5)) {
	const char *p = strchr(hstr, '\n');
	if (p)
	    hstr = p+1;
    }
    /* skip invalid first line if any */
    if (isspace(*hstr)) {
	const char *p = strchr(hstr, '\n');
	if (p)
	    hstr = p+1;
    }
    hstr_len = strlen(hstr);
    /* skip terminator if any */
    if (strstr(hstr, "\n\r\n"))
	hstr_len -= 2;
    else
    if (strstr(hstr, "\n\n"))
	hstr_len -= 1;
    httpHeaderInit(&hdr);
    /* debugLevels[55] = 8; */
    parse_success = httpHeaderParse(&hdr, hstr, hstr+hstr_len);
    /* debugLevels[55] = 2; */
    if (!parse_success) {
	debug(66, 2) ("TEST: failed to parsed a header: {\n%s}\n", hstr);
	return;
    }
    /* we think that we parsed it, veryfy */
    memBufDefInit(&mb);
    packerToMemInit(&p, &mb);
    httpHeaderPackInto(&hdr, &p);
    if ((pos = abs(httpHeaderStrCmp(hstr, mb.buf, hstr_len)))) {
	bug_count++;
	debug(66, 2) ("TEST: hdr parsing bug (pos: %d near '%s'): expected: {\n%s} got: {\n%s}\n",
	    pos, hstr+pos, hstr, mb.buf);
    }
    httpHeaderClean(&hdr);
    packerClean(&p);
    memBufClean(&mb);
}


/* like strncasecmp but ignores ws characters */ 
static int
httpHeaderStrCmp(const char *h1, const char *h2, int len)
{
    int len1 = 0;
    int len2 = 0;
    assert(h1 && h2);
    /* fast check first */
    if (!strncasecmp(h1, h2, len))
	return 0;
    while (1) {
	const char c1 = toupper(h1[len1 += xcountws(h1 + len1)]);
	const char c2 = toupper(h2[len2 += xcountws(h2 + len2)]);
        if (c1 < c2) return -len1;
        if (c1 > c2) return +len1;
	if (!c1 && !c2)
	    return 0;
        if (c1) len1++;
	if (c2) len2++;
    }
    return 0;
}
