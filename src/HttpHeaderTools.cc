/*
 * $Id: HttpHeaderTools.cc,v 1.1 1998/03/05 00:01:08 rousskov Exp $
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

void
httpHeaderInitAttrTable(field_attrs_t * table, int count)
{
    int i;
    assert(table);
    assert(count > 1);		/* to protect from buggy "countof" implementations */

    /* reorder so that .id becomes an index */
    for (i = 0; i < count;) {
	const int id = table[i].id;
	assert(id >= 0 && id < count);	/* sanity check */
	assert(id >= i);	/* entries prior to i have been indexed already */
	if (id != i) {		/* out of order */
	    const field_attrs_t fa = table[id];
	    assert(fa.id != id);	/* avoid endless loops */
	    table[id] = table[i];	/* swap */
	    table[i] = fa;
	} else
	    i++;		/* make progress */
    }

    /* calculate name lengths and init stats */
    for (i = 0; i < count; ++i) {
	assert(table[i].name);
	table[i].name_len = strlen(table[i].name);
	debug(55, 5) ("hdr table entry[%d]: %s (%d)\n", i, table[i].name, table[i].name_len);
	assert(table[i].name_len);
	/* init stats */
	memset(&table[i].stat, 0, sizeof(table[i].stat));
    }
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
httpHeaderIdByName(const char *name, int name_len, const field_attrs_t * attrs, int end, int mask)
{
    int i;
    for (i = 0; i < end; ++i) {
	if (mask < 0 || EBIT_TEST(mask, i)) {
	    if (name_len >= 0 && name_len != attrs[i].name_len)
		continue;
	    if (!strncasecmp(name, attrs[i].name,
		    name_len < 0 ? attrs[i].name_len + 1 : name_len))
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
