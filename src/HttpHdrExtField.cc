
/*
 * $Id: HttpHdrExtField.cc,v 1.3 1998/04/06 22:32:06 wessels Exp $
 *
 * DEBUG: section 69    HTTP Header: Extension Field
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

/* local prototypes */
static HttpHdrExtField *httpHdrExtFieldDoCreate(const char *name, int name_len, const char *value, int val_len);


/* implementation */

static HttpHdrExtField *
httpHdrExtFieldDoCreate(const char *name, int name_len,
    const char *value, int value_len)
{
    HttpHdrExtField *f = xcalloc(1, sizeof(HttpHdrExtField));
    stringLimitInit(&f->name, name, name_len);
    stringLimitInit(&f->value, value, value_len);
    return f;
}

HttpHdrExtField *
httpHdrExtFieldCreate(const char *name, const char *value)
{
    return httpHdrExtFieldDoCreate(
	name, strlen(name),
	value, strlen(value));
}

/* parses ext field; returns fresh ext field on success and NULL on failure */
HttpHdrExtField *
httpHdrExtFieldParseCreate(const char *field_start, const char *field_end)
{
    /* note: name_start == field_start */
    const char *name_end = strchr(field_start, ':');
    const char *value_start;
    /* note: value_end == field_end */

    if (!name_end || name_end <= field_start || name_end > field_end)
	return NULL;

    value_start = name_end + 1;	/* skip ':' */
    /* skip white space */
    while (value_start < field_end && isspace(*value_start))
	value_start++;

    /* cut off "; parameter" from Content-Type @?@ why? */
    if (!strncasecmp(field_start, "Content-Type:", 13)) {
	const int l = strcspn(value_start, ";\t ");
	if (l > 0 && value_start + l < field_end)
	    field_end = value_start + l;
    }
    return httpHdrExtFieldDoCreate(
	field_start, name_end - field_start,
	value_start, field_end - value_start);
}

void
httpHdrExtFieldDestroy(HttpHdrExtField * f)
{
    assert(f);
    stringClean(&f->name);
    stringClean(&f->value);
    xfree(f);
}

HttpHdrExtField *
httpHdrExtFieldDup(HttpHdrExtField * f)
{
    assert(f);
    return httpHdrExtFieldDoCreate(
	strBuf(f->name), strLen(f->name),
	strBuf(f->value), strLen(f->value));
}
