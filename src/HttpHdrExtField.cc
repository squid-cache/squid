
/*
 * $Id: HttpHdrExtField.cc,v 1.11 2003/02/21 22:50:05 robertc Exp $
 *
 * DEBUG: section 69    HTTP Header: Extension Field
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
    while (value_start < field_end && xisspace(*value_start))
        value_start++;

    return httpHdrExtFieldDoCreate(
               field_start, name_end - field_start,
               value_start, field_end - value_start);
}

void
httpHdrExtFieldDestroy(HttpHdrExtField * f)
{
    assert(f);
    f->name.clean();
    f->value.clean();
    xfree(f);
}

HttpHdrExtField *
httpHdrExtFieldDup(HttpHdrExtField * f)
{
    assert(f);
    return httpHdrExtFieldDoCreate(
               f->name.buf(), f->name.size(),
               f->value.buf(), f->value.size());
}
