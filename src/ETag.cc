
/*
 * $Id: ETag.cc,v 1.4 1998/07/22 20:36:41 wessels Exp $
 *
 * DEBUG: section 7?    HTTP ETag
 * AUTHOR: Alex Rousskov
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  Duane Wessels and the University of California San Diego.  Please
 *  see the COPYRIGHT file for full details.  Squid incorporates
 *  software developed and/or copyrighted by other sources.  Please see
 *  the CREDITS file for full details.
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

/*
 * Note: ETag is not an http "field" like, for example HttpHdrRange. ETag is a
 * field-value that maybe used in many http fields.
 */

/* parses a string as weak or strong entity-tag; returns true on success */
/* note: we do not duplicate "str"! */
int
etagParseInit(ETag * etag, const char *str)
{
    int len;
    assert(etag && str);
    etag->str = NULL;
    etag->weak = !strncmp(str, "W/", 2);
    if (etag->weak)
	str += 2;
    /* check format (quoted-string) */
    len = strlen(str);
    if (len >= 2 && str[0] == '"' && str[len - 1] == '"')
	etag->str = str;
    return etag->str != NULL;
}

/* returns true if etags are equal */
int
etagIsEqual(const ETag * tag1, const ETag * tag2)
{
    assert(tag1 && tag2);
    assert(!tag1->weak && !tag2->weak);		/* weak comparison not implemented yet */
    return !strcmp(tag1->str, tag2->str);
}
