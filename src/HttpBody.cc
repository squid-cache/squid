/*
 * $Id: HttpBody.cc,v 1.5 1998/02/26 18:00:30 wessels Exp $
 *
 * DEBUG: section 56    HTTP Message Body
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


/* local constants */

/* local routines */


void
httpBodyInit(HttpBody * body)
{
    body->buf = NULL;
    body->size = 0;
    body->freefunc = NULL;
}

void
httpBodyClean(HttpBody * body)
{
    assert(body);
    if (body->buf) {
	assert(body->freefunc);
	(*body->freefunc) (body->buf);
    }
    body->buf = NULL;
    body->size = 0;
}

/* set body, if freefunc is NULL the content will be copied, otherwise not */
void
httpBodySet(HttpBody * body, const char *buf, int size, FREE * freefunc)
{
    assert(body);
    assert(!body->buf);
    assert(buf);
    assert(size);
    assert(buf[size - 1] == '\0');	/* paranoid */
    if (!freefunc) {		/* they want us to make our own copy */
	body->buf = xmalloc(size);
	xmemcpy(body->buf, buf, size);
	freefunc = &xfree;
    }
    body->freefunc = freefunc;
    body->size = size;
}

void
httpBodyPackInto(const HttpBody * body, Packer * p)
{
    assert(body && p);
    /* assume it was a 0-terminating buffer */
    if (body->size)
	packerAppend(p, body->buf, body->size - 1);
}

const char *
httpBodyPtr(const HttpBody * body)
{
    return body->buf ? body->buf : "";
}
