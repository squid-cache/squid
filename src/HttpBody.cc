


/*
 * $Id: HttpBody.cc,v 1.13 1998/07/20 17:19:01 wessels Exp $
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *  
 */

#include "squid.h"


void
httpBodyInit(HttpBody * body)
{
    body->mb = MemBufNull;
}

void
httpBodyClean(HttpBody * body)
{
    assert(body);
    if (!memBufIsNull(&body->mb))
	memBufClean(&body->mb);
}

/* set body by absorbing mb */
void
httpBodySet(HttpBody * body, MemBuf *mb)
{
    assert(body);
    assert(memBufIsNull(&body->mb));
    body->mb = *mb; /* absorb */
}

void
httpBodyPackInto(const HttpBody * body, Packer * p)
{
    assert(body && p);
    if (body->mb.size)
	packerAppend(p, body->mb.buf, body->mb.size);
}

#if UNUSED_CODE
const char *
httpBodyPtr(const HttpBody * body)
{
    return body->mb.buf ? body->mb.buf : "";
}
#endif
