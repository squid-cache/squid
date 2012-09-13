
/*
 * DEBUG: section 56    HTTP Message Body
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
#include "HttpBody.h"
#include "MemBuf.h"

HttpBody::HttpBody() : mb(new MemBuf)
{}

HttpBody::~HttpBody()
{
    delete mb;
}

void
HttpBody::clear()
{
    mb->clean();
}

/* set body by absorbing mb */
void
HttpBody::setMb(MemBuf * mb_)
{
    delete mb;
    /* note: protection against assign-to-self is not needed
     * as MemBuf doesn't have a copy-constructor. If such a constructor
     * is ever added, add such protection here.
     */
    mb = mb_;		/* absorb */
}

void
HttpBody::packInto(Packer * p) const
{
    assert(p);

    if (mb->contentSize())
        packerAppend(p, mb->content(), mb->contentSize());
}
