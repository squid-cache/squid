/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 56    HTTP Message Body */

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
    mb = mb_;       /* absorb */
}

void
HttpBody::packInto(Packable * p) const
{
    assert(p);

    if (mb->contentSize())
        p->append(mb->content(), mb->contentSize());
}

