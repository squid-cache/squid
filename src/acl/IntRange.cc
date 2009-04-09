/*
 * $Id$
 *
 * DEBUG: section 28    Access Control
 * AUTHOR: Robert Collins
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "acl/IntRange.h"
#include "wordlist.h"
#include "Parsing.h"

/* explicit instantiation required for some systems */
/** \cond AUTODOCS-IGNORE */
template cbdata_type CbDataList< Range<int> >::CBDATA_CbDataList;
/** \endcond */

void
ACLIntRange::parse()
{
    char *a;

    while ((a = strtokFile())) {
        char *b = strchr(a, '-');
        unsigned short port1, port2;

        if (b)
            *b++ = '\0';

        port1 = xatos(a);

        if (b)
            port2 = xatos(b);
        else
            port2 = port1;

        if (port2 >= port1) {
            RangeType temp (0,0);
            temp.start = port1;
            temp.end = port2+1;
            ranges.push_back(temp);
        } else {
            debugs(28, 0, "ACLIntRange::parse: Invalid port value");
            self_destruct();
        }
    }
}

bool
ACLIntRange::empty() const
{
    return ranges.empty();
}

bool
ACLIntRange::match(int i)
{
    RangeType const toFind (i, i+1);
    CbDataListIterator<RangeType> iter(ranges);

    while (!iter.end()) {
        const RangeType & element = iter.next();
        RangeType result = element.intersection (toFind);

        if (result.size())
            return true;
    }

    return false;
}

ACLData<int> *
ACLIntRange::clone() const
{
    if (!ranges.empty())
        fatal("ACLIntRange::clone: attempt to clone used ACL");

    return new ACLIntRange (*this);
}

ACLIntRange::~ACLIntRange ()
{}

wordlist *
ACLIntRange::dump ()
{
    wordlist *W = NULL;
    char buf[32];
    CbDataListIterator<RangeType> iter(ranges);

    while (!iter.end()) {
        const RangeType & element = iter.next();

        if (element.size() == 1)
            snprintf(buf, sizeof(buf), "%d", element.start);
        else
            snprintf(buf, sizeof(buf), "%d-%d", element.start, element.end-1);

        wordlistAdd(&W, buf);
    }

    return W;
}

