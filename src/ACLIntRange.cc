/*
 * $Id: ACLIntRange.cc,v 1.6 2005/05/08 23:31:06 hno Exp $
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
#include "ACLIntRange.h"

/* explicit instantiation required for some systems */

template cbdata_type List<Range<int> >
::CBDATA_List;

void
ACLIntRange::parse()
{
    char *t = NULL;

    while ((t = strtokFile())) {
        RangeType temp (0,0);
        temp.start = atoi(t);
        t = strchr(t, '-');

        if (t && *(++t))
            temp.end = atoi(t) + 1;
        else
            temp.end = temp.start+1;

        ranges.push_back(temp);
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
    ListIterator<RangeType> iter(ranges);

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
    ListIterator<RangeType> iter(ranges);

    while (!iter.end()) {
        const RangeType & element = iter.next();

        if (element.size() == 1)
            snprintf(buf, sizeof(buf), "%d", element.start);
        else
            snprintf(buf, sizeof(buf), "%d-%d", element.start, element.end);

        wordlistAdd(&W, buf);
    }

    return W;
}

