/*
 * $Id: ACLIntRange.cc,v 1.1 2003/02/25 12:16:55 robertc Exp $
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

void
ACLIntRange::parse()
{
    RangeType **Tail;
    RangeType *q = NULL;
    char *t = NULL;

    for (Tail = &ranges; *Tail; Tail = &((*Tail)->next))

        ;
    while ((t = strtokFile())) {
        Range<int> temp (0,0);
        temp.start = atoi(t);
        t = strchr(t, '-');

        if (t && *(++t))
            temp.end = atoi(t) + 1;
        else
            temp.end = temp.start+1;

        q = new RangeType (temp);

        *(Tail) = q;

        Tail = &q->next;
    }
}

bool
ACLIntRange::match(int i)
{
    Range<int> const toFind (i, i+1);
    RangeType *prev;
    RangeType *data = ranges;
    prev = NULL;

    while (data) {
        Range<int> result = data->element.intersection (toFind);

        if (result.size()) {
            /* matched */

            if (prev != NULL) {
                /* shift the element just found to the second position
                 * in the list */
                prev->next = data->next;
                data->next = ranges->next;
                ranges->next = data;
            }

            return true;
        }

        prev = data;
        data = data->next;
    }

    return false;
}

void
ACLIntRange::deleteSelf() const
{
    delete this;
}

ACLData<int> *
ACLIntRange::clone() const
{
    if (ranges)
        fatal("ACLIntRange::clone: attempt to clone used ACL");

    return new ACLIntRange (*this);
}

ACLIntRange::~ACLIntRange ()
{
    if (ranges)
        ranges->deleteSelf();
}

wordlist *
ACLIntRange::dump ()
{
    wordlist *W = NULL;
    char buf[32];
    RangeType *data = ranges;

    while (data != NULL) {
        if (data->element.size() == 1)
            snprintf(buf, sizeof(buf), "%d", data->element.start);
        else
            snprintf(buf, sizeof(buf), "%d-%d", data->element.start, data->element.end);

        wordlistAdd(&W, buf);

        data = data->next;
    }

    return W;
}

