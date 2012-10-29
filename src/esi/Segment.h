/*
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

#ifndef SQUID_ESISEGMENT_H
#define SQUID_ESISEGMENT_H

/* TODO: Factor the store memory segment management into a reusable code block
 * or perhaps use membuffers here?
 */

#include "base/RefCount.h"
#include "cbdata.h"
#include "defines.h"
#include "SquidString.h"

class ESISegment : public RefCountable
{

public:
    typedef RefCount<ESISegment> Pointer;
    static void ListAppend (Pointer &, char const *, size_t);
    static void ListTransfer (Pointer &from, Pointer &to);
    void *operator new (size_t byteCount);
    void operator delete (void *address);

    ESISegment();
    ESISegment(ESISegment const &);
    ESISegment::Pointer cloneList() const;
    char *listToChar() const;
    void listAppend (char const *s, size_t length);
    void adsorbList (ESISegment::Pointer from);
    size_t space() const;

    char buf[HTTP_REQBUF_SZ];
    size_t len; /* how much data has been pushed into this */
    Pointer next;
    size_t append(char const *, size_t);
    size_t append (Pointer);
    ESISegment const *tail() const;
    ESISegment *tail();
    void dumpToLog() const;

private:
    size_t listLength()const;
    void dumpOne() const;
};

void ESISegmentFreeList (ESISegment::Pointer &head);

#endif /* SQUID_ESISEGMENT_H */
