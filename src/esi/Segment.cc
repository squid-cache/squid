
/*
 * DEBUG: section 86    ESI processing
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
 ;  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "Debug.h"
#include "esi/Segment.h"
#include "SquidString.h"

CBDATA_TYPE(ESISegment);

/* ESISegment */
void
ESISegmentFreeList (ESISegment::Pointer &head)
{
    while (head.getRaw()) {
        ESISegment::Pointer temp = head;
        head = head->next;
        temp->next = NULL;
    }
}

size_t
ESISegment::space() const
{
    assert (len <= sizeof(buf));
    return sizeof (buf) - len;
}

void
ESISegment::adsorbList (ESISegment::Pointer from)
{
    assert (next.getRaw() == NULL);
    assert (from.getRaw() != NULL);
    /* prevent worst case */
    assert (!(len == 0 && from->len == space() ));
    Pointer copyFrom = from;

    while (copyFrom.getRaw() && space() >= copyFrom->len) {
        assert (append (copyFrom) == copyFrom->len);
        copyFrom = copyFrom->next;
    }

    next = copyFrom;
}

void
ESISegment::ListTransfer (ESISegment::Pointer &from, ESISegment::Pointer &to)
{
    if (!to.getRaw()) {
        to = from;
        from = NULL;
        return;
    }

    ESISegment::Pointer temp = to->tail();
    temp->adsorbList (from);
    from = NULL;
}

size_t
ESISegment::listLength() const
{
    size_t result = 0;
    ESISegment const* temp = this;

    while (temp) {
        result += temp->len;
        temp = temp->next.getRaw();
    }

    return result;
}

char *
ESISegment::listToChar() const
{
    size_t length = listLength();
    char *rv = (char *)xmalloc (length + 1);
    assert (rv);
    rv [length] = '\0';

    ESISegment::Pointer temp = this;
    size_t pos = 0;

    while (temp.getRaw()) {
        memcpy(&rv[pos], temp->buf, temp->len);
        pos += temp->len;
        temp = temp->next;
    }

    return rv;
}

void
ESISegment::listAppend (char const *s, size_t length)
{
    assert (next.getRaw() == NULL);
    ESISegment::Pointer output = this;
    /* copy the string to output */
    size_t pos=0;

    while (pos < length) {
        if (output->space() == 0) {
            assert (output->next.getRaw() == NULL);
            output->next = new ESISegment;
            output = output->next;
        }

        pos += output->append(s + pos, length - pos);
    }
}

void
ESISegment::ListAppend (ESISegment::Pointer &head, char const *s, size_t len)
{
    if (!head.getRaw())
        head = new ESISegment;

    head->tail()->listAppend (s, len);
}

void *
ESISegment::operator new(size_t byteCount)
{
    assert (byteCount == sizeof (ESISegment));
    void *rv;
    CBDATA_INIT_TYPE(ESISegment);
    rv = (void *)cbdataAlloc (ESISegment);
    return rv;
}

void
ESISegment::operator delete (void *address)
{
    cbdataFree (address);
}

/* XXX: if needed, make this iterative */
ESISegment::Pointer
ESISegment::cloneList () const
{
    ESISegment::Pointer result = new ESISegment (*this);
    result->next = next.getRaw() ? next->cloneList() : NULL;
    return result;
}

size_t
ESISegment::append(char const *appendBuffer, size_t appendLength)
{
    size_t toCopy = min(appendLength, space());
    memcpy(&buf[len], appendBuffer, toCopy);
    len += toCopy;
    return toCopy;
}

size_t
ESISegment::append(ESISegment::Pointer from)
{
    return append (from->buf, from->len);
}

ESISegment const *
ESISegment::tail() const
{
    ESISegment const *result = this;

    while (result->next.getRaw())
        result = result->next.getRaw();

    return result;
}

ESISegment *
ESISegment::tail()
{
    ESISegment::Pointer result = this;

    while (result->next.getRaw())
        result = result->next;

    return result.getRaw();
}

ESISegment::ESISegment() : len(0), next(NULL)
{}

ESISegment::ESISegment(ESISegment const &old) : len (0), next(NULL)
{
    append (old.buf, old.len);
}

void
ESISegment::dumpToLog() const
{
    ESISegment::Pointer temp = this;

    while (temp.getRaw()) {
        temp->dumpOne();
        temp = temp->next;
    }
}

void
ESISegment::dumpOne() const
{
    String temp;
    temp.limitInit(buf, len);
    debugs(86, 9, "ESISegment::dumpOne: \"" << temp << "\"");
}
