
/*
 * $Id: StoreMetaUnpacker.cc,v 1.3 2006/05/20 13:15:14 hno Exp $
 *
 * DEBUG: section 20    Storage Manager Swapfile Unpacker
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
 */

#include "squid.h"
#include "StoreMetaUnpacker.h"
#include "StoreMeta.h"

off_t const StoreMetaUnpacker::MinimumBufferLength = sizeof(char) + sizeof(int);

bool
StoreMetaUnpacker::isBufferSane()
{
    if (buf[0] != (char) STORE_META_OK)
        return false;

    /*
     * sanity check on 'buflen' value.  It should be at least big
     * enough to hold one type and one length.
     */
    getBufferLength();

    if (*hdr_len < MinimumBufferLength)
        return false;

    if (*hdr_len > buflen)
        return false;

    return true;
}

void
StoreMetaUnpacker::getBufferLength()
{
    xmemcpy(hdr_len, &buf[1], sizeof(int));
}

StoreMetaUnpacker::StoreMetaUnpacker (char const *aBuffer, ssize_t aLen, int *anInt) : buf (aBuffer), buflen(aLen), hdr_len(anInt), position(1 + sizeof(int))
{
    assert (aBuffer != NULL);
}

void
StoreMetaUnpacker::getType()
{
    type = buf[position++];
}

void
StoreMetaUnpacker::getLength()
{
    xmemcpy(&length, &buf[position], sizeof(int));
    position += sizeof(int);
}

bool
StoreMetaUnpacker::doOneEntry()
{
    getType();
    getLength();

    if (position + length > *hdr_len) {
        debug(20, 0) ("storeSwapMetaUnpack: overflow!\n");
        debug(20, 0) ("\ttype=%d, length=%d, *hdr_len=%d, offset=%d\n",
                      type, length, *hdr_len, (int) position);
        return false;
    }

    StoreMeta *newNode = StoreMeta::Factory(type, length, &buf[position]);

    if (!newNode)
        return false;

    tail = StoreMeta::Add (tail, newNode);

    position += length;

    return true;
}

bool
StoreMetaUnpacker::moreToProcess() const
{
    return *hdr_len - position - MinimumBufferLength >= 0;
}

StoreMeta *
StoreMetaUnpacker::createStoreMeta ()
{
    tlv *TLV = NULL;
    tail = &TLV;
    assert(hdr_len != NULL);

    if (!isBufferSane())
        return NULL;

    getBufferLength();

    assert (position == 1 + sizeof(int));

    while (moreToProcess()) {
        if (!doOneEntry())
            break;
    }

    return TLV;
}
