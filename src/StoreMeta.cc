
/*
 * $Id: StoreMeta.cc,v 1.3 2003/08/04 22:14:41 robertc Exp $
 *
 * DEBUG: section 20    Storage Manager Swapfile Metadata
 * AUTHOR: Kostas Anagnostakis
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
#include "StoreMeta.h"
#include "Store.h"
#include "MemObject.h"
#include "StoreMetaMD5.h"
#include "StoreMetaURL.h"
#include "StoreMetaSTD.h"
#include "StoreMetaVary.h"

bool
StoreMeta::validType(char type)
{
    /* VOID is reserved, and new types have to be added as classes */

    if (type <= STORE_META_VOID || type >= STORE_META_END) {
        debug(20, 0) ("storeSwapMetaUnpack: bad type (%d)!\n", type);
        return false;
    }

    /* Unused in any current squid code */
    if (type == STORE_META_KEY_URL ||
            type == STORE_META_KEY_SHA ||
            type == STORE_META_HITMETERING ||
            type == STORE_META_VALID) {
        debug (20,0)("Obsolete and unused type (%d) in disk metadata\n", type);
        return false;
    }

    return true;
}

class IntRange
{

public:
    IntRange (int minimum, int maximum) : _min (minimum), _max (maximum)
    {
        if (_min > _max) {
            int temp = _min;
            _min = _max;
            _max = temp;
        }
    }

    bool includes (int anInt) const
    {
        if (anInt < _min || anInt > _max)
            return false;

        return true;
    }

private:
    int _min;
    int _max;
};

const int StoreMeta::MinimumTLVLength = 0;
const int StoreMeta::MaximumTLVLength = 1 << 16;

bool
StoreMeta::validLength(int length) const
{
    if (!IntRange (MinimumTLVLength, MaximumTLVLength).includes(length)) {
        debug(20, 0) ("storeSwapMetaUnpack: insane length (%d)!\n", length);
        return false;
    }

    return true;
}


StoreMeta *
StoreMeta::Factory (char type, size_t len, void const *value)
{
    if (!validType(type))
        return NULL;

    StoreMeta *result;

    switch (type) {

    case STORE_META_KEY:
        result = new StoreMetaMD5;
        break;

    case STORE_META_URL:
        result = new StoreMetaURL;
        break;

    case STORE_META_STD:
        result = new StoreMetaSTD;
        break;

    case STORE_META_VARY_HEADERS:
        result = new StoreMetaVary;
        break;

    default:
        debug (20,0)("Attempt to create unknown concrete StoreMeta\n");
        return NULL;
    }

    if (!result->validLength(len)) {
        delete result;
        return NULL;
    }

    result->length = len;
    result->value = xmalloc(len);
    xmemcpy(result->value, value, len);
    return result;
}

void
StoreMeta::FreeList(StoreMeta **head)
{
    StoreMeta *node;

    while ((node = *head) != NULL) {
        *head = node->next;
        xfree(node->value);
        delete node;
    }
}

StoreMeta **
StoreMeta::Add(StoreMeta **tail, StoreMeta *aNode)
{
    assert (*tail == NULL);
    *tail = aNode;
    return &aNode->next;		/* return new tail pointer */
}

bool
StoreMeta::checkConsistency(StoreEntry *e) const
{
    switch (getType()) {

    case STORE_META_KEY:

    case STORE_META_URL:

    case STORE_META_VARY_HEADERS:
        assert(0);
        break;

    case STORE_META_STD:
        break;

    default:
        debug(20, 1) ("WARNING: got unused STORE_META type %d\n", getType());
        break;
    }

    return true;
}
