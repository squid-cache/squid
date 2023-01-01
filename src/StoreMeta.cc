/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Swapfile Metadata */

#include "squid.h"
#include "base/Range.h"
#include "MemObject.h"
#include "Store.h"
#include "StoreMeta.h"
#include "StoreMetaMD5.h"
#include "StoreMetaObjSize.h"
#include "StoreMetaSTD.h"
#include "StoreMetaSTDLFS.h"
#include "StoreMetaURL.h"
#include "StoreMetaVary.h"

bool
StoreMeta::validType(char type)
{
    /* VOID is reserved, and new types have to be added as classes */
    if (type <= STORE_META_VOID || type >= STORE_META_END + 10) {
        debugs(20, DBG_CRITICAL, "storeSwapMetaUnpack: bad type (" << type << ")!");
        return false;
    }

    /* Not yet implemented */
    if (type >= STORE_META_END ||
            type == STORE_META_STOREURL ||
            type == STORE_META_VARY_ID) {
        debugs(20, 3, "storeSwapMetaUnpack: Not yet implemented (" << type << ") in disk metadata");
        return false;
    }

    /* Unused in any current squid code */
    if (type == STORE_META_KEY_URL ||
            type == STORE_META_KEY_SHA ||
            type == STORE_META_HITMETERING ||
            type == STORE_META_VALID) {
        debugs(20, DBG_CRITICAL, "Obsolete and unused type (" << type << ") in disk metadata");
        return false;
    }

    return true;
}

const int StoreMeta::MinimumTLVLength = 0;
const int StoreMeta::MaximumTLVLength = 1 << 16;

bool
StoreMeta::validLength(int aLength) const
{
    static const Range<int> TlvValidLengths = Range<int>(StoreMeta::MinimumTLVLength, StoreMeta::MaximumTLVLength);
    if (!TlvValidLengths.contains(aLength)) {
        debugs(20, DBG_CRITICAL, MYNAME << ": insane length (" << aLength << ")!");
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

    case STORE_META_STD_LFS:
        result = new StoreMetaSTDLFS;
        break;

    case STORE_META_OBJSIZE:
        result = new StoreMetaObjSize;
        break;

    case STORE_META_VARY_HEADERS:
        result = new StoreMetaVary;
        break;

    default:
        debugs(20, DBG_CRITICAL, "Attempt to create unknown concrete StoreMeta");
        return NULL;
    }

    if (!result->validLength(len)) {
        delete result;
        return NULL;
    }

    result->length = len;
    result->value = xmalloc(len);
    memcpy(result->value, value, len);
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
    return &aNode->next;        /* return new tail pointer */
}

bool
StoreMeta::checkConsistency(StoreEntry *) const
{
    switch (getType()) {

    case STORE_META_KEY:

    case STORE_META_URL:

    case STORE_META_VARY_HEADERS:
        assert(0);
        break;

    case STORE_META_STD:
        break;

    case STORE_META_STD_LFS:
        break;

    case STORE_META_OBJSIZE:
        break;

    default:
        debugs(20, DBG_IMPORTANT, "WARNING: got unused STORE_META type " << getType());
        break;
    }

    return true;
}

StoreMeta::StoreMeta(const StoreMeta &s) :
    length(s.length),
    value(s.value),
    next(s.next)
{}

StoreMeta& StoreMeta::operator=(const StoreMeta &s)
{
    length=s.length;
    value=s.value;
    next=s.next;
    return *this;
}

