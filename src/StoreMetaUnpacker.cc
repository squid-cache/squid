/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Swapfile Unpacker */

#include "squid.h"
#include "base/TextException.h"
#include "Debug.h"
#include "defines.h"
#include "StoreMeta.h"
#include "StoreMetaUnpacker.h"

int const StoreMetaUnpacker::MinimumBufferLength = sizeof(char) + sizeof(int);

/// useful for meta stored in pre-initialized (with zeros) db files
bool
StoreMetaUnpacker::isBufferZero()
{
    // We could memcmp the entire buffer, but it is probably safe enough
    // to test a few bytes because if we do not detect a corrupted entry
    // it is not a big deal. Empty entries are not isBufferSane anyway.
    const int depth = 10;
    if (buflen < depth)
        return false; // cannot be sure enough

    for (int i = 0; i < depth; ++i) {
        if (buf[i])
            return false;
    }
    return true;
}

void
StoreMetaUnpacker::checkBuffer()
{
    assert(buf); // paranoid; already checked in the constructor
    if (buf[0] != static_cast<char>(STORE_META_OK))
        throw TexcHere("store entry metadata is corrupted");
    /*
     * sanity check on 'buflen' value.  It should be at least big
     * enough to hold one type and one length.
     */
    getBufferLength();
    if (*hdr_len < MinimumBufferLength)
        throw TexcHere("store entry metadata is too small");
    if (*hdr_len > buflen)
        throw TexcHere("store entry metadata is too big");
}

void
StoreMetaUnpacker::getBufferLength()
{
    memcpy(hdr_len, &buf[1], sizeof(int));
}

StoreMetaUnpacker::StoreMetaUnpacker(char const *aBuffer, ssize_t aLen, int *anInt) :
    buf(aBuffer),
    buflen(aLen),
    hdr_len(anInt),
    position(1 + sizeof(int)),
    type('\0'),
    length(0),
    tail(NULL)
{
    assert(aBuffer != NULL);
}

void
StoreMetaUnpacker::getType()
{
    type = buf[position];
    ++position;
}

void
StoreMetaUnpacker::getLength()
{
    memcpy(&length, &buf[position], sizeof(int));
    position += sizeof(int);
}

bool
StoreMetaUnpacker::doOneEntry()
{
    getType();
    getLength();

    if (position + length > *hdr_len) {
        debugs(20, DBG_CRITICAL, "storeSwapMetaUnpack: overflow!");
        debugs(20, DBG_CRITICAL, "\ttype=" << type << ", length=" << length << ", *hdr_len=" << *hdr_len << ", offset=" << position);
        return false;
    }

    StoreMeta *newNode = StoreMeta::Factory(type, length, &buf[position]);

    if (newNode)
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

    checkBuffer();

    getBufferLength();

    assert (position == 1 + sizeof(int));

    while (moreToProcess()) {
        if (!doOneEntry())
            break;
    }

    if (!TLV)
        throw TexcHere("store entry metadata is empty");

    assert(TLV);
    return TLV;
}

