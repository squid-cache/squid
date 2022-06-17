/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Raw.h"
#include "base/TextException.h"
#include "debug/Stream.h"
#include "sbuf/Stream.h"
#include "store/SwapMetaView.h"

#include <iostream>

namespace Store {

/// properly reports or rejects a problematic raw swap meta field type
static void
HandleBadRawType(const RawSwapMetaType type)
{
    if (ReservedSwapMetaType(type)) {
        debugs(20, 3, "ignoring swap meta field with a reserved type: " << int(type));
        return;
    }

    if (DeprecatedSwapMetaType(type)) {
        debugs(20, DBG_CRITICAL, "ERROR: Ignoring swap meta field with a deprecated type: " << int(type));
        return;
    }

    // TODO: Instead of assuming that all future swap meta types can be ignored
    // (and some should be reported at level-0/1), future-proof this code by
    // using a type bit to define whether to silently ignore a swap meta field
    // with that type (or even the whole Store entry with that field).

    const auto typeValuesWeMightAdd = 10;
    // compute "type > RawSwapMetaTypeTop() + typeValuesWeMightAdd" w/o overflow
    if (type >= typeValuesWeMightAdd && type - typeValuesWeMightAdd > RawSwapMetaTypeTop()) {
        debugs(20, DBG_CRITICAL, "ERROR: Malformed cache storage; ignoring swap meta field with an unexpected type: " << int(type));
        return;
    }

    if (type > RawSwapMetaTypeTop()) {
        debugs(20, 3, "ignoring swap meta field with a presumed future type: " << int(type));
        return;
    }

    Assure(type <= RawSwapMetaTypeBottom);
    debugs(20, DBG_CRITICAL, "ERROR: Malformed cache storage; ignoring swap meta field with an invalid type: " << int(type));
}

/// a helper function to safely copy raw end-bounded serialized input into the
/// given item and advance that input to the next item
template <typename T>
static void
Extract(T &item, const char * &input, const void *end)
{
    if (input + sizeof(item) > end)
        throw TextException("truncated swap meta field", Here());
    memcpy(&item, input, sizeof(item));
    input += sizeof(item);
}

} // namespace Store

Store::SwapMetaView::SwapMetaView(const void * const begin, const void * const end)
{
    auto input = static_cast<const char *>(begin);

    Extract(rawType, input, end);
    if (HonoredSwapMetaType(rawType))
        type = static_cast<SwapMetaType>(rawType);
    else
        HandleBadRawType(rawType); // and leave type as STORE_META_VOID

    RawSwapMetaLength lengthOrGarbage = 0;
    Extract(lengthOrGarbage, input, end);
    if (lengthOrGarbage < 0)
        throw TextException("negative swap meta field length value", Here());
    if (uint64_t(lengthOrGarbage) > SwapMetaFieldValueLengthMax)
        throw TextException("huge swap meta field length value", Here());
    if (input + lengthOrGarbage > end)
        throw TextException("truncated swap meta field value", Here());
    rawLength = static_cast<size_t>(lengthOrGarbage);

    Assure(input > begin);
    Assure(input + rawLength <= end);
    rawValue = input;
}

void
Store::SwapMetaView::checkExpectedLength(const size_t expectedLength) const
{
    if (rawLength != expectedLength)
        throw TextException(ToSBuf("Bad value length in a Store entry meta field expecting a ",
                                   expectedLength, "-byte value: ", *this), Here());
}

std::ostream &
operator <<(std::ostream &os, const Store::SwapMetaView &meta)
{
    os << "type=" << int(meta.rawType);
    // XXX: Change Raw constructor to take void* data instead of casting here.
    const auto rawValue = reinterpret_cast<const char*>(meta.rawValue);
    // TODO: Add/use something like Raw::bestPresentationEncoding() to report
    // binary data as hex, URLs as plain text, and Vary with \r\n escapes?
    os << Raw("value", rawValue, meta.rawLength).minLevel(DBG_DATA).hex();
    return os;
}

