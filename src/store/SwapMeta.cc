/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "store/SwapMeta.h"

void
Store::CheckSwapMetaSerialization(const RawSwapMetaType type, const RawSwapMetaLength length, const void *value)
{
    // we do not serialize deprecated or reserved types
    assert(HonoredSwapMetaType(type));

    assert(length >= 0);
    assert(size_t(length) <= SwapMetaFieldValueLengthMax);

    // cannot write a non-empty value if it is missing
    assert(!length || value);
}

