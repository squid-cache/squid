/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "store/SwapMeta.h"

#include <limits>

namespace Store {

// XXX: Move detailed check descriptions inside the function.
// TODO: Refactor into a static_assert after migrating to C++17.
/// Validates that all SwapMetaType names are classified, protecting developers
/// from forgetting to classify a name after removing it from SwapMetaType.
/// Also checks that honored and ignored sets are mutually exclusive.
/// Also checks that deprecated and reserved sets are mutually exclusive.
static bool
CheckSwapMetaTypeEnum(bool &useMe)
{
    for (auto i = RawSwapMetaTypeMax(); i != STORE_META_VOID; --i) {
        assert(HonoredSwapMetaType(i) || IgnoredSwapMetaType(i));
        assert(!(HonoredSwapMetaType(i) && IgnoredSwapMetaType(i)));
        assert(!(DeprecatedSwapMetaType(i) && ReservedSwapMetaType(i)));
    }

    useMe = true;
    return true;
}

/// triggers one-time SwapMetaType enum validation at startup
static bool Checked = Store::CheckSwapMetaTypeEnum(Checked);

} // namespace Store

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

