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

// TODO: Refactor into a static_assert after migrating to C++17.
/// Upholds swap metadata invariants that cannot be checked at compile time
/// (yet) but can be checked without swap in/out transaction specifics.
static bool
CheckSwapMetaTypeEnum(bool &useMe)
{
    for (auto i = RawSwapMetaTypeTop(); i != RawSwapMetaTypeBottom; --i) {
        // assertion descriptions below are approximate; many mistake variations
        // are possible and one mistake may affect multiple invariants

        // remembered to classify a name after removing it from SwapMetaType
        assert(HonoredSwapMetaType(i) || IgnoredSwapMetaType(i));

        // did not list the same value in these two mutually exclusive sets
        assert(!(HonoredSwapMetaType(i) && IgnoredSwapMetaType(i)));

        // did not list the same value in these two mutually exclusive sets
        assert(!(DeprecatedSwapMetaType(i) && ReservedSwapMetaType(i)));
    }

    // upheld RawSwapMetaTypeBottom definition of being unrelated to any named
    // SwapMetaDataType values, including past, current, and reserved
    assert(!HonoredSwapMetaType(RawSwapMetaTypeBottom));
    assert(!IgnoredSwapMetaType(RawSwapMetaTypeBottom));

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

