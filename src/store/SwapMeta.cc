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

static void
checkTooSmallRawType(const RawSwapMetaType rawType)
{
    // RawSwapMetaTypeBottom and smaller values are unrelated to any named
    // SwapMetaDataType values, including past, current, and future ones
    assert(!HonoredSwapMetaType(rawType)); // current
    assert(!IgnoredSwapMetaType(rawType)); // past and future
    assert(!DeprecatedSwapMetaType(rawType)); // past
    assert(!ReservedSwapMetaType(rawType)); // future
}

static void
checkKnownRawType(const RawSwapMetaType rawType)
{
    // a known raw type is either honored or ignored
    assert(HonoredSwapMetaType(rawType) || IgnoredSwapMetaType(rawType));
    assert(!(HonoredSwapMetaType(rawType) && IgnoredSwapMetaType(rawType)));

    if (IgnoredSwapMetaType(rawType)) {
        // an ignored raw type is either deprecated or reserved
        assert(DeprecatedSwapMetaType(rawType) || ReservedSwapMetaType(rawType));
        assert(!(DeprecatedSwapMetaType(rawType) && ReservedSwapMetaType(rawType)));
    } else {
        // an honored raw type is neither deprecated nor reserved
        assert(!DeprecatedSwapMetaType(rawType) && !ReservedSwapMetaType(rawType));
    }
}

static void
checkTooBigRawType(const RawSwapMetaType rawType)
{
    // values beyond RawSwapMetaTypeTop() may be reserved for future use but
    // cannot be honored or deprecated
    if (ReservedSwapMetaType(rawType)) {
        assert(IgnoredSwapMetaType(rawType));
    } else {
        assert(!HonoredSwapMetaType(rawType));
        assert(!IgnoredSwapMetaType(rawType));
        assert(!DeprecatedSwapMetaType(rawType));
    }
}

/// Upholds swap metadata invariants that cannot be checked at compile time but
/// can be checked without swap in/out transaction specifics.
static bool
CheckSwapMetaTypeClassification(bool &useMe)
{
    using limits = std::numeric_limits<RawSwapMetaType>;
    for (auto rawType = limits::min(); true; ++rawType) {

        if (rawType <= RawSwapMetaTypeBottom)
            checkTooSmallRawType(rawType);
        else if (rawType > RawSwapMetaTypeTop())
            checkTooBigRawType(rawType);
        else
            checkKnownRawType(rawType);

        if (rawType == limits::max())
            break;
    }

    // RawSwapMetaTypeTop() is documented as an honored type value
    assert(HonoredSwapMetaType(RawSwapMetaTypeTop()));

    useMe = true;
    return true;
}

/// triggers one-time SwapMetaType enum validation at startup
static bool Checked = CheckSwapMetaTypeClassification(Checked);

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

