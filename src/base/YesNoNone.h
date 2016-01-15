/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_YESNONONE_H_
#define SQUID_YESNONONE_H_

#include "base/TextException.h"

// TODO: generalize / template to non-boolean option types
// and make YesNoNone the boolean instance of the template

/**
 * Used for boolean enabled/disabled options with complex default logic.
 * Allows Squid to compute the right default after configuration.
 * Checks that not-yet-defined option values are not used.
 * Allows for implicit default Yes/No values to be used by initialization
 * without configure() being called, but not dumped as squid.conf content.
 *
 * Use x.configure(bool) when the value is configured.
 * Use x.defaultTo(bool) to assign defaults.
 */
class YesNoNone
{
    enum SetHow : uint8_t { optUnspecified = 0, optImplicitly = 1, optConfigured = 2 };

public:
    // this constructor initializes to 'unspecified' state
    YesNoNone():
        setHow_(optUnspecified),
        option(false)
    {}

    // this constructor initializes to 'implicit' state
    explicit YesNoNone(bool beSet):
        setHow_(optImplicitly),
        option(beSet)
    {}

    /// the boolean equivalent of the value stored.
    /// asserts if the value has not been set.
    explicit operator bool() const {
        Must(setHow_ != optUnspecified);
        return option;
    }

    /// enables or disables the option; updating to 'configured' state
    void configure(bool beSet) {
        setHow_ = optConfigured;
        option = beSet;
    }

    /// enables or disables the option; updating to 'implicit' state
    void defaultTo(bool beSet) {
        Must(setHow_ != optConfigured);
        setHow_ = optImplicitly;
        option = beSet;
    }

    /// whether the option was enabled or disabled,
    /// by squid.conf values resulting in explicit configure() usage.
    bool configured() const {return setHow_ == optConfigured;}

private:
    SetHow setHow_; ///< how the option was set
    bool option; ///< specified yes/no value; meaningless if optUnspecified
};

#endif /* SQUID_YESNONONE_H_ */

