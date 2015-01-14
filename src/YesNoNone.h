/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_YESNONONE_H_
#define SQUID_YESNONONE_H_

/// Used for boolean enabled/disabled options with complex default logic.
/// Allows Squid to compute the right default after configuration.
/// Checks that not-yet-defined option values are not used.
class YesNoNone
{
// TODO: generalize to non-boolean option types
public:
    YesNoNone(): option(0) {}

    /// returns true iff enabled; asserts if the option has not been configured
    operator void *() const; // TODO: use a fancy/safer version of the operator

    /// enables or disables the option;
    void configure(bool beSet);

    /// whether the option was enabled or disabled, by user or Squid
    bool configured() const { return option != 0; }

private:
    enum { optUnspecified = -1, optDisabled = 0, optEnabled = 1 };
    int option; ///< configured value or zero
};

#endif /* SQUID_YESNONONE_H_ */

