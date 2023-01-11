/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/RegexPattern.h"
#include "debug/Stream.h"
#include "sbuf/Stream.h"

#include <iostream>

RegexPattern::RegexPattern(const SBuf &aPattern, const std::regex::flag_type aFlags):
    pattern(aPattern),
    regex(aPattern.rawContent(), aPattern.length(), aFlags)
{
    // this class supports other syntax variations, but its current users must
    // support one of these two for backward compatibility reasons, and we check
    // that they have not forgotten to do so
    assert((aFlags & (std::regex::basic|std::regex::extended)) != 0);
    debugs(28, 2, *this);
}

bool
RegexPattern::match(const char *str) const
{
    std::cmatch found;
    if (std::regex_search(str, found, regex)) {
        debugs(18, 5, "matched " << found[0]);
        return true;
    }
    return false;
}

void
RegexPattern::print(std::ostream &os, const RegexPattern * const previous) const
{
    // report context-dependent explicit options and delimiters
    if (!previous) {
        // do not report default settings
        if (!caseSensitive())
            os << "-i ";
    } else {
        os << ' '; // separate us from the previous value

        // do not report same-as-previous (i.e. inherited) settings
        if (previous->regex.flags() != regex.flags())
            os << (caseSensitive() ? "+i " : "-i ");
    }

    os << pattern;
}

