/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
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
    regex(pattern.rawContent(), pattern.length(), aFlags|std::regex::nosubs|std::regex::optimize)
{
    // this class supports other syntax variations, but its current users must
    // support one of these two for backward compatibility reasons, and we check
    // that they have not forgotten to do so
    assert((aFlags & (std::regex::basic|std::regex::extended)) != 0);
}

bool
RegexPattern::match(const char *str) const
{
    return std::regex_search(str, regex);
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

