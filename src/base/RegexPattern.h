/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_REGEXPATTERN_H
#define SQUID_SRC_BASE_REGEXPATTERN_H

#include "mem/forward.h"

#include <regex>

/**
 * A regular expression,
 * plain text and compiled representations
 */
class RegexPattern
{
    MEMPROXY_CLASS(RegexPattern);

public:
    RegexPattern() = delete;
    RegexPattern(const std::regex_constants::syntax_option_type &aFlags, const char *aPattern); // throws std::regex_error
    RegexPattern(const RegexPattern &) = delete;
    RegexPattern(RegexPattern &&) = default; // throws std::regex_error
    ~RegexPattern();

    const char * c_str() const {return pattern;}
    bool match(const char *str) const {return std::regex_search(str, regex);}

public:
    std::regex_constants::syntax_option_type flags;

private:
    char *pattern;
    std::regex regex;
};

#endif /* SQUID_SRC_BASE_REGEXPATTERN_H */

