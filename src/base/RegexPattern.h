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

/**
 * A regular expression,
 * plain text and compiled representations
 */
class RegexPattern
{
    MEMPROXY_CLASS(RegexPattern);

public:
    RegexPattern() = delete;
    RegexPattern(int aFlags, const char *aPattern) : flags(aFlags), pattern(xstrdup(aPattern)) {}
    RegexPattern(const RegexPattern &) = delete;
    RegexPattern(RegexPattern &&) = default;
    ~RegexPattern();

    int flags;
    char *pattern;
    regex_t regex;
};

#endif /* SQUID_SRC_BASE_REGEXPATTERN_H */

