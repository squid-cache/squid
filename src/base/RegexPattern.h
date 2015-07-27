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
    RegexPattern(const RegexPattern && o) = delete;
    ~RegexPattern();

    int flags;
    char *pattern;
    regex_t regex;
};

/// list of regular expressions.
/// \deprecated use a std::list<RegexPattern> instead
class RegexList : public RegexPattern
{
    MEMPROXY_CLASS(RegexList);

public:
    RegexList() = delete;
    RegexList(int aFlags, const char *aPattern) : RegexPattern(aFlags, aPattern), next(nullptr) {}
    RegexList(const RegexList &) = delete;
    RegexList(const RegexList && o) = delete;
    ~RegexList();

    RegexList *next;
};

#endif /* SQUID_SRC_BASE_REGEXPATTERN_H */

