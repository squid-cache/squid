/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_REGEXLIST_H_
#define SQUID_REGEXLIST_H_

#include "mem/forward.h"

#include <regex>

/// list of regular expressions.
class RegexList
{
    MEMPROXY_CLASS(RegexList);

public:
    RegexList() = delete;
    RegexList(int aFlags, const char *aPattern) : flags(aFlags), pattern(xstrdup(aPattern)), next(nullptr) {}
    RegexList(const RegexList &) = delete;
    RegexList(const RegexList && o) = delete;
    ~RegexList();

    int flags;
    char *pattern;
    regex_t regex;
    RegexList *next;
};

#endif /* SQUID_REGEXLIST_H_ */

