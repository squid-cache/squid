/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_REGEXLIST_H_
#define SQUID_REGEXLIST_H_

/// list of regular expressions. Currently a POD.
class RegexList
{
public:
    int flags;
    char *pattern;
    regex_t regex;
    RegexList *next;
};

#endif /* SQUID_REGEXLIST_H_ */

