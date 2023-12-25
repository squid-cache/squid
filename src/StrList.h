/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 66    HTTP Header Tools */

#ifndef SQUID_STRLIST_H_
#define SQUID_STRLIST_H_

#include "sbuf/forward.h"

#include <iterator>

class String;

/// Appends the given item to a delimiter-separated list in str.
void strListAdd(String * str, const char *item, char del);

/// Appends the given item of a given size to a delimiter-separated list in str.
void strListAdd(String &str, const char *item, const size_t itemSize, const char del = ',');

/// Appends the given item to a delimiter-separated list in str.
/// Use strListAdd(c-string) for c-string items with unknown length.
void strListAdd(String &str, const SBuf &item, char delimiter = ',');

int strListIsMember(const String * str, const SBuf &item, char del);
int strListIsSubstr(const String * list, const char *s, char del);
/// Iterates through delimiter-separated and optionally "quoted" list members.
/// Follows HTTP #rule, including skipping OWS and empty members.
int strListGetItem(const String * str, char del, const char **item, int *ilen, const char **pos);
/// Searches for the first matching key=value pair
/// within a delimiter-separated list of items.
/// \returns the value of the found pair or an empty string.
SBuf getListMember(const String &list, const char *key, const char delimiter);

#endif /* SQUID_STRLIST_H_ */

