/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 66    HTTP Header Tools */

#ifndef SQUID_STRLIST_H_
#define SQUID_STRLIST_H_

#include "sbuf/forward.h"

class String;

void strListAdd(String * str, const char *item, char del);
int strListIsMember(const String * str, const SBuf &item, char del);
int strListIsSubstr(const String * list, const char *s, char del);
int strListGetItem(const String * str, char del, const char **item, int *ilen, const char **pos);
/// Searches for the first matching key=value pair
/// within a delimiter-separated list of items.
/// \returns the value of the found pair or an empty string.
SBuf getListMember(const String &list, const char *key, const char del);

#endif /* SQUID_STRLIST_H_ */

