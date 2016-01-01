/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 66    HTTP Header Tools */

#ifndef SQUID_STRLIST_H_
#define SQUID_STRLIST_H_

class String;

void strListAdd(String * str, const char *item, char del);
int strListIsMember(const String * str, const char *item, char del);
int strListIsSubstr(const String * list, const char *s, char del);
int strListGetItem(const String * str, char del, const char **item, int *ilen, const char **pos);

#endif /* SQUID_STRLIST_H_ */

