/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
class StrList;

/// Appends the given item to a delimiter-separated list in str.
void strListAdd(String * str, const char *item, char del);

/// Appends the given item to a delimiter-separated list in str.
/// Use strListAdd(c-string) for c-string items with unknown length.
void strListAdd(String &str, const SBuf &item, char delimiter = ',');

int strListIsMember(const String * str, const SBuf &item, char del);
int strListIsSubstr(const String * list, const char *s, char del);
/// Iterates through delimiter-separated and optionally "quoted" list members.
/// Follows HTTP #rule, including skipping OWS and empty members.
/// \deprecated use a C++ range-based "for" loop with StrList instead
int strListGetItem(const String * str, char del, const char **item, int *ilen, const char **pos);
/// Searches for the first matching key=value pair
/// within a delimiter-separated list of items.
/// \returns the value of the found pair or an empty string.
SBuf getListMember(const String &list, const char *key, const char delimiter);

/// a forward iterator for StrList
class StrListIterator: public std::iterator<std::forward_iterator_tag, SBuf>
{
public:
    explicit StrListIterator(const StrList *list);

    bool operator ==(const StrListIterator &other) const { return this->position == other.position; }
    bool operator !=(const StrListIterator &other) const { return !(*this == other); }
    const value_type &operator *() const { return current; }

    StrListIterator &operator++() {
        proceed();
        return *this;
    }

    StrListIterator operator++(int) {
        const StrListIterator past(*this);
        ++(*this);
        return past;
    }

private:
    void proceed();

    const StrList *list; /// the list being iterated; nil when iteration ended
    const char *position; ///< where to start searching for the next list member
    value_type current; ///< the last list member found
};

/// A reference to a constant string containing delimiter-separated members
/// that may be "quoted". Allows member iteration using range-based "for" loops.
/// Iteration follows HTTP #rule, including skipping OWS and empty members.
class StrList
{
public:
    explicit StrList(const String &s, const char delimitr = ','): raw_(s), delimiter_(delimitr) {}

    StrListIterator begin() const { return StrListIterator(this); }
    StrListIterator end() const { return StrListIterator(nullptr); }

    const String &raw() const { return raw_; }
    char delimiter() const { return delimiter_; }

private:
    const String &raw_; /// the list being iterated
    const char delimiter_; ///< member separator
};

#endif /* SQUID_STRLIST_H_ */

