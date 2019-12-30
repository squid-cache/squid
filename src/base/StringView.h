/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS string_views for details.
 */

#ifndef SQUID_BASE_STRING_VIEW_H
#define SQUID_BASE_STRING_VIEW_H

#include <iosfwd>

// TODO: Replace with std::string_view after switching to C+17
/// a reference to portion of a character sequence
/// 0-termination is neither assumed nor honored -- NUL is not treated specially
class StringView
{
public:
    StringView(): start_(nullptr), size_(0) {}
    StringView(const char * const start, const size_t len):
        start_(start),
        size_(len)
    {
        // require zero length for nil start to stop bug propagation here
        assert(start || !len);
    }

    bool empty() const { return !size_; }
    size_t size() const { return size_; }
    const char *data() const { return start_; }

    /* all operators are case-sensitive */
    bool operator ==(const StringView &other) const;
    bool operator !=(const StringView &other) const { return !(*this == other); }

    /* add more methods if needed but mimic std::string_view APIs */

private:
    const char *start_;
    size_t size_;
};

std::ostream &operator <<(std::ostream &, const StringView &);

#endif

