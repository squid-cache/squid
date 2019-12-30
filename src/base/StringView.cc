/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS string_views for details.
 */

#include "squid.h"
#include "base/StringView.h"

#include <cstring>
#include <iostream>

bool
StringView::operator ==(const StringView &other) const
{
    return size_ == other.size_ &&
           (empty() || memcmp(start_, other.start_, size_) == 0);
}

std::ostream &
operator <<(std::ostream &os, const StringView &view)
{
    if (const auto size = view.size())
        os.write(view.data(), size);
    return os;
}

