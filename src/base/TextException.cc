/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "sbuf/SBuf.h"

#include <iostream>
#include <sstream>
#include <unordered_map>

/// a standard CoW string; avoids noise and circular dependencies of SBuf
typedef std::runtime_error WhatString;

/// a collection of strings indexed by pointers to their creator objects
typedef std::unordered_multimap<const void*, WhatString> WhatStrings;

/// requested what() strings of alive TextException objects
static WhatStrings *WhatStrings_ = nullptr;

TextException::TextException(SBuf message, const SourceLocation &location):
    TextException(message.c_str(), location)
{}

TextException::~TextException() throw()
{
    if (WhatStrings_)
        WhatStrings_->erase(this); // there only if what() has been called
}

std::ostream &
TextException::print(std::ostream &os) const
{
    os << std::runtime_error::what() <<
        Debug::Extra << "exception location: " << where;
    // TODO: ...error_detail: " << (ERR_DETAIL_EXCEPTION_START+id());
    return os;
}

const char *
TextException::what() const throw()
{
    std::ostringstream os;
    print(os);
    const WhatString result(os.str());

    // extend result.c_str() lifetime to this object lifetime
    if (!WhatStrings_)
        WhatStrings_ = new WhatStrings;
    // *this could change, but we must preserve old results for they may be used
    WhatStrings_->emplace(std::make_pair(this, result));

    return result.what();
}

std::ostream &
CurrentException(std::ostream &os)
{
    if (std::current_exception()) {
        try {
            throw; // re-throw to recognize the exception type
        }
        catch (const std::exception &ex) {
            os << ex.what();
        }
        catch (...) {
            os << "[unknown exception type]";
        }
    } else {
        os << "[no active exception]";
    }
    return os;
}

