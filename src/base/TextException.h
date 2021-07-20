/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__TEXTEXCEPTION_H
#define SQUID__TEXTEXCEPTION_H

#include "base/Here.h"
#include "base/Assert.h"

#include <stdexcept>

class SBuf;

/// an std::runtime_error with thrower location info
class TextException: public std::runtime_error
{

public:
    TextException(const char *message, const SourceLocation &location):
        std::runtime_error(message),
        where(location)
    {}

    TextException(SBuf message, const SourceLocation &location);

    TextException(const TextException &) = default;
    TextException(TextException &&) = default;
    TextException& operator=(const TextException &) = default;

    /* std::runtime_error API */
    virtual ~TextException() throw() override;
    virtual const char *what() const throw() override;

    /// same-location exceptions have the same ID
    SourceLocationId id() const { return where.id(); }

    /// dumps the exception text into the stream
    std::ostream &print(std::ostream &) const;

    /// code location related to the exception; usually the thrower location
    SourceLocation where;

    // TODO: Add support for arbitrary (re)thrower-supplied details:
    // std::tuple<Details...> details;
};

/// prints active (i.e., thrown but not yet handled) exception
std::ostream &CurrentException(std::ostream &);

/// efficiently prints TextException
std::ostream &operator <<(std::ostream &, const TextException &);

/// legacy convenience macro; it is not difficult to type Here() now
#define TexcHere(msg) TextException((msg), Here())

/// Like Assert() but only logs the exception if level-3 debugging is enabled
/// and runs even when NDEBUG macro is defined. Deprecated: Use Assert() for
/// code logic checks and throw explicitly when input validation fails.
#define Must(condition) \
    Assert_(3, (condition), #condition, Here())

/// Like Must() but supports custom exception message and location.
/// \param description string literal describing the condition; what MUST happen
/// Deprecated: Use Assert2() for code logic checks and throw explicitly when
/// input validation fails.
#define Must3(condition, description, location) \
    Assert_(3, (condition), (description), (location))

/// Reports and swallows all exceptions to prevent compiler warnings and runtime
/// errors related to throwing class destructors. Should be used for most dtors.
#define SWALLOW_EXCEPTIONS(code) \
    try { \
        code \
    } catch (...) { \
        debugs(0, DBG_IMPORTANT, "BUG: ignoring exception;" << \
               Debug::Extra << "bug location: " << Here() << \
               Debug::Extra << "ignored exception: " << CurrentException); \
    }

#endif /* SQUID__TEXTEXCEPTION_H */

