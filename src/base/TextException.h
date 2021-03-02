/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__TEXTEXCEPTION_H
#define SQUID__TEXTEXCEPTION_H

#include "base/Here.h"

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

/// formats a message similar to that of a failed assert(success) check
SBuf MakeFailedCheckMessage(const SBuf &successDescription);
/// convenience wrapper for MakeFailedCheckMessage(SBuf)
SBuf MakeFailedCheckMessage(const char *successDescription);

/// Like assert() but throws an exception instead of aborting the process
/// and allows the caller to specify a custom exception message.
/// \param successDescription description of the condition -- what MUST happen
template <typename Description>
inline void
Must3(const bool condition, const Description successDescription, const SourceLocation &location)
{
    // XXX: Cannot pass SBuf to TextException() without #including SBuf.h:
    // compile error: invalid use of incomplete type ‘class SBuf’
    if (!condition)
        throw TextException("MakeFailedCheckMessage(successDescription)", location);
}

/// Like assert() but throws an exception instead of aborting the process.
#define Must(condition) Must3(!!(condition), (#condition), Here())

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

