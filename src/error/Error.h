/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_ERROR_ERROR_H
#define _SQUID_SRC_ERROR_ERROR_H

#include "error/Detail.h"
#include "error/forward.h"
#include "mem/PoolingAllocator.h"

#include <iosfwd>
#include <vector>

/// zero or more non-nil pointers to unique ErrorDetail objects
using ErrorDetails = std::vector<ErrorDetailPointer, PoolingAllocator<ErrorDetailPointer> >;

/// prints all details separated by '+' (or, if there are no details, nothing)
std::ostream &operator <<(std::ostream &os, const ErrorDetails &);

/// a transaction problem
class Error {
public:
    Error() = default;
    Error(const err_type c): category(c) {} ///< support implicit conversions
    Error(const err_type c, const ErrorDetailPointer &d): Error(c) { update(d); }

    explicit operator bool() const { return category != ERR_NONE; }

    /// if necessary, stores the given error information (if any)
    void update(const Error &);

    /// if necessary, stores the given error information (if any);
    /// more convenient and faster alternative to calling update(Error(c, d))
    void update(err_type, const ErrorDetailPointer &);

    /// records an additional error detail (if any), leaving category unchanged
    /// \param detail either nil or a pointer to a new or an already known detail
    void update(const ErrorDetailPointer &detail);

    /// switch to the default "no error information" state
    void clear() { *this = Error(); }

    err_type category = ERR_NONE; ///< primary error classification (or ERR_NONE)
    ErrorDetails details; ///< additional details about the error

private:
    bool startUpdate(err_type, bool);
};

extern const char *err_type_str[];

inline
err_type
errorTypeByName(const char *name)
{
    for (int i = 0; i < ERR_MAX; ++i)
        if (strcmp(name, err_type_str[i]) == 0)
            return (err_type)i;
    return ERR_MAX;
}

inline
const char *
errorTypeName(err_type err)
{
    if (err < ERR_NONE || err >= ERR_MAX)
        return "UNKNOWN";
    return err_type_str[err];
}

std::ostream &operator <<(std::ostream &os, const Error &error);

#endif /* _SQUID_SRC_ERROR_ERROR_H */

