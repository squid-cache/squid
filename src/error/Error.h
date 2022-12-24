/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_ERROR_ERROR_H
#define _SQUID_SRC_ERROR_ERROR_H

#include "error/Detail.h"
#include "error/forward.h"

#include <iosfwd>

/// a transaction problem
class Error {
public:
    Error() = default;
    Error(const err_type c): category(c) {} ///< support implicit conversions
    Error(const err_type c, const ErrorDetailPointer &d): category(c), detail(d) {}

    explicit operator bool() const { return category != ERR_NONE; }

    /// if necessary, stores the given error information (if any)
    void update(const Error &);

    /// convenience wrapper for update(Error)
    void update(const err_type c, const ErrorDetailPointer &d) { update(Error(c, d)); }

    /// switch to the default "no error information" state
    void clear() { *this = Error(); }

    err_type category = ERR_NONE; ///< primary error classification (or ERR_NONE)
    ErrorDetailPointer detail; ///< additional details about the error
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

