/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SSL_ERRORDETAIL_H
#define SQUID_SRC_SSL_ERRORDETAIL_H

#include "security/ErrorDetail.h"

#include <optional>

// TODO: Remove Security::X wrappers and move the remaining configurable error
// details (i.e. templates/error-details.txt) code to src/security/ErrorDetail.

namespace Ssl
{
/**
 * Converts user-friendly error "name" into an Security::ErrorCode
 * and adds it to the provided container (using emplace).
 * This function can handle numeric error numbers as well as names.
 */
bool ParseErrorString(const char *name, Security::Errors &);

/// The Security::ErrorCode code of the error described by  "name".
inline Security::ErrorCode
GetErrorCode(const char *name)
{
    return Security::ErrorCodeFromName(name);
}

/// \return string representation of a known TLS error (or a raw error code)
/// \param prefixRawCode whether to prefix raw codes with "SSL_ERR="
inline const char *
GetErrorName(const Security::ErrorCode code, const bool prefixRawCode = false)
{
    return Security::ErrorNameFromCode(code, prefixRawCode);
}

/// a short description of the given TLS error known to Squid (or, if the error
/// is unknown, nothing)
std::optional<SBuf> GetErrorDescr(Security::ErrorCode);

/// \return true if the TLS error is optional and may not be supported by current squid version
bool ErrorIsOptional(const char *name);

}//namespace Ssl
#endif /* SQUID_SRC_SSL_ERRORDETAIL_H */

