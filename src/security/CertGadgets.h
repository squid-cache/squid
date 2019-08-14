/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CERTGADGETS_H
#define SQUID_SRC_SECURITY_CERTGADGETS_H

#include "security/forward.h"

namespace Security
{

/// \return the SubjectName field of the given certificate
SBuf CertSubjectName(const CertPointer &);

/// Squid defined error code (<0), an error code returned by X.509 API, or SSL_ERROR_NONE
typedef int ErrorCode;

/// \return true if cert was issued by the given issuer CA.
///         sets checkCode to the library specific test result.
bool CertIssuerCheck(const CertPointer &cert, const CertPointer &issuer, ErrorCode &checkCode);

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CERTGADGETS_H */

