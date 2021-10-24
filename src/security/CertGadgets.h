/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
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

#if SQUID_CAN_INTERROGATE_X509_CERTIFICATES

/// \return the SubjectName field of the given certificate (if found), or an empty SBuf
SBuf CertSubjectName(const CertPointer &);

/// \return the Issuer field of the given certificate (if found), or an empty SBuf
SBuf CertIssuerName(const CertPointer &);

/// \returns whether cert was (correctly) issued by the given issuer
/// Due to complexity of the underlying checks, it is impossible to clearly
/// distinguish pure negative answers (e.g., two independent certificates)
/// from errors (e.g., the issuer certificate lacks the right CA extension).
bool CertIsIssuedBy(const CertPointer &cert, const CertPointer &issuer);

/// convenience wrapper for checking self-signed certificates
inline bool CertIsSelfSigned(const CertPointer &cert) {
    return CertIsIssuedBy(cert, cert);
}

#endif // SQUID_CAN_INTERROGATE_X509_CERTIFICATES

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CERTGADGETS_H */

