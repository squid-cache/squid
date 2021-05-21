/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CERTERROR_H
#define SQUID_SRC_SECURITY_CERTERROR_H

#include "security/forward.h"

namespace Security
{

/// An X.509 certificate-related error.
/// Pairs an error code with the certificate experiencing the error.
class CertError
{
public:
    CertError(int anErr, const Security::CertPointer &aCert, int aDepth = -1) :
        code(anErr), cert(aCert), depth(aDepth)
    {}

    bool operator == (const CertError &ce) const {
        // We expect to be used in contexts where identical certificates have
        // identical pointers.
        return code == ce.code && depth == ce.depth && cert == ce.cert;
    }

    bool operator != (const CertError &ce) const {
        return !(*this == ce);
    }

public:
    Security::ErrorCode code; ///< certificate error code
    Security::CertPointer cert; ///< certificate with the above error code

    /**
     * Absolute cert position in the final certificate chain that may include
     * intermediate certificates. Chain positions start with zero and increase
     * towards the root certificate. Negative if unknown.
     */
    int depth;
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CERTERROR_H */

