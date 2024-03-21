/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CERTIFICATEPROPERTIES_H
#define SQUID_SRC_SECURITY_CERTIFICATEPROPERTIES_H

#include "security/CertSignAlgorithm.h"
#include "security/DigestAlgorithm.h"
#include "security/forward.h"

#include <string>

namespace Security
{

/**
 * Certificate generation parameters
 */
class CertificateProperties
{
public:
    CertificateProperties() = default;

    CertPointer mimicCert;          ///< Certificate to mimic

    CertPointer signWithX509;       ///< Certificate to sign the generated request
    PrivateKeyPointer signWithPkey; ///< The key of the signing certificate

    bool setValidAfter = false;  ///< Do not mimic "Not Valid After" field
    bool setValidBefore = false; ///< Do not mimic "Not Valid Before" field

    bool setCommonName = false; ///< Replace the CN field of the mimicing subject with the given
    std::string commonName;     ///< A CN to use for the generated certificate

    CertSignAlgorithm signAlgorithm = algSignEnd; ///< The signing algorithm to use
    DigestAlgorithm signHash = UnknownDigestAlgorithm; ///< The signing hash to use

private:
    CertificateProperties(CertificateProperties const &) = delete;
    CertificateProperties &operator =(CertificateProperties const &) = delete;
    CertificateProperties(CertificateProperties &&) = delete;
    CertificateProperties &operator =(CertificateProperties &&) = delete;
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CERTIFICATEPROPERTIES_H */

