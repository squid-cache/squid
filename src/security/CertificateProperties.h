/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CERTIFICATEPROPERTIES_H
#define SQUID_SRC_SECURITY_CERTIFICATEPROPERTIES_H

#include "security/forward.h"

namespace Security
{

/**
 * Certificate generation parameters to mimic
 */
class CertificateProperties
{
public:
    CertificateProperties() = default;

    Security::CertPointer mimicCert;          ///< Certificate to mimic

    Security::CertPointer signWithX509;       ///< Certificate to sign the generated request
    Security::PrivateKeyPointer signWithPkey; ///< The key of the signing certificate

    bool setValidAfter = false;  ///< Do not mimic "Not Valid After" field
    bool setValidBefore = false; ///< Do not mimic "Not Valid Before" field

    bool setCommonName = false; ///< Replace the CN field of the mimicing subject with the given
    std::string commonName;     ///< A CN to use for the generated certificate

    CertSignAlgorithm signAlgorithm = Security::algSignEnd; ///< The signing algorithm to use
    DigestAlgorithm signHash = nullptr;                     ///< The signing hash to use

private:
    CertificateProperties(CertificateProperties const &) = delete;
    CertificateProperties &operator =(CertificateProperties const &) = delete;
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CERTIFICATEPROPERTIES_H */

