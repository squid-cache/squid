/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Definitions for functions defined in Algorithm .h files
 * which cannot be defined in their auto-generated .cc files.
 * TODO: auto-generate the array lookup
 */

#include "squid.h"
#include "base/IoManip.h"
#include "debug/Stream.h"
#include "security/CertAdaptAlgorithm.h"
#include "security/CertSignAlgorithm.h"
#include "security/DigestAlgorithm.h"

const char *
Security::certAdaptAlgorithmName(const int alg)
{
    assert(alg >= 0);
    assert(alg < algSetEnd);
    return CertAdaptAlgorithm_str[alg];
}

Security::CertAdaptAlgorithm
Security::certAdaptAlgorithmId(const char *name)
{
    for (int i = 0; i < algSetEnd; ++i) {
        if (strcmp(CertAdaptAlgorithm_str[i], name) == 0)
            return static_cast<CertAdaptAlgorithm>(i);
    }

    std::string msg("unknown cert adaptation algorithm: ");
    msg.append(name);
    throw std::runtime_error(msg);
}

const char *
Security::certSignAlgorithmName(const int sg)
{
    assert(sg >= 0);
    assert(sg < algSignEnd);
    return CertSignAlgorithm_str[sg];
}

Security::CertSignAlgorithm
Security::certSignAlgorithmId(const char *name)
{
    for (int i = 0; i < algSignEnd; ++i) {
        if (strcmp(CertSignAlgorithm_str[i], name) == 0)
            return static_cast<CertSignAlgorithm>(i);
    }

    std::string msg("unknown cert signing algorithm: ");
    msg.append(name);
    throw std::runtime_error(msg);
}

const char *
Security::digestName(const DigestAlgorithm alg)
{
    assert(alg != UnknownDigestAlgorithm);
#if USE_OPENSSL
    const char *name = EVP_MD_name(alg);
#elif USE_GNUTLS
    const char *name = gnutls_digest_get_name(alg);
#else
    const char *name = nullptr;
#endif

    if (!name) {
        std::string msg("unknown digest algorithm: id=");
        std::ostringstream ss;
        ss << AsHex<const DigestAlgorithm>(alg);
        ss.flush();
        msg.append(ss.str());
        throw std::runtime_error(msg);
    }

    return name;
}

Security::DigestAlgorithm
Security::digestByName(const char *name)
{
#if USE_OPENSSL
    const auto id = EVP_get_digestbyname(name);
#elif USE_GNUTLS
    const auto id = gnutls_digest_get_id(name);
#else
    const auto id = UnknownDigestAlgorithm; // not supported
#endif

    if (id == UnknownDigestAlgorithm) {
        std::string msg("unknown digest algorithm: ");
        msg.append(name);
        throw std::runtime_error(msg);
    }

    return id;
}

