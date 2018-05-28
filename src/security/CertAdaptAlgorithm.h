/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CERTADAPTALGORITHM_H
#define SQUID_SRC_SECURITY_CERTADAPTALGORITHM_H

#include <stdexcept>
#include <string>

namespace Security
{

/// Supported certificate adaptation algorithms
typedef enum {
    algSetValidAfter = 0,
    algSetValidBefore,
    algSetCommonName,
    algSetEnd
} CertAdaptAlgorithm;

/// Short names for certificate adaptation algorithms
extern const char *CertAdaptAlgorithm_str[];

/// \returns the short name of the adaptation algorithm "alg"
inline const char *
certAdaptAlgorithmName(const int alg)
{
    assert(alg >= 0);
    assert(alg < Security::algSetEnd);
    return CertAdaptAlgorithm_str[alg];
}

/// \returns the id of the named adaptation algorithm
inline CertAdaptAlgorithm
certAdaptAlgorithmId(const char *alg)
{
    for (int i = 0; i < algSetEnd; ++i) {
        if (strcmp(CertAdaptAlgorithm_str[i], alg) == 0)
            return static_cast<CertAdaptAlgorithm>(i);
    }

    std::string msg("unknown cert adaptation algorithm: ");
    msg.append(alg);
    throw std::runtime_error(msg);
}

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CERTADAPTALGORITHM_H */
