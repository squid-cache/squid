/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CERTADAPTALGORITHM_H
#define SQUID_SRC_SECURITY_CERTADAPTALGORITHM_H

#include "security/forward.h"

namespace Security
{

/// Supported certificate adaptation algorithms
enum CertAdaptAlgorithm : short {
    algSetValidAfter = 0,
    algSetValidBefore,
    algSetCommonName,
    algSetEnd
};

/// Short names for certificate adaptation algorithms
extern const char *CertAdaptAlgorithm_str[];

/// \returns the short name of the adaptation algorithm "alg"
const char *certAdaptAlgorithmName(const int alg);

/// \returns the id of the named adaptation algorithm
CertAdaptAlgorithm certAdaptAlgorithmId(const char *name);

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CERTADAPTALGORITHM_H */
