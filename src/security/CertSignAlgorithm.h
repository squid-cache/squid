/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CERTSIGNALGORITHM_H
#define SQUID_SRC_SECURITY_CERTSIGNALGORITHM_H

#include "security/forward.h"

namespace Security
{

enum CertSignAlgorithm : short {
    algSignTrusted = 0,
    algSignUntrusted,
    algSignSelf,
    algSignEnd
};

/// Short names for certificate signing algorithms
extern const char *CertSignAlgorithm_str[];

/// \returns the short name of the signing algorithm sg
const char *certSignAlgorithmName(const int sg);

/// \returns the id of the named signing algorithm
CertSignAlgorithm certSignAlgorithmId(const char *name);

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CERTSIGNALGORITHM_H */
