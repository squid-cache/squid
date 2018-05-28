/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CERTSIGNALGORITHM_H
#define SQUID_SRC_SECURITY_CERTSIGNALGORITHM_H

#include <stdexcept>
#include <string>

namespace Security
{

typedef enum {
    algSignTrusted = 0,
    algSignUntrusted,
    algSignSelf,
    algSignEnd
} CertSignAlgorithm;

/// Short names for certificate signing algorithms
extern const char *CertSignAlgorithm_str[];

/// \returns the short name of the signing algorithm sg
inline const char *
certSignAlgorithmName(const int sg)
{
    assert(sg >= 0);
    assert(sg < algSignEnd);
    return CertSignAlgorithm_str[sg];
}

/// \returns the id of the named signing algorithm
inline CertSignAlgorithm
certSignAlgorithmId(const char *sg)
{
    for (int i = 0; i < algSignEnd; ++i) {
        if (strcmp(CertSignAlgorithm_str[i], sg) == 0)
            return static_cast<CertSignAlgorithm>(i);
    }

    std::string msg("unknown cert signing algorithm: ");
    msg.append(sg);
    throw std::runtime_error(msg);
}

} // namespace Security

#endif /* SQUID_SRC_SECURITY_CERTSIGNALGORITHM_H */
