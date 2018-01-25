/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_SECURITY_DIGESTALGORITHM_H
#define SQUID__SRC_SECURITY_DIGESTALGORITHM_H

namespace Security
{

#if USE_OPENSSL
typedef EVP_MD const * DigestAlgorithm;
#elif USE_GNUTLS
typedef gnutls_digest_algorithm_t DigestAlgorithm;
#else
typedef void * DigestAlgorithm;
#endif

/// retrieve the name of a Digest algorithm
inline const char *
digestName(const DigestAlgorithm alg)
{
#if USE_OPENSSL
    return EVP_MD_name(alg);
#elif USE_GNUTLS
    return gnutls_digest_get_name(alg);
#else
    return nullptr;
#endif
}

/// retrieve a Digest algorithm handle from its name
inline const DigestAlgorithm
digestByName(const char *name)
{
#if USE_OPENSSL
    return EVP_get_digestbyname(name);
#elif USE_GNUTLS
    return gnutls_digest_get_id(name);
#else
    return nullptr; // not supported
#endif
}

} // namespace Security

#endif /* SQUID__SRC_SECURITY_DIGESTALGORITHM_H */
