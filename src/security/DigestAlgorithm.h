/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID__SRC_SECURITY_DIGESTALGORITHM_H
#define SQUID__SRC_SECURITY_DIGESTALGORITHM_H

#if USE_OPENSSL
#if HAVE_OPENSSL_EVP_H
#include <openssl/evp.h>
#endif
#elif USE_GNUTLS
#if HAVE_GNUTLS_GNUTLS_H
#include <gnutls/gnutls.h>
#endif
#endif

namespace Security
{

#if USE_OPENSSL
typedef EVP_MD const * DigestAlgorithm;
#define UnknownDigestAlgorithm nullptr
#elif USE_GNUTLS
typedef gnutls_digest_algorithm_t DigestAlgorithm;
#define UnknownDigestAlgorithm GNUTLS_DIG_UNKNOWN
#else
typedef void * DigestAlgorithm;
#define UnknownDigestAlgorithm nullptr
#endif

/// retrieve the name of a Digest algorithm
const char *digestName(const DigestAlgorithm);

/// retrieve a Digest algorithm handle from its name
const DigestAlgorithm digestByName(const char *name);

} // namespace Security

#endif /* SQUID__SRC_SECURITY_DIGESTALGORITHM_H */
