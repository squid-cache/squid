/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_CERTIFICATE_H
#define SQUID_SRC_SECURITY_CERTIFICATE_H

#include "sbuf/forward.h"
#include "security/forward.h"

// The accessing/testing functions below require a non-constant Certificate when
// it is modified by an underlying library implementation (e.g., GnuTLS).

namespace Security
{

/// Content of a X.509 file before parsing.
#if USE_OPENSSL
using CertFileRawPointer = std::unique_ptr<BIO, HardFun<void, BIO*, &BIO_vfree>>;
#elif HAVE_LIBGNUTLS
inline void gnutls_datum_free(gnutls_datum_t *p) {
    if (p && p->size > 0)
        gnutls_free(p->data);
    delete p;
}
using CertFileRawPointer = std::unique_ptr<gnutls_datum_t, HardFun<void, gnutls_datum_t*, &gnutls_datum_free>>;
#else
using CertFileRawPointer = std::unique_ptr<nullptr_t>;
#endif

/// The SubjectName field of the given certificate (if found) or an empty SBuf.
SBuf SubjectName(Certificate &);

/// The Issuer field of the given certificate (if found) or an empty SBuf.
SBuf IssuerName(Certificate &);

/// Whether cert was (correctly) issued by the given issuer.
/// Due to complexity of the underlying checks, it is impossible to clearly
/// distinguish pure negative answers (e.g., two independent certificates)
/// from errors (e.g., the issuer certificate lacks the right CA extension).
bool IssuedBy(Certificate &cert, Certificate &issuer);

/// Whether the given certificate is self-signed.
inline bool SelfSigned(Certificate &c) { return IssuedBy(c, c); }

} // namespace Security

// Declared outside Security because all underlying Security::Certificate types
// are declared inside global namespace.
/// reports a one-line gist of the Certificate Subject Name (for debugging)
std::ostream &operator <<(std::ostream &, Security::Certificate &);

#endif /* SQUID_SRC_SECURITY_CERTIFICATE_H */

