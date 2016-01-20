/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "security/forward.h"

#if !USE_OPENSSL

namespace Security
{

#if USE_GNUTLS
template std::unordered_map<Security::ContextPtr, Lock> & ContextPointer::Locks();

template std::unordered_map<gnutls_x509_crt_t, Lock> & CertPointer::Locks();

template std::unordered_map<gnutls_x509_crl_t, Lock> & CrlPointer::Locks();
#endif

template std::unordered_map<void*, Lock> & DhePointer::Locks();

} // namespace Security

#endif /* !USE_OPENSSL */

