/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"

/* MS Visual Studio Projects are monolithic, so we need the following
 * #if to exclude the SSL code from compile process when not needed.
 */
#if USE_OPENSSL

#include "acl/Certificate.h"
#include "acl/CertificateData.h"
#include "acl/Checklist.h"
#include "client_side.h"
#include "fde.h"
#include "globals.h"
#include "HttpRequest.h"

int
ACLCertificateStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    const int fd = checklist->fd();
    const bool goodDescriptor = 0 <= fd && fd <= Biggest_FD;
    SSL *ssl = goodDescriptor ? fd_table[fd].ssl : 0;
    X509 *cert = SSL_get_peer_certificate(ssl);
    const bool res = data->match (cert);
    X509_free(cert);
    return res;
}

ACLCertificateStrategy *
ACLCertificateStrategy::Instance()
{
    return &Instance_;
}

ACLCertificateStrategy ACLCertificateStrategy::Instance_;

#endif /* USE_OPENSSL */

