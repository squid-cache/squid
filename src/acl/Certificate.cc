/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
#include "http/Stream.h"
#include "HttpRequest.h"

int
ACLCertificateStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    const int fd = checklist->fd();
    const bool goodDescriptor = 0 <= fd && fd <= Biggest_FD;
    auto ssl = goodDescriptor ? fd_table[fd].ssl.get() : nullptr;
    X509 *cert = SSL_get_peer_certificate(ssl);
    const bool res = data->match (cert);
    X509_free(cert);
    return res;
}

#endif /* USE_OPENSSL */

