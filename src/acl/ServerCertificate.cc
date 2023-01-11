/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_OPENSSL

#include "acl/CertificateData.h"
#include "acl/Checklist.h"
#include "acl/ServerCertificate.h"
#include "client_side.h"
#include "fde.h"
#include "http/Stream.h"
#include "ssl/ServerBump.h"

int
ACLServerCertificateStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    Security::CertPointer cert;
    if (checklist->serverCert)
        cert = checklist->serverCert;
    else if (checklist->al && Comm::IsConnOpen(checklist->al->hier.tcpServer)) {
        const auto ssl = fd_table[checklist->al->hier.tcpServer->fd].ssl.get();
        cert.resetWithoutLocking(SSL_get_peer_certificate(ssl));
    } else if (checklist->conn() && checklist->conn()->serverBump())
        cert = checklist->conn()->serverBump()->serverCert;

    if (!cert)
        return 0;

    return data->match(cert.get());
}

#endif /* USE_OPENSSL */

