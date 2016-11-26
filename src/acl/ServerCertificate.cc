/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
ACLServerCertificateStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    Security::CertPointer cert;
    if (checklist->serverCert)
        cert = checklist->serverCert;
    else if (checklist->conn() != NULL && checklist->conn()->serverBump())
        cert = checklist->conn()->serverBump()->serverCert;

    if (!cert)
        return 0;

    return data->match(cert.get());
}

ACLServerCertificateStrategy *
ACLServerCertificateStrategy::Instance()
{
    return &Instance_;
}

ACLServerCertificateStrategy ACLServerCertificateStrategy::Instance_;

#endif /* USE_OPENSSL */

