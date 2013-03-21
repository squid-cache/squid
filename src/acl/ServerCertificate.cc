/*
 */

#include "squid.h"

#if USE_SSL

#include "acl/ServerCertificate.h"
#include "acl/Checklist.h"
#include "acl/CertificateData.h"
#include "client_side.h"
#include "fde.h"
#include "ssl/ServerBump.h"

int
ACLServerCertificateStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    X509 *cert = NULL;
    if (checklist->serverCert.get())
        cert = checklist->serverCert.get();
    else if (checklist->conn() != NULL && checklist->conn()->serverBump())
        cert = checklist->conn()->serverBump()->serverCert.get();

    if (!cert)
        return 0;

    return data->match(cert);
}

ACLServerCertificateStrategy *
ACLServerCertificateStrategy::Instance()
{
    return &Instance_;
}

ACLServerCertificateStrategy ACLServerCertificateStrategy::Instance_;

#endif /* USE_SSL */
