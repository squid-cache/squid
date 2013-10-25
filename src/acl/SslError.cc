#include "squid.h"
#include "acl/Checklist.h"
#include "acl/SslError.h"
#include "acl/SslErrorData.h"

int
ACLSslErrorStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    return data->match (checklist->sslErrors);
}

ACLSslErrorStrategy *
ACLSslErrorStrategy::Instance()
{
    return &Instance_;
}

ACLSslErrorStrategy ACLSslErrorStrategy::Instance_;
