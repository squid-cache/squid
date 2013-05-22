#include "squid.h"
#include "acl/SslError.h"
#include "acl/SslErrorData.h"
#include "acl/Checklist.h"

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
