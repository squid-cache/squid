
/*
 * $Id$
 */

#include "squid.h"
#include "acl/SslError.h"
#include "acl/SslErrorData.h"
#include "acl/Checklist.h"

/* explicit template instantiation required for some systems */

template class ACLStrategised<int>;



int
ACLSslErrorStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    return data->match (checklist->ssl_error);
}

ACLSslErrorStrategy *
ACLSslErrorStrategy::Instance()
{
    return &Instance_;
}

ACLSslErrorStrategy ACLSslErrorStrategy::Instance_;
