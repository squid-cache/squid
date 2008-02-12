
/*
 * $Id: ACLSslError.cc,v 1.1 2008/02/11 22:24:39 rousskov Exp $
 */

#include "squid.h"
#include "ACLSslError.h"
#include "ACLSslErrorData.h"
#include "ACLChecklist.h"

/* explicit template instantiation required for some systems */

template class ACLStrategised<int>

;

ACL::Prototype ACLSslError::RegistryProtoype(&ACLSslError::RegistryEntry_, "ssl_error");

ACLStrategised<int> ACLSslError::RegistryEntry_(new ACLSslErrorData, ACLSslErrorStrategy::Instance(), "ssl_error");

int
ACLSslErrorStrategy::match (ACLData<MatchType> * &data, ACLChecklist *checklist)
{
    return data->match (checklist->ssl_error);
}

ACLSslErrorStrategy *
ACLSslErrorStrategy::Instance()
{
    return &Instance_;
}

ACLSslErrorStrategy ACLSslErrorStrategy::Instance_;
