#include "squid.h"
#include "acl/HierCode.h"
#include "acl/HierCodeData.h"
#include "acl/Checklist.h"
#include "HttpRequest.h"

/* explicit template instantiation required for some systems */

template class ACLStrategised<hier_code>;

int
ACLHierCodeStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    return data->match (checklist->request->hier.code);
}

ACLHierCodeStrategy *
ACLHierCodeStrategy::Instance()
{
    return &Instance_;
}

ACLHierCodeStrategy ACLHierCodeStrategy::Instance_;
