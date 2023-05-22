/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLREQUESTHEADERSTRATEGY_H
#define SQUID_ACLREQUESTHEADERSTRATEGY_H
#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/FilledChecklist.h"
#include "acl/Strategy.h"
#include "HttpRequest.h"

template <Http::HdrType header>
class ACLRequestHeaderStrategy : public ACLStrategy<char const *>
{

public:
    int match (ACLData<char const *> * &, ACLFilledChecklist *) override;
    bool requiresRequest() const override {return true;}
};

template <Http::HdrType header>
int
ACLRequestHeaderStrategy<header>::match (ACLData<char const *> * &data, ACLFilledChecklist *checklist)
{
    char const *theHeader = checklist->request->header.getStr(header);

    if (nullptr == theHeader)
        return 0;

    return data->match(theHeader);
}

#endif /* SQUID_REQUESTHEADERSTRATEGY_H */

