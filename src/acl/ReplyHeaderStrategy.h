/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLREPLYHEADERSTRATEGY_H
#define SQUID_ACLREPLYHEADERSTRATEGY_H

#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/FilledChecklist.h"
#include "acl/Strategy.h"
#include "HttpReply.h"

template <Http::HdrType header>
class ACLReplyHeaderStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<char const *> * &, ACLFilledChecklist *);
    virtual bool requiresReply() const {return true;}
};

template <Http::HdrType header>
int
ACLReplyHeaderStrategy<header>::match (ACLData<char const *> * &data, ACLFilledChecklist *checklist)
{
    char const *theHeader = checklist->reply->header.getStr(header);

    if (NULL == theHeader)
        return 0;

    return data->match(theHeader);
}

#endif /* SQUID_REPLYHEADERSTRATEGY_H */

