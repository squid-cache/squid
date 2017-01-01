/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLREPLYHEADERSTRATEGY_H
#define SQUID_ACLREPLYHEADERSTRATEGY_H

class ACLChecklist;

#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/FilledChecklist.h"
#include "acl/Strategy.h"
#include "HttpReply.h"

template <http_hdr_type header>
class ACLReplyHeaderStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<char const *> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresReply() const {return true;}

    static ACLReplyHeaderStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLReplyHeaderStrategy(ACLReplyHeaderStrategy const &);

private:
    static ACLReplyHeaderStrategy *Instance_;
    ACLReplyHeaderStrategy() {}

    ACLReplyHeaderStrategy&operator=(ACLReplyHeaderStrategy const &);
};

template <http_hdr_type header>
int
ACLReplyHeaderStrategy<header>::match (ACLData<char const *> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    char const *theHeader = checklist->reply->header.getStr(header);

    if (NULL == theHeader)
        return 0;

    return data->match(theHeader);
}

template <http_hdr_type header>
ACLReplyHeaderStrategy<header> *
ACLReplyHeaderStrategy<header>::Instance()
{
    if (!Instance_)
        Instance_ = new ACLReplyHeaderStrategy<header>;

    return Instance_;
}

template <http_hdr_type header>
ACLReplyHeaderStrategy<header> * ACLReplyHeaderStrategy<header>::Instance_ = NULL;

#endif /* SQUID_REPLYHEADERSTRATEGY_H */

