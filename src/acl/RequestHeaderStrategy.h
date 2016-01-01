/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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

template <http_hdr_type header>

class ACLRequestHeaderStrategy : public ACLStrategy<char const *>
{

public:
    virtual int match (ACLData<char const *> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresRequest() const {return true;}

    static ACLRequestHeaderStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLRequestHeaderStrategy(ACLRequestHeaderStrategy const &);

private:
    static ACLRequestHeaderStrategy *Instance_;
    ACLRequestHeaderStrategy() {}

    ACLRequestHeaderStrategy&operator=(ACLRequestHeaderStrategy const &);
};

template <http_hdr_type header>
int
ACLRequestHeaderStrategy<header>::match (ACLData<char const *> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    char const *theHeader = checklist->request->header.getStr(header);

    if (NULL == theHeader)
        return 0;

    return data->match(theHeader);
}

template <http_hdr_type header>
ACLRequestHeaderStrategy<header> *
ACLRequestHeaderStrategy<header>::Instance()
{
    if (!Instance_)
        Instance_ = new ACLRequestHeaderStrategy<header>;

    return Instance_;
}

template <http_hdr_type header>
ACLRequestHeaderStrategy<header> * ACLRequestHeaderStrategy<header>::Instance_ = NULL;

#endif /* SQUID_REQUESTHEADERSTRATEGY_H */

