/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLHTTPREQHEADER_H
#define SQUID_ACLHTTPREQHEADER_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"
#include "HttpHeader.h"

/// \ingroup ACLAPI
class ACLHTTPReqHeaderStrategy : public ACLStrategy<HttpHeader*>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresRequest() const { return true; }

    static ACLHTTPReqHeaderStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLHTTPReqHeaderStrategy(ACLHTTPReqHeaderStrategy const &);

private:
    static ACLHTTPReqHeaderStrategy Instance_;
    ACLHTTPReqHeaderStrategy() { }

    ACLHTTPReqHeaderStrategy&operator = (ACLHTTPReqHeaderStrategy const &);
};

/// \ingroup ACLAPI
class ACLHTTPReqHeader
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<HttpHeader*> RegistryEntry_;
};

#endif /* SQUID_ACLHTTPREQHEADER_H */

