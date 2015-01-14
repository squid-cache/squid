/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLHTTPREPHEADER_H
#define SQUID_ACLHTTPREPHEADER_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"
#include "HttpHeader.h"

/// \ingroup ACLAPI
class ACLHTTPRepHeaderStrategy : public ACLStrategy<HttpHeader*>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresReply() const { return true; }

    static ACLHTTPRepHeaderStrategy *Instance();
    /**
     * Not implemented to prevent copies of the instance.
     \par
     * Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends
     */
    ACLHTTPRepHeaderStrategy(ACLHTTPRepHeaderStrategy const &);

private:
    static ACLHTTPRepHeaderStrategy Instance_;
    ACLHTTPRepHeaderStrategy() { }

    ACLHTTPRepHeaderStrategy&operator = (ACLHTTPRepHeaderStrategy const &);
};

/// \ingroup ACLAPI
class ACLHTTPRepHeader
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<HttpHeader*> RegistryEntry_;
};

#endif /* SQUID_ACLHTTPREPHEADER_H */

