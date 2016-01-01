/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLMETHOD_H
#define SQUID_ACLMETHOD_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"
#include "http/RequestMethod.h"

/// \ingroup ACLAPI
class ACLMethodStrategy : public ACLStrategy<HttpRequestMethod>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresRequest() const {return true;}

    static ACLMethodStrategy *Instance();

    /**
     * Not implemented to prevent copies of the instance.
     \par
     * Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends
     */
    ACLMethodStrategy(ACLMethodStrategy const &);

private:
    static ACLMethodStrategy Instance_;
    ACLMethodStrategy() {}

    ACLMethodStrategy&operator=(ACLMethodStrategy const &);
};

/// \ingroup ACLAPI
class ACLMethod
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<HttpRequestMethod> RegistryEntry_;
};

#endif /* SQUID_ACLMETHOD_H */

