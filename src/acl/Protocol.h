/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLPROTOCOL_H
#define SQUID_ACLPROTOCOL_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"
#include "anyp/ProtocolType.h"

class ACLProtocolStrategy : public ACLStrategy<AnyP::ProtocolType>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *, ACLFlags &);
    virtual bool requiresRequest() const {return true;}

    static ACLProtocolStrategy *Instance();
    /* Not implemented to prevent copies of the instance. */
    /* Not private to prevent brain dead g+++ warnings about
     * private constructors with no friends */
    ACLProtocolStrategy(ACLProtocolStrategy const &);

private:
    static ACLProtocolStrategy Instance_;
    ACLProtocolStrategy() {}

    ACLProtocolStrategy&operator=(ACLProtocolStrategy const &);
};

class ACLProtocol
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<AnyP::ProtocolType> RegistryEntry_;
};

#endif /* SQUID_ACLPROTOCOL_H */

